// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Interface to a Linux device.
 * 1 Input, 0 Outputs.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#define REQUEST_MERGING
#define PREFETCH_LEN PAGE_SIZE
//#define FRONT_MERGE // FIXME: this does not work.

// low-level device parameters
//#define USE_MAX_SECTORS         (MARS_MAX_SEGMENT_SIZE >> 9)
//#define USE_MAX_PHYS_SEGMENTS   (MARS_MAX_SEGMENT_SIZE >> 9)
//#define USE_MAX_SEGMENT_SIZE    MARS_MAX_SEGMENT_SIZE
//#define USE_LOGICAL_BLOCK_SIZE  512
//#define USE_SEGMENT_BOUNDARY    (PAGE_SIZE-1)
//#define USE_QUEUE_ORDERED       QUEUE_ORDERED_DRAIN

//#define USE_CONGESTED_FN
#define USE_MERGE_BVEC

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_if.h"

///////////////////////// own static definitions ////////////////////////

// TODO: check bounds, ensure that free minor numbers are recycled
static int device_minor = 0;

//////////////// object / aspect constructors / destructors ///////////////

///////////////////////// linux operations ////////////////////////

/* callback
 */
static
void if_endio(struct generic_callback *cb)
{
	struct if_mref_aspect *mref_a = cb->cb_private;
	struct if_input *input;
	struct bio *bio;
	int k;
	int rw = 0;
	int error;

	if (unlikely(!mref_a)) {
		MARS_FAT("callback with no mref_a called. something is very wrong here!\n");
		return;
	}

	mars_trace(mref_a->object, "if_endio");
	mars_log_trace(mref_a->object);

	for (k = 0; k < mref_a->bio_count; k++) {
		bio = mref_a->orig_bio[k];
		mref_a->orig_bio[k] = NULL;
		if (unlikely(!bio)) {
			MARS_FAT("callback with no bio called (k = %d). something is very wrong here!\n", k);
			continue;
		}

		rw = bio->bi_rw & 1;

		CHECK_ATOMIC(&bio->bi_comp_cnt, 1);
		if (!atomic_dec_and_test(&bio->bi_comp_cnt)) {
			continue;
		}
#if 1
		if (mref_a->is_kmapped) {
			struct bio_vec *bvec;
			int i;
			bio_for_each_segment(bvec, bio, i) {
				MARS_IO("kunmap %p\n", bvec->bv_page);
				kunmap(bvec->bv_page);
			}
		}
#endif

		error = mref_a->cb.cb_error;
		if (unlikely(error < 0)) {
			MARS_ERR("NYI: error=%d RETRY LOGIC %u\n", error, bio->bi_size);
		} else { // bio conventions are slightly different...
			error = 0;
			bio->bi_size = 0;
		}
		bio_endio(bio, error);
		bio_put(bio);
	}
	input = mref_a->input;
	if (input) {
		atomic_dec(&input->flying_count);
		if (rw) {
			atomic_dec(&input->write_flying_count);
		} else {
			atomic_dec(&input->read_flying_count);
		}
	}
}

/* Kick off plugged mrefs
 */
static void _if_unplug(struct if_input *input)
{
	//struct if_brick *brick = input->brick;
	LIST_HEAD(tmp_list);
	unsigned long flags;

	might_sleep();

	down(&input->kick_sem);
	traced_lock(&input->req_lock, flags);
	if (!list_empty(&input->plug_anchor)) {
		// move over the whole list
		list_replace_init(&input->plug_anchor, &tmp_list);
		atomic_set(&input->plugged_count, 0);
	}
  	traced_unlock(&input->req_lock, flags);
	up(&input->kick_sem);

	while (!list_empty(&tmp_list)) {
		struct if_mref_aspect *mref_a;
		struct mref_object *mref;
		int hash_index;
		unsigned long flags;

		mref_a = container_of(tmp_list.next, struct if_mref_aspect, plug_head);
		list_del_init(&mref_a->plug_head);

		hash_index = mref_a->hash_index;
		traced_lock(&input->hash_lock[hash_index], flags);
		list_del_init(&mref_a->hash_head);
		traced_unlock(&input->hash_lock[hash_index], flags);

                mref = mref_a->object;

		if (unlikely(mref_a->current_len > mref_a->max_len)) {
			MARS_ERR("request len %d > %d\n", mref_a->current_len, mref_a->max_len);
		}
		mref->ref_len = mref_a->current_len;

		mars_trace(mref, "if_unplug");

		atomic_inc(&input->flying_count);
		if (mref->ref_rw) {
			atomic_inc(&input->write_flying_count);
		} else {
			atomic_inc(&input->read_flying_count);
		}

		GENERIC_INPUT_CALL(input, mref_io, mref);
		GENERIC_INPUT_CALL(input, mref_put, mref);
	}
}

/* accept a linux bio, convert to mref and call buf_io() on it.
 */
static int if_make_request(struct request_queue *q, struct bio *bio)
{
	struct if_input *input;
	struct if_brick *brick = NULL;
	struct mref_object *mref = NULL;
	struct if_mref_aspect *mref_a;
	struct generic_callback *cb;
	struct bio_vec *bvec;
	int i;
	bool assigned = false;
	const bool unplug = bio_rw_flagged(bio, BIO_RW_UNPLUG);
	const bool barrier = ((bio->bi_rw & 1) != READ && bio_rw_flagged(bio, BIO_RW_BARRIER));
	loff_t pos = ((loff_t)bio->bi_sector) << 9; // TODO: make dynamic
	int rw = bio_data_dir(bio);
	int total_len = bio->bi_size;
        int error = -ENOSYS;

	MARS_IO("bio %p size = %d\n", bio, bio->bi_size);

	might_sleep();

	input = q->queuedata;
        if (unlikely(!input))
                goto err;

	if (rw) {
		atomic_inc(&input->total_write_count);
	} else {
		atomic_inc(&input->total_read_count);
	}

	brick = input->brick;
        if (unlikely(!brick))
                goto err;

	/* Get a reference to the bio.
	 * Will be released after bio_endio().
	 */
	atomic_inc(&bio->bi_cnt);

	/* FIXME: THIS IS PROVISIONARY (use event instead)
	 */
	while (unlikely(!brick->power.led_on)) {
		msleep(2 * HZ);
	}

	_CHECK_ATOMIC(&bio->bi_comp_cnt, !=, 0);
	atomic_set(&bio->bi_comp_cnt, 0);

#ifdef IO_DEBUGGING
	{
		const unsigned short prio = bio_prio(bio);
		const bool sync = bio_rw_flagged(bio, BIO_RW_SYNCIO);
		const unsigned int ff = bio->bi_rw & REQ_FAILFAST_MASK;
		MARS_IO("BIO rw = %lx len = %d prio = %d sync = %d unplug = %d ff = %d\n", bio->bi_rw, bio->bi_size, prio, sync, unplug, ff);
	}
#endif

	down(&input->kick_sem);

	bio_for_each_segment(bvec, bio, i) {
		struct page *page = bvec->bv_page;
		int bv_len = bvec->bv_len;
		int offset = bvec->bv_offset;
		void *data;

		data = kmap(page);
		MARS_IO("page = %p data = %p\n", page, data);
		error = -EINVAL;
		if (unlikely(!data))
			break;

		data += offset;

		while (bv_len > 0) {
			struct list_head *tmp;
			int hash_index;
			int this_len = 0;
			unsigned long flags;

			mref = NULL;
			mref_a = NULL;

			MARS_IO("rw = %d i = %d pos = %lld  bv_page = %p bv_offset = %d data = %p bv_len = %d\n", rw, i, pos, bvec->bv_page, bvec->bv_offset, data, bv_len);

			hash_index = (pos / IF_HASH_CHUNK) % IF_HASH_MAX;

#ifdef REQUEST_MERGING
			traced_lock(&input->hash_lock[hash_index], flags);
			for (tmp = input->hash_table[hash_index].next; tmp != &input->hash_table[hash_index]; tmp = tmp->next) {
				struct if_mref_aspect *tmp_a;
				struct mref_object *tmp_mref;
				int i;

				tmp_a = container_of(tmp, struct if_mref_aspect, hash_head);
				tmp_mref = tmp_a->object;
				if (tmp_a->orig_page != page || tmp_mref->ref_rw != rw || tmp_a->bio_count >= MAX_BIO || tmp_a->current_len + bv_len > tmp_a->max_len) {
					continue;
				}

				if (tmp_mref->ref_data + tmp_a->current_len == data) {
					goto merge_end;
#ifdef FRONT_MERGE // FIXME: this cannot work. ref_data must never be changed. pre-allocate from offset 0 instead.
				} else if (data + bv_len == tmp_mref->ref_data) {
					goto merge_front;
#endif
				}
				continue;

#ifdef FRONT_MERGE // FIXME: this cannot work. ref_data must never be changed. pre-allocate from offset 0 instead.
			merge_front:
				tmp_mref->ref_data = data;
#endif
			merge_end:
				tmp_a->current_len += bv_len;
				mref = tmp_mref;
				mref_a = tmp_a;
				this_len = bv_len;
				if (barrier) {
					mref->ref_skip_sync = false;
				}

				for (i = 0; i < mref_a->bio_count; i++) {
					if (mref_a->orig_bio[i] == bio) {
						goto unlock;
					}
				}

				CHECK_ATOMIC(&bio->bi_comp_cnt, 0);
				atomic_inc(&bio->bi_comp_cnt);
				mref_a->orig_bio[mref_a->bio_count++] = bio;
				assigned = true;
				goto unlock;
			} // foreach hash collision list member

		unlock:
			traced_unlock(&input->hash_lock[hash_index], flags);
#endif
			if (!mref) {
				int prefetch_len;
				error = -ENOMEM;
				mref = if_alloc_mref(&brick->hidden_output, &input->mref_object_layout);
				if (unlikely(!mref)) {
					up(&input->kick_sem);
					goto err;
				}
				mref_a = if_mref_get_aspect(&brick->hidden_output, mref);
				if (unlikely(!mref_a)) {
					up(&input->kick_sem);
					goto err;
				}

#ifdef PREFETCH_LEN
				prefetch_len = PREFETCH_LEN - offset;
#if 1
				// TODO: this restriction is too strong to be useful for performance boosts. Do better.
				if (prefetch_len > total_len) {
					prefetch_len = total_len;
				}
#endif
				if (pos + prefetch_len > input->info.current_size) {
					prefetch_len = input->info.current_size - pos;
				}
				if (prefetch_len < bv_len) {
					prefetch_len = bv_len;
				}
#else
				prefetch_len = bv_len;
#endif

				cb = &mref_a->cb;
				cb->cb_fn = if_endio;
				cb->cb_private = mref_a;
				cb->cb_error = 0;
				cb->cb_prev = NULL;
				mref->ref_cb = cb;
				mref_a->input = input;
				mref->ref_rw = mref->ref_may_write = rw;
				mref->ref_pos = pos;
				mref->ref_len = prefetch_len;
				mref->ref_data = data; // direct IO
				mref_a->orig_page = page;
				mref_a->is_kmapped = true;

				error = GENERIC_INPUT_CALL(input, mref_get, mref);
				if (unlikely(error < 0)) {
					up(&input->kick_sem);
					goto err;
				}
				
				mars_trace(mref, "if_start");

				this_len = mref->ref_len; // now may be shorter than originally requested.
				mref_a->max_len = this_len;
				if (this_len > bv_len) {
					this_len = bv_len;
				}
				mref_a->current_len = this_len;
				if (rw) {
					atomic_inc(&input->total_mref_write_count);
				} else {
					atomic_inc(&input->total_mref_read_count);
				}

				CHECK_ATOMIC(&bio->bi_comp_cnt, 0);
				atomic_inc(&bio->bi_comp_cnt);
				mref_a->orig_bio[0] = bio;
				mref_a->bio_count = 1;
				assigned = true;
				
				if (brick->skip_sync && !barrier) {
					mref->ref_skip_sync = true;
				}

				atomic_inc(&input->plugged_count);

				mref_a->hash_index = hash_index;
				traced_lock(&input->hash_lock[hash_index], flags);
				list_add_tail(&mref_a->hash_head, &input->hash_table[hash_index]);
				traced_unlock(&input->hash_lock[hash_index], flags);

				traced_lock(&input->req_lock, flags);
				list_add_tail(&mref_a->plug_head, &input->plug_anchor);
				traced_unlock(&input->req_lock, flags);
			} // !mref

			pos += this_len;
			data += this_len;
			bv_len -= this_len;
			total_len -= this_len;
		} // while bv_len > 0
	} // foreach bvec

	up(&input->kick_sem);

	if (likely(!total_len)) {
		error = 0;
	} else {
		MARS_ERR("bad rest len = %d\n", total_len);
	}

err:

	if (error < 0) {
		MARS_ERR("cannot submit request from bio, status=%d\n", error);
		if (assigned) {
			//... cleanup the mess NYI
		} else {
			bio_endio(bio, error);
		}
	}

	if (unplug ||
	   (brick && brick->max_plugged > 0 && atomic_read(&input->plugged_count) > brick->max_plugged)) {
		_if_unplug(input);
	}

	return error;
}

static int if_open(struct block_device *bdev, fmode_t mode)
{
	struct if_input *input = bdev->bd_disk->private_data;
	atomic_inc(&input->open_count);
	MARS_INF("----------------------- OPEN %d ------------------------------\n", atomic_read(&input->open_count));
	return 0;
}

static int if_release(struct gendisk *gd, fmode_t mode)
{
	struct if_input *input = gd->private_data;
	int max = 0;
	int nr;

	MARS_INF("----------------------- CLOSE %d ------------------------------\n", atomic_read(&input->open_count));

	while ((nr = atomic_read(&input->flying_count)) > 0) {
		MARS_INF("%d IO requests not yet completed\n", nr);
		if (max++ > 10)
			break;
		msleep(2000);
	}

	if (atomic_dec_and_test(&input->open_count)) {
		struct if_brick *brick = input->brick;
		brick->has_closed = true;
		mars_trigger();
	}
	return 0;
}

//static
void if_unplug(struct request_queue *q)
{
	int was_plugged = 1;
#if 1
	spin_lock_irq(q->queue_lock);
	was_plugged = blk_remove_plug(q);
	spin_unlock_irq(q->queue_lock);
#else
	queue_flag_clear_unlocked(QUEUE_FLAG_PLUGGED, q);
#endif
	MARS_IO("UNPLUG %d\n", was_plugged);
	if (true || was_plugged) {
		struct if_input *input = q->queuedata;
		_if_unplug(input);
	}
}

//static
int mars_congested(void *data, int bdi_bits)
{
	struct if_input *input = data;
	int ret = 0;
	if (bdi_bits & (1 << BDI_sync_congested) &&
	   atomic_read(&input->flying_count) > 0) {
		ret |= (1 << BDI_sync_congested);
		
	}
	return ret;
}

static
int mars_merge_bvec(struct request_queue *q, struct bvec_merge_data *bvm, struct bio_vec *bvec)
{
	unsigned int bio_size = bvm->bi_size;
	if (!bio_size) {
		return bvec->bv_len;
	}
	return 128;
}

static const struct block_device_operations if_blkdev_ops = {
	.owner =   THIS_MODULE,
	.open =    if_open,
	.release = if_release,

};

static int if_switch(struct if_brick *brick)
{
	struct if_input *input = brick->inputs[0];
	struct request_queue *q;
	struct gendisk *disk;
	int minor;
	unsigned long capacity;
	int status;

	if (brick->power.button) {
		mars_power_led_off((void*)brick,  false);
		status = GENERIC_INPUT_CALL(input, mars_get_info, &input->info);
		if (status < 0) {
			MARS_ERR("cannot get device info, status=%d\n", status);
			return status;
		}
		capacity = input->info.current_size >> 9; // TODO: make this dynamic
		
		q = blk_alloc_queue(GFP_MARS);
		if (!q) {
			MARS_ERR("cannot allocate device request queue\n");
			return -ENOMEM;
		}
		q->queuedata = input;
		input->q = q;
		
		disk = alloc_disk(1);
		if (!disk) {
			MARS_ERR("cannot allocate gendisk\n");
			return -ENOMEM;
		}

		minor = device_minor++; //TODO: protect against races (e.g. atomic_t)
		disk->queue = q;
		disk->major = MARS_MAJOR; //TODO: make this dynamic for >256 devices
		disk->first_minor = minor;
		disk->fops = &if_blkdev_ops;
		//snprintf(disk->disk_name, sizeof(disk->disk_name),  "mars%d", minor);
		snprintf(disk->disk_name, sizeof(disk->disk_name),  "mars/%s", brick->brick_name);
		MARS_DBG("created device name %s\n", disk->disk_name);
		disk->private_data = input;
		set_capacity(disk, capacity);
		
		blk_queue_make_request(q, if_make_request);
#ifdef USE_MAX_SECTORS
		blk_queue_max_sectors(q, USE_MAX_SECTORS);
#endif
#ifdef USE_MAX_PHYS_SEGMENTS
		blk_queue_max_phys_segments(q, USE_MAX_PHYS_SEGMENTS);
#endif
#ifdef USE_MAX_HW_SEGMENTS
		blk_queue_max_hw_segments(q, USE_MAX_HW_SEGMENTS);
#endif
#ifdef USE_MAX_SEGMENT_SIZE
		blk_queue_max_segment_size(q, USE_MAX_SEGMENT_SIZE);
#endif
#ifdef USE_LOGICAL_BLOCK_SIZE
		blk_queue_logical_block_size(q, USE_LOGICAL_BLOCK_SIZE);
#endif
#ifdef USE_SEGMENT_BOUNDARY
		blk_queue_segment_boundary(q, USE_SEGMENT_BOUNDARY);
#endif
#ifdef USE_QUEUE_ORDERED
		blk_queue_ordered(q, USE_QUEUE_ORDERED, NULL);
#endif
		blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
		q->unplug_fn = if_unplug;
		q->queue_lock = &input->req_lock; // needed!
		
		input->bdev = bdget(MKDEV(disk->major, minor));
		/* we have no partitions. we contain only ourselves. */
		input->bdev->bd_contains = input->bdev;

		MARS_INF("ra_pages OLD = %lu NEW = %d\n", q->backing_dev_info.ra_pages, brick->readahead);
		q->backing_dev_info.ra_pages = brick->readahead;
#ifdef USE_CONGESTED_FN
		q->backing_dev_info.congested_fn = mars_congested;
		q->backing_dev_info.congested_data = input;
#endif
#ifdef USE_MERGE_BVEC
		blk_queue_merge_bvec(q, mars_merge_bvec);
#endif

		// point of no return
		add_disk(disk);
		input->disk = disk;
		//set_device_ro(input->bdev, 0); // TODO: implement modes
		mars_power_led_on((void*)brick, true);
	} else {
		mars_power_led_on((void*)brick, false);
		disk = input->disk;
		if (!disk)
			goto is_down;

#if 0
		q = disk->queue;
		if (q) {
			blk_cleanup_queue(q);
			input->q = NULL;
		}
#endif
		if (atomic_read(&input->open_count) > 0) {
			MARS_INF("device '%s' is open %d times, cannot shutdown\n", disk->disk_name, atomic_read(&input->open_count));
			return -EBUSY;
		}
		if (input->bdev) {
			bdput(input->bdev);
			input->bdev = NULL;
		}
		del_gendisk(input->disk);
		put_disk(input->disk);
		input->disk = NULL;
	is_down:
		mars_power_led_off((void*)brick, true);
	}
	return 0;
}

//////////////// informational / statistics ///////////////

static
char *if_statistics(struct if_brick *brick, int verbose)
{
	struct if_input *input = brick->inputs[0];
	char *res = kmalloc(512, GFP_MARS);
	int tmp1 = atomic_read(&input->total_read_count); 
	int tmp2 = atomic_read(&input->total_mref_read_count);
	int tmp3 = atomic_read(&input->total_write_count); 
	int tmp4 = atomic_read(&input->total_mref_write_count);
	if (!res)
		return NULL;
	sprintf(res, "reads = %d mref_reads = %d (%d%%) writes = %d mref_writes = %d (%d%%) | plugged = %d flying = %d (reads = %d writes = %d)\n",
		tmp1,
		tmp2,
		tmp1 ? tmp2 * 100 / tmp1 : 0,
		tmp3,
		tmp4,
		tmp3 ? tmp4 * 100 / tmp3 : 0,
		atomic_read(&input->plugged_count),
		atomic_read(&input->flying_count),
		atomic_read(&input->read_flying_count),
		atomic_read(&input->write_flying_count));
	return res;
}

static
void if_reset_statistics(struct if_brick *brick)
{
	struct if_input *input = brick->inputs[0];
	atomic_set(&input->total_read_count, 0);
	atomic_set(&input->total_write_count, 0);
	atomic_set(&input->total_mref_read_count, 0);
	atomic_set(&input->total_mref_write_count, 0);
}

////////////////// own brick / input / output operations //////////////////

// none

//////////////// object / aspect constructors / destructors ///////////////

static int if_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct if_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->plug_head);
	INIT_LIST_HEAD(&ini->hash_head);
	return 0;
}

static void if_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct if_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->plug_head);
	CHECK_HEAD_EMPTY(&ini->hash_head);
}

MARS_MAKE_STATICS(if);

//////////////////////// contructors / destructors ////////////////////////

static int if_brick_construct(struct if_brick *brick)
{
	struct if_output *hidden = &brick->hidden_output;
	_if_output_init(brick, hidden, "internal");
	return 0;
}

static int if_brick_destruct(struct if_brick *brick)
{
	return 0;
}

static int if_input_construct(struct if_input *input)
{
	int i;
	for (i = 0; i < IF_HASH_MAX; i++) {
		spin_lock_init(&input->hash_lock[i]);
		INIT_LIST_HEAD(&input->hash_table[i]);
	}
	INIT_LIST_HEAD(&input->plug_anchor);
	sema_init(&input->kick_sem, 1);
	spin_lock_init(&input->req_lock);
	atomic_set(&input->open_count, 0);
	atomic_set(&input->flying_count, 0);
	atomic_set(&input->plugged_count, 0);
	return 0;
}

static int if_input_destruct(struct if_input *input)
{
	return 0;
}

static int if_output_construct(struct if_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct if_brick_ops if_brick_ops = {
	.brick_switch = if_switch,
	.brick_statistics = if_statistics,
	.reset_statistics = if_reset_statistics,
};

static struct if_output_ops if_output_ops = {
	.make_object_layout = if_make_object_layout,
};

const struct if_input_type if_input_type = {
	.type_name = "if_input",
	.input_size = sizeof(struct if_input),
	.input_construct = &if_input_construct,
	.input_destruct = &if_input_destruct,
};

static const struct if_input_type *if_input_types[] = {
	&if_input_type,
};

const struct if_output_type if_output_type = {
	.type_name = "if_output",
	.output_size = sizeof(struct if_output),
	.master_ops = &if_output_ops,
	.output_construct = &if_output_construct,
	.aspect_types = if_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
};

static const struct if_output_type *if_output_types[] = {
	&if_output_type,
};


const struct if_brick_type if_brick_type = {
	.type_name = "if_brick",
	.brick_size = sizeof(struct if_brick),
	.max_inputs = 1,
	.max_outputs = 0,
	.master_ops = &if_brick_ops,
	.default_input_types = if_input_types,
	.default_output_types = if_output_types,
	.brick_construct = &if_brick_construct,
	.brick_destruct = &if_brick_destruct,
};
EXPORT_SYMBOL_GPL(if_brick_type);

////////////////// module init stuff /////////////////////////

static void __exit exit_if(void)
{
	int status;
	MARS_INF("exit_if()\n");
	status = if_unregister_brick_type();
	unregister_blkdev(MARS_MAJOR, "mars");
}

static int __init init_if(void)
{
	int status;

	(void)if_aspect_types; // not used, shut up gcc

	MARS_INF("init_if()\n");
	status = register_blkdev(MARS_MAJOR, "mars");
	if (status)
		return status;
	status = if_register_brick_type();
	if (status)
		goto err_device;
	return status;
err_device:
	MARS_ERR("init_if() status=%d\n", status);
	exit_if();
	return status;
}

MODULE_DESCRIPTION("MARS if");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_if);
module_exit(exit_if);
