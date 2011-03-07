// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Interface to a Linux device.
 * 1 Input, 0 Outputs.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define LOG
#define REQUEST_MERGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_if_device.h"

///////////////////////// own static definitions ////////////////////////

static int device_minor = 0;

//////////////// object / aspect constructors / destructors ///////////////

///////////////////////// linux operations ////////////////////////

/* callback
 */
static void _if_device_endio(struct generic_callback *cb)
{
	struct if_device_mref_aspect *mref_a = cb->cb_private;
	struct bio *bio;
	struct bio_vec *bvec;
	int i, k;
	int error;

	if (unlikely(!mref_a)) {
		MARS_FAT("callback with no mref_a called. something is very wrong here!\n");
		return;
	}

#if 1
	if (mref_a->yyy++ > 0)
		MARS_ERR("yyy = %d\n", mref_a->yyy - 1);
#endif

	for (k = 0; k < mref_a->bio_count; k++) {
		bio = mref_a->orig_bio[k];
		mref_a->orig_bio[k] = NULL;
		if (unlikely(!bio)) {
			MARS_FAT("callback with no bio called (k = %d). something is very wrong here!\n", k);
			continue;
		}

		CHECK_ATOMIC(&bio->bi_comp_cnt, 1);
		if (!atomic_dec_and_test(&bio->bi_comp_cnt)) {
			continue;
		}

		bio_for_each_segment(bvec, bio, i) {
			kunmap(bvec->bv_page);
		}

		error = mref_a->cb.cb_error;
		if (unlikely(error < 0)) {
			MARS_ERR("NYI: error=%d RETRY LOGIC %u\n", error, bio->bi_size);
		} else { // bio conventions are slightly different...
			error = 0;
			bio->bi_size = 0;
		}
		bio->bi_check3++;
		bio_endio(bio, error);
		bio_put(bio);
	}
}

/* Kick off plugged mrefs
 */
static void _if_device_unplug(struct if_device_input *input)
{
	LIST_HEAD(tmp_list);
	unsigned long flags;

	might_sleep();

	down(&input->kick_sem);
	traced_lock(&input->req_lock, flags);
	if (!list_empty(&input->plug_anchor)) {
		// move over the whole list
		list_replace_init(&input->plug_anchor, &tmp_list);
	}
  	traced_unlock(&input->req_lock, flags);
	up(&input->kick_sem);

	while (!list_empty(&tmp_list)) {
		struct if_device_mref_aspect *mref_a;
		struct mref_object *mref;
		mref_a = container_of(tmp_list.next, struct if_device_mref_aspect, plug_head);
		list_del_init(&mref_a->plug_head);
                mref = mref_a->object;

#if 1
		if (mref_a->xxx++ > 0)
			MARS_ERR("xxx = %d\n", mref_a->xxx - 1);
#endif
		GENERIC_INPUT_CALL(input, mref_io, mref);
		GENERIC_INPUT_CALL(input, mref_put, mref);
	}
}

/* accept a linux bio, convert to mref and call buf_io() on it.
 */
static int if_device_make_request(struct request_queue *q, struct bio *bio)
{
	struct if_device_input *input;
	struct if_device_brick *brick;
	struct mref_object *mref = NULL;
	struct if_device_mref_aspect *mref_a;
	struct generic_callback *cb;
	struct bio_vec *bvec;
	int i;
	bool assigned = false;
	const bool unplug = bio_rw_flagged(bio, BIO_RW_UNPLUG);
	//const bool barrier = ((bio->bi_rw & 1) != READ && bio_rw_flagged(bio, BIO_RW_BARRIER));
	loff_t pos = ((loff_t)bio->bi_sector) << 9; // TODO: make dynamic
	int rw = bio_data_dir(bio);
        int error = -ENOSYS;

	MARS_DBG("make_request(%d)\n", bio->bi_size);

	might_sleep();

	input = q->queuedata;
        if (unlikely(!input))
                goto err;

	brick = input->brick;
        if (unlikely(!brick))
                goto err;

	/* Get a reference to the bio.
	 * Will be released after bio_endio().
	 */
	atomic_inc(&bio->bi_cnt);
	bio->bi_check = false;
	bio->bi_check2 = 0;
	bio->bi_check3 = 0;

	/* FIXME: THIS IS PROVISIONARY (use event instead)
	 */
	while (unlikely(!brick->power.led_on)) {
		msleep(2 * HZ);
	}

	_CHECK_ATOMIC(&bio->bi_comp_cnt, !=, 0);
	atomic_set(&bio->bi_comp_cnt, 0);

#ifdef LOG
	{
		const unsigned short prio = bio_prio(bio);
		const bool sync = bio_rw_flagged(bio, BIO_RW_SYNCIO);
		const unsigned int ff = bio->bi_rw & REQ_FAILFAST_MASK;
		MARS_INF("BIO rw = %lx len = %d prio = %d sync = %d unplug = %d ff = %d\n", bio->bi_rw, bio->bi_size, prio, sync, unplug, ff);
	}
#endif

	down(&input->kick_sem);

	bio_for_each_segment(bvec, bio, i) {
		int bv_len = bvec->bv_len;
		void *data = kmap(bvec->bv_page);
		data += bvec->bv_offset;

		while (bv_len > 0) {
			struct list_head *tmp;
			unsigned long flags;
			int len = 0;

			mref = NULL;
			mref_a = NULL;
#ifdef LOG
			MARS_INF("rw = %d i = %d pos = %lld  bv_page = %p bv_offset = %d data = %p bv_len = %d\n", rw, i, pos, bvec->bv_page, bvec->bv_offset, data, bv_len);
#endif

#ifdef REQUEST_MERGING
			traced_lock(&input->req_lock, flags);
			for (tmp = input->plug_anchor.next; tmp != &input->plug_anchor; tmp = tmp->next) {
				struct if_device_mref_aspect *tmp_a;
				tmp_a = container_of(tmp, struct if_device_mref_aspect, plug_head);
				len = bv_len;
#ifdef LOG
				MARS_INF("bio = %p mref = %p len = %d maxlen = %d\n", bio, mref, len, tmp_a->maxlen);
#endif
				if (len > tmp_a->maxlen) {
					len = tmp_a->maxlen;
				}
				if (len <= 0 || tmp_a->bio_count >= MAX_BIO)
					continue;

				if (tmp_a->object->ref_data + tmp_a->object->ref_len == data && tmp_a->object->ref_rw == rw
				   && tmp_a->orig_page == bvec->bv_page) {
					mref_a = tmp_a;
					mref = tmp_a->object;
					mref->ref_len += len;
					mref_a->maxlen -= len;
					CHECK_ATOMIC(&bio->bi_comp_cnt, 0);
					atomic_inc(&bio->bi_comp_cnt);
					mref_a->orig_bio[mref_a->bio_count++] = bio;
					assigned = true;

#ifdef LOG
					MARS_INF("merge bio = %p mref = %p bio_count = %d len = %d ref_len = %d\n", bio, mref, mref_a->bio_count, len, mref->ref_len);
#endif
					break;
				}
			}
			traced_unlock(&input->req_lock, flags);
#endif
			if (!mref) {
				error = -ENOMEM;
				mref = if_device_alloc_mref(&brick->hidden_output, &input->mref_object_layout);
				if (unlikely(!mref)) {
					up(&input->kick_sem);
					goto err;
				}
				mref_a = if_device_mref_get_aspect(&brick->hidden_output, mref);
				if (unlikely(!mref_a)) {
					up(&input->kick_sem);
					goto err;
				}
				cb = &mref_a->cb;
				cb->cb_fn = _if_device_endio;
				cb->cb_private = mref_a;
				cb->cb_error = 0;
				cb->cb_prev = NULL;
				mref->ref_cb = cb;
				mref_a->input = input;
				mref->ref_rw = mref->ref_may_write = rw;
				mref->ref_pos = pos;
				mref->ref_len = PAGE_SIZE;
				//mref->ref_len = 512;
				mref->ref_data = data; // direct IO

				error = GENERIC_INPUT_CALL(input, mref_get, mref);
				if (unlikely(error < 0)) {
					up(&input->kick_sem);
					goto err;
				}
				
				CHECK_ATOMIC(&bio->bi_comp_cnt, 0);
				atomic_inc(&bio->bi_comp_cnt);
				mref_a->orig_page = bvec->bv_page;
				mref_a->orig_bio[0] = bio;
				mref_a->bio_count = 1;
				assigned = true;

				len = bv_len;
				if (len > mref->ref_len)
					len = mref->ref_len;
				mref_a->maxlen = mref->ref_len - len;
				mref->ref_len = len;
				
				traced_lock(&input->req_lock, flags);
				list_add_tail(&mref_a->plug_head, &input->plug_anchor);
				traced_unlock(&input->req_lock, flags);
			}

			pos += len;
			data += len;
			bv_len -= len;
		} // while bv_len > 0
	} // foreach bvec

	up(&input->kick_sem);

	error = 0;

err:

	if (error < 0) {
		MARS_ERR("cannot submit request, status=%d\n", error);
		if (assigned) {
			//...
		} else {
			bio->bi_check3++;
			bio_endio(bio, error);
		}
	}

	if (unplug) {
		_if_device_unplug(input);
	}

	return error;
}

static int if_device_open(struct block_device *bdev, fmode_t mode)
{
	struct if_device_input *input = bdev->bd_disk->private_data;
	(void)input;
	MARS_DBG("if_device_open()\n");
	return 0;
}

static int if_device_release(struct gendisk *gd, fmode_t mode)
{
	MARS_DBG("if_device_close()\n");
	return 0;
}

static const struct block_device_operations if_device_blkdev_ops = {
	.owner =   THIS_MODULE,
	.open =    if_device_open,
	.release = if_device_release,

};

////////////////// own brick / input / output operations //////////////////

static void if_device_unplug(struct request_queue *q)
{
	struct if_device_input *input = q->queuedata;
	MARS_DBG("UNPLUG\n");
#ifdef LOG
	MARS_INF("UNPLUG\n");
#endif
	queue_flag_clear_unlocked(QUEUE_FLAG_PLUGGED, q);
	_if_device_unplug(input);
}


//////////////// object / aspect constructors / destructors ///////////////

static int if_device_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct if_device_mref_aspect *ini = (void*)_ini;
	//INIT_LIST_HEAD(&ini->tmp_head);
	INIT_LIST_HEAD(&ini->plug_head);
	return 0;
}

static void if_device_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct if_device_mref_aspect *ini = (void*)_ini;
	//CHECK_HEAD_EMPTY(&ini->tmp_head);
	CHECK_HEAD_EMPTY(&ini->plug_head);
}

MARS_MAKE_STATICS(if_device);

//////////////////////// contructors / destructors ////////////////////////

static int if_device_brick_construct(struct if_device_brick *brick)
{
	struct if_device_output *hidden = &brick->hidden_output;
	_if_device_output_init(brick, hidden, "internal");
	return 0;
}

static int if_device_brick_destruct(struct if_device_brick *brick)
{
	return 0;
}

static int if_device_switch(struct if_device_brick *brick)
{
	struct if_device_input *input = brick->inputs[0];
	struct request_queue *q;
	struct gendisk *disk;
	int minor;
	struct mars_info info = {};
	unsigned long capacity;
	int status;

	if (brick->power.button) {
		mars_power_led_off((void*)brick,  false);
		status = GENERIC_INPUT_CALL(input, mars_get_info, &info);
		if (status < 0) {
			MARS_ERR("cannot get device info, status=%d\n", status);
			return status;
		}
		capacity = info.current_size >> 9; // TODO: make this dynamic
		
		q = blk_alloc_queue(GFP_MARS);
		if (!q) {
			MARS_ERR("cannot allocate device request queue\n");
			return -ENOMEM;
		}
		q->queuedata = input;
		input->q = q;
		
		//MARS_DBG("2\n");
		disk = alloc_disk(1);
		if (!disk) {
			MARS_ERR("cannot allocate gendisk\n");
			return -ENOMEM;
		}

		//MARS_DBG("3\n");
		minor = device_minor++; //TODO: protect against races (e.g. atomic_t)
		disk->queue = q;
		disk->major = MARS_MAJOR; //TODO: make this dynamic for >256 devices
		disk->first_minor = minor;
		disk->fops = &if_device_blkdev_ops;
		//snprintf(disk->disk_name, sizeof(disk->disk_name),  "mars%d", minor);
		snprintf(disk->disk_name, sizeof(disk->disk_name),  "mars/%s", brick->brick_name);
		MARS_DBG("created device name %s\n", disk->disk_name);
		disk->private_data = input;
		set_capacity(disk, capacity);
		
		blk_queue_make_request(q, if_device_make_request);
		blk_queue_max_segment_size(q, MARS_MAX_SEGMENT_SIZE);
		blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
		q->unplug_fn = if_device_unplug;
		sema_init(&input->kick_sem, 1);
		spin_lock_init(&input->req_lock);
		q->queue_lock = &input->req_lock; // needed!
		//blk_queue_ordered(q, QUEUE_ORDERED_DRAIN, NULL);//???
		
		//MARS_DBG("4\n");
		input->bdev = bdget(MKDEV(disk->major, minor));
		/* we have no partitions. we contain only ourselves. */
		input->bdev->bd_contains = input->bdev;

#if 0 // ???
		q->backing_dev_info.congested_fn = mars_congested;
		q->backing_dev_info.congested_data = input;
#endif

#if 0 // ???
		blk_queue_merge_bvec(q, mars_merge_bvec);
#endif
		INIT_LIST_HEAD(&input->plug_anchor);

		// point of no return
		//MARS_DBG("99999\n");
		add_disk(disk);
		input->disk = disk;
		//set_device_ro(input->bdev, 0); // TODO: implement modes
		mars_power_led_on((void*)brick, true);
	} else {
		mars_power_led_on((void*)brick, false);
		if (input->bdev) {
			bdput(input->bdev);
			input->bdev = NULL;
		}
		disk = input->disk;
		if (disk) {
			q = disk->queue;
			del_gendisk(input->disk);
			put_disk(input->disk);
			input->disk = NULL;
			if (q) {
				blk_cleanup_queue(q);
			}
		}
		//........
		mars_power_led_off((void*)brick, true);
	}
	return 0;
}

static int if_device_input_construct(struct if_device_input *input)
{
	return 0;
}

static int if_device_input_destruct(struct if_device_input *input)
{
	if (input->bdev)
		bdput(input->bdev);
	if (input->disk) {
		del_gendisk(input->disk);
		//put_disk(input->disk);
	}
	if (input->q)
		blk_cleanup_queue(input->q);
	return 0;
}

static int if_device_output_construct(struct if_device_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct if_device_brick_ops if_device_brick_ops = {
	.brick_switch = if_device_switch,
};

static struct if_device_output_ops if_device_output_ops = {
	.make_object_layout = if_device_make_object_layout,
};

const struct if_device_input_type if_device_input_type = {
	.type_name = "if_device_input",
	.input_size = sizeof(struct if_device_input),
	.input_construct = &if_device_input_construct,
	.input_destruct = &if_device_input_destruct,
};

static const struct if_device_input_type *if_device_input_types[] = {
	&if_device_input_type,
};

const struct if_device_output_type if_device_output_type = {
	.type_name = "if_device_output",
	.output_size = sizeof(struct if_device_output),
	.master_ops = &if_device_output_ops,
	.output_construct = &if_device_output_construct,
	.aspect_types = if_device_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
};
const struct if_device_brick_type if_device_brick_type = {
	.type_name = "if_device_brick",
	.brick_size = sizeof(struct if_device_brick),
	.max_inputs = 1,
	.max_outputs = 0,
	.master_ops = &if_device_brick_ops,
	.default_input_types = if_device_input_types,
	.brick_construct = &if_device_brick_construct,
	.brick_destruct = &if_device_brick_destruct,
};
EXPORT_SYMBOL_GPL(if_device_brick_type);

////////////////// module init stuff /////////////////////////

static void __exit exit_if_device(void)
{
	int status;
	MARS_INF("exit_if_device()\n");
	status = if_device_unregister_brick_type();
	unregister_blkdev(MARS_MAJOR, "mars");
}

static int __init init_if_device(void)
{
	int status;

	(void)if_device_aspect_types; // not used, shut up gcc

	MARS_INF("init_if_device()\n");
	status = register_blkdev(MARS_MAJOR, "mars");
	if (status)
		return status;
	status = if_device_register_brick_type();
	if (status)
		goto err_device;
	return status;
err_device:
	MARS_ERR("init_if_device() status=%d\n", status);
	exit_if_device();
	return status;
}

MODULE_DESCRIPTION("MARS if_device");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_if_device);
module_exit(exit_if_device);
