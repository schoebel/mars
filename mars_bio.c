// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Bio brick (interface to blkdev IO via kernel bios)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

//#define FAKE_IO

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>

#include "mars.h"
#include "lib_timing.h"

#include "mars_bio.h"

static struct timing_stats timings[2] = {};

struct threshold bio_submit_threshold = {
	.thr_ban = &mars_global_ban,
	.thr_limit = BIO_SUBMIT_MAX_LATENCY,
	.thr_factor = 100,
	.thr_plus = 0,
};
EXPORT_SYMBOL_GPL(bio_submit_threshold);

struct threshold bio_io_threshold[2] = {
	[0] = {
		.thr_ban = &mars_global_ban,
		.thr_limit = BIO_IO_R_MAX_LATENCY,
		.thr_factor = 10,
		.thr_plus = 10000,
	},
	[1] = {
		.thr_ban = &mars_global_ban,
		.thr_limit = BIO_IO_W_MAX_LATENCY,
		.thr_factor = 10,
		.thr_plus = 10000,
	},
};
EXPORT_SYMBOL_GPL(bio_io_threshold);

///////////////////////// own type definitions ////////////////////////

static void bio_ref_put(struct bio_output *output, struct mref_object *mref);

///////////////////////// own helper functions ////////////////////////

/* This is called from the kernel bio layer.
 */
static
void bio_callback(struct bio *bio, int code)
{
	struct bio_mref_aspect *mref_a = bio->bi_private;
	struct bio_brick *brick;
	unsigned long flags;

	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->output, err);
	brick = mref_a->output->brick;
	CHECK_PTR(brick, err);

	mref_a->status_code = code;

	spin_lock_irqsave(&brick->lock, flags);
	list_del(&mref_a->io_head);
	list_add_tail(&mref_a->io_head, &brick->completed_list);
	atomic_inc(&brick->completed_count);
	spin_unlock_irqrestore(&brick->lock, flags);

	wake_up_interruptible(&brick->response_event);
	return;

err:
	MARS_FAT("cannot handle bio callback\n");
}

/* Map from kernel address/length to struct page (if not already known),
 * check alignment constraints, create bio from it.
 * Return the length (may be smaller than requested).
 */
static
int make_bio(struct bio_brick *brick, void *data, int len, loff_t pos, struct bio_mref_aspect *private, struct bio **_bio)
{
	unsigned long long sector;
	int sector_offset;
	int data_offset;
	int page_offset;
	int page_len;
	int bvec_count;
	int rest_len = len;
	int result_len = 0;
	int status;
	int i;
	struct bio *bio = NULL;
	struct block_device *bdev;

	status = -EINVAL;
	CHECK_PTR(brick, out);
	bdev = brick->bdev;
	CHECK_PTR(bdev, out);

	if (unlikely(rest_len <= 0)) {
		MARS_ERR("bad bio len %d\n", rest_len);
		goto out;
	}

	sector = pos >> 9;                     // TODO: make dynamic
	sector_offset = pos & ((1 << 9) - 1);  // TODO: make dynamic
	data_offset = ((unsigned long)data) & ((1 << 9) - 1);  // TODO: make dynamic

	if (unlikely(sector_offset > 0)) {
		MARS_ERR("odd sector offset %d\n", sector_offset);
		goto out;
	}
	if (unlikely(sector_offset != data_offset)) {
		MARS_ERR("bad alignment: sector_offset %d != data_offet %d\n", sector_offset, data_offset);
		goto out;
	}
	if (unlikely(rest_len & ((1 << 9) - 1))) {
		MARS_ERR("odd length %d\n", rest_len);
		goto out;
	}

	page_offset = ((unsigned long)data) & (PAGE_SIZE-1);
	page_len = rest_len + page_offset;
	bvec_count = (page_len - 1) / PAGE_SIZE + 1;
	if (bvec_count > brick->bvec_max) {
		bvec_count = brick->bvec_max;
	}

	MARS_IO("sector_offset = %d data = %p pos = %lld rest_len = %d page_offset = %d page_len = %d bvec_count = %d\n", sector_offset, data, pos, rest_len, page_offset, page_len, bvec_count);

	bio = bio_alloc(GFP_MARS, bvec_count);
	status = -ENOMEM;
	if (unlikely(!bio)) {
		goto out;
	}

	for (i = 0; i < bvec_count && rest_len > 0; i++) {
		struct page *page;
		int this_rest = PAGE_SIZE - page_offset;
		int this_len = rest_len;

		if (this_len > this_rest) {
			this_len = this_rest;
		}
#ifdef MARS_DEBUGGING
		if (unlikely(!virt_addr_valid(data))) {
			MARS_ERR("invalid virtual kernel address %p\n", data);
			status = -EINVAL;
			goto out;
		}
#endif

		page = brick_iomap(data, &page_offset, &this_len);
		if (unlikely(!page)) {
			MARS_ERR("cannot iomap() kernel address %p\n", data);
			status = -EINVAL;
			goto out;
		}

		MARS_IO("  i = %d page = %p bv_len = %d bv_offset = %d\n", i, page, this_len, page_offset);

		bio->bi_io_vec[i].bv_page = page;
		bio->bi_io_vec[i].bv_len = this_len;
		bio->bi_io_vec[i].bv_offset = page_offset;

		data += this_len;
		rest_len -= this_len;
		result_len += this_len;
		page_offset = 0;
		//MARS_IO("page_offset=%d this_len=%d (new len=%d, new status=%d)\n", page_offset, this_len, rest_len, status);
	}

	if (unlikely(rest_len != 0)) {
		MARS_ERR("computation of bvec_count %d was wrong, diff=%d\n", bvec_count, rest_len);
		status = -EIO;
		goto out;
	}

	bio->bi_vcnt = i;
	bio->bi_idx = 0;
	bio->bi_size = result_len;
	bio->bi_sector = sector;
	bio->bi_bdev = bdev;
	bio->bi_private = private;
	bio->bi_end_io = bio_callback;
	bio->bi_rw = 0; // must be filled in later
	status = result_len;

out:
	if (unlikely(status < 0)) {
		MARS_ERR("error %d\n", status);
		if (bio) {
			bio_put(bio);
			bio = NULL;
		}
	}
	*_bio = bio;
	return status;
}


////////////////// own brick / input / output operations //////////////////

#define PRIO_INDEX(mref) ((mref)->ref_prio + 1)

static int bio_get_info(struct bio_output *output, struct mars_info *info)
{
	struct bio_brick *brick = output->brick;
	struct inode *inode;
	int status = 0;

	if (unlikely(!brick->filp ||
		     !brick->filp->f_mapping ||
		     !(inode = brick->filp->f_mapping->host))) {
		status = -ENOENT;
		goto done;
	}
	brick->total_size = inode->i_size;
	info->current_size = brick->total_size;
	MARS_DBG("determined device size = %lld\n", info->current_size);
	info->backing_file = brick->filp;
done:
	return status;
}

static int bio_ref_get(struct bio_output *output, struct mref_object *mref)
{
	struct bio_mref_aspect *mref_a;
	int status = -EINVAL;

	CHECK_PTR(output, done);
	CHECK_PTR(output->brick, done);

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	mref_a = bio_mref_get_aspect(output->brick, mref);
	CHECK_PTR(mref_a, done);
	mref_a->output = output;
	mref_a->bio = NULL;


	if (!mref->ref_data) { // buffered IO.
		status = -ENOMEM;
		mref->ref_data = brick_block_alloc(mref->ref_pos, (mref_a->alloc_len = mref->ref_len));
		if (unlikely(!mref->ref_data)) {
			goto done;
		}
		mref_a->do_dealloc = true;
	}

	status = make_bio(output->brick, mref->ref_data, mref->ref_len, mref->ref_pos, mref_a, &mref_a->bio);
	if (unlikely(status < 0 || !mref_a->bio)) {
		MARS_ERR("could not create bio, status = %d\n", status);
		goto done;
	}

	if (unlikely(mref->ref_prio < MARS_PRIO_HIGH))
		mref->ref_prio = MARS_PRIO_HIGH;
	else if (unlikely(mref->ref_prio > MARS_PRIO_LOW))
		mref->ref_prio = MARS_PRIO_LOW;

	MARS_IO("len = %d status = %d prio = %d fly = %d\n", mref->ref_len, status, mref->ref_prio, atomic_read(&output->brick->fly_count[PRIO_INDEX(mref)]));

	mref->ref_len = status;
	_mref_get_first(mref);
	status = 0;

done:
	return status;
}

static
void bio_ref_put(struct bio_output *output, struct mref_object *mref)
{
	struct bio_mref_aspect *mref_a;

	if (!_mref_put(mref)) {
		goto done;
	}

	MARS_IO("deallocating\n");

	mref->ref_total_size = output->brick->total_size;

	mref_a = bio_mref_get_aspect(output->brick, mref);
	CHECK_PTR(mref_a, err);

	if (likely(mref_a->bio)) {
#ifdef MARS_DEBUGGING
		int bi_cnt = atomic_read(&mref_a->bio->bi_cnt);
		if (bi_cnt > 1) {
			MARS_DBG("bi_cnt = %d\n", bi_cnt);
		}
#endif
		bio_put(mref_a->bio);
		mref_a->bio = NULL;
	}
	if (mref_a->do_dealloc) {
		MARS_IO("free page\n");
		brick_block_free(mref->ref_data, mref_a->alloc_len);
		mref->ref_data = NULL;
	}
	bio_free_mref(mref);

done:
	return;

err:
	MARS_FAT("cannot work\n");
}

static
void _bio_ref_io(struct bio_output *output, struct mref_object *mref, bool cork)
{
	struct bio_brick *brick = output->brick;
	struct bio_mref_aspect *mref_a = bio_mref_get_aspect(output->brick, mref);
	struct bio *bio;
	unsigned long long latency;
	unsigned long flags;
	int rw;
	int status = -EINVAL;

	CHECK_PTR(mref_a, err);
	bio = mref_a->bio;
	CHECK_PTR(bio, err);

	_mref_get(mref);
	atomic_inc(&brick->fly_count[PRIO_INDEX(mref)]);

	bio_get(bio);

	rw = mref->ref_rw & 1;
#ifdef BIO_RW_NOIDLE
	if (brick->do_noidle && !cork) {
		rw |= (1 << BIO_RW_NOIDLE);
	}
#endif
	if (!mref->ref_skip_sync) {
#ifdef BIO_RW_SYNCIO
		if (brick->do_sync) {
			rw |= (1 << BIO_RW_SYNCIO);
		}
#endif
#ifdef BIO_RW_UNPLUG
		if (brick->do_unplug && !cork) {
			rw |= (1 << BIO_RW_UNPLUG);
		}
#endif
	}

	MARS_IO("starting IO rw = %d prio 0 %d fly = %d\n", rw, mref->ref_prio, atomic_read(&brick->fly_count[PRIO_INDEX(mref)]));
	mars_trace(mref, "bio_submit");

	mref_a->start_stamp = cpu_clock(raw_smp_processor_id());
	spin_lock_irqsave(&brick->lock, flags);
	list_add_tail(&mref_a->io_head, &brick->submitted_list[rw & 1]);
	spin_unlock_irqrestore(&brick->lock, flags);

#ifdef FAKE_IO
	bio->bi_end_io(bio, 0);
#else
	bio->bi_rw = rw;
	latency = TIME_STATS(
		&timings[rw & 1],
		submit_bio(rw, bio)
		);
#endif

	threshold_check(&bio_submit_threshold, latency);

	status = 0;
	if (unlikely(bio_flagged(bio, BIO_EOPNOTSUPP)))
		status = -EOPNOTSUPP;

	MARS_IO("submitted\n");

	if (likely(status >= 0))
		goto done;

	bio_put(bio);
	atomic_dec(&brick->fly_count[PRIO_INDEX(mref)]);

err:
	MARS_ERR("IO error %d\n", status);
	CHECKED_CALLBACK(mref, status, done);
	atomic_dec(&mars_global_io_flying);

done: ;
}

static
void bio_ref_io(struct bio_output *output, struct mref_object *mref)
{
	atomic_inc(&mars_global_io_flying);
	if (mref->ref_prio == MARS_PRIO_LOW ||
	    (mref->ref_prio == MARS_PRIO_NORMAL && mref->ref_rw)) {
		struct bio_mref_aspect *mref_a = bio_mref_get_aspect(output->brick, mref);
		struct bio_brick *brick = output->brick;
		unsigned long flags;

		_mref_get(mref);

		spin_lock_irqsave(&brick->lock, flags);
		list_add_tail(&mref_a->io_head, &brick->queue_list[PRIO_INDEX(mref)]);
		atomic_inc(&brick->queue_count[PRIO_INDEX(mref)]);
		spin_unlock_irqrestore(&brick->lock, flags);
		brick->submitted = true;

		wake_up_interruptible(&brick->submit_event);
		return;
	}
	// realtime IO: start immediately
	_bio_ref_io(output, mref, false);
}

static
int bio_response_thread(void *data)
{
	struct bio_brick *brick = data;
#ifdef IO_DEBUGGING
	int round = 0;
#endif

	MARS_INF("bio response thread has started on '%s'.\n", brick->brick_path);

	for (;;) {
		LIST_HEAD(tmp_list);
		unsigned long flags;
		int thr_limit;
		int sleeptime;
		int count;
		int i;

		thr_limit = bio_io_threshold[0].thr_limit;
		if (bio_io_threshold[1].thr_limit < thr_limit)
			thr_limit = bio_io_threshold[1].thr_limit;

		sleeptime = HZ / 10;
		if (thr_limit > 0) {
			sleeptime = thr_limit / (1000000 * 2 / HZ);
			if (unlikely(sleeptime < 2))
				sleeptime = 2;
		}

#ifdef IO_DEBUGGING
		round++;
		MARS_IO("%d sleeping %d...\n", round, sleeptime);
#endif
		wait_event_interruptible_timeout(
			brick->response_event,
			atomic_read(&brick->completed_count) > 0,
			sleeptime);

		MARS_IO("%d woken up, completed_count = %d fly_count[0] = %d fly_count[1] = %d fly_count[2] = %d\n",
			round,
			atomic_read(&brick->completed_count),
			atomic_read(&brick->fly_count[0]),
			atomic_read(&brick->fly_count[1]),
			atomic_read(&brick->fly_count[2]));

		spin_lock_irqsave(&brick->lock, flags);
		list_replace_init(&brick->completed_list, &tmp_list);
		spin_unlock_irqrestore(&brick->lock, flags);

		count = 0;
		for (;;) {
			struct list_head *tmp;
			struct bio_mref_aspect *mref_a;
			struct mref_object *mref;
			unsigned long long latency;
			int code;

			if (list_empty(&tmp_list)) {
				if (brick_thread_should_stop())
					goto done;
				break;
			}
			
			tmp = tmp_list.next;
			list_del_init(tmp);
			atomic_dec(&brick->completed_count);

			mref_a = container_of(tmp, struct bio_mref_aspect, io_head);
			mref = mref_a->object;

			
			latency = cpu_clock(raw_smp_processor_id()) - mref_a->start_stamp;
			threshold_check(&bio_io_threshold[mref->ref_rw & 1], latency);

			code = mref_a->status_code;
#ifdef IO_DEBUGGING
			round++;
			MARS_IO("%d completed , status = %d\n", round, code);
#endif
		
			mars_trace(mref, "bio_endio");

			if (code < 0) {
				MARS_ERR("IO error %d\n", code);
			} else {
				mref_checksum(mref);
				mref->ref_flags |= MREF_UPTODATE;
			}

			SIMPLE_CALLBACK(mref, code);

			MARS_IO("%d callback done.\n", round);
			
			atomic_dec(&brick->fly_count[PRIO_INDEX(mref)]);
			atomic_inc(&brick->total_completed_count[PRIO_INDEX(mref)]);
			count++;

			MARS_IO("%d completed_count = %d fly_count = %d\n", round, atomic_read(&brick->completed_count), atomic_read(&brick->fly_count[PRIO_INDEX(mref)]));

			if (likely(mref_a->bio)) {
				bio_put(mref_a->bio);
			}
			bio_ref_put(mref_a->output, mref);

			atomic_dec(&mars_global_io_flying);
		}

		/* Try to detect slow requests as early as possible,
		 * even before they have completed.
		 */
		for (i = 0; i < 2; i++) {
			unsigned long long eldest = 0;

			spin_lock_irqsave(&brick->lock, flags);
			if (!list_empty(&brick->submitted_list[i])) {
				struct bio_mref_aspect *mref_a;
				mref_a = container_of(brick->submitted_list[i].next, struct bio_mref_aspect, io_head);
				eldest = mref_a->start_stamp;
			}
			spin_unlock_irqrestore(&brick->lock, flags);

			if (eldest) {
				threshold_check(&bio_io_threshold[i], cpu_clock(raw_smp_processor_id()) - eldest);
			}
		}

		if (count) {
			brick->submitted = true;
			wake_up_interruptible(&brick->submit_event);
		}
	}
done:
	MARS_INF("bio response thread has stopped.\n");
	return 0;
}

static
bool _bg_should_run(struct bio_brick *brick)
{
	return (atomic_read(&brick->queue_count[2]) > 0 && 
		atomic_read(&brick->fly_count[0]) + atomic_read(&brick->fly_count[1]) <= brick->bg_threshold &&
		(brick->bg_maxfly <= 0 || atomic_read(&brick->fly_count[2]) < brick->bg_maxfly));
}

static
int bio_submit_thread(void *data)
{
	struct bio_brick *brick = data;
#ifdef IO_DEBUGGING
	int round = 0;
#endif

	MARS_INF("bio submit thread has started on '%s'.\n", brick->brick_path);

	while (!brick_thread_should_stop()) {
		int prio;
#ifdef IO_DEBUGGING
		round++;
		MARS_IO("%d sleeping...\n", round);
#endif
		wait_event_interruptible_timeout(
			brick->submit_event,
			brick->submitted,
			HZ / 2);

		brick->submitted = false;

		MARS_IO("%d woken up, completed_count = %d fly_count[0] = %d fly_count[1] = %d fly_count[2] = %d\n",
			round,
			atomic_read(&brick->completed_count),
			atomic_read(&brick->fly_count[0]),
			atomic_read(&brick->fly_count[1]),
			atomic_read(&brick->fly_count[2]));

		for (prio = 0; prio < MARS_PRIO_NR; prio++) {
			LIST_HEAD(tmp_list);
			unsigned long flags;

			if (prio == MARS_PRIO_NR-1 && !_bg_should_run(brick)) {
				break;
			}

			MARS_IO("%d pushing prio %d to foreground, completed_count = %d\n", round, prio, atomic_read(&brick->completed_count));

			spin_lock_irqsave(&brick->lock, flags);
			list_replace_init(&brick->queue_list[prio], &tmp_list);
			spin_unlock_irqrestore(&brick->lock, flags);

			while (!list_empty(&tmp_list)) {
				struct list_head *tmp = tmp_list.next;
				struct bio_mref_aspect *mref_a;
				struct mref_object *mref;
				bool cork;

				list_del_init(tmp);
				
				mref_a = container_of(tmp, struct bio_mref_aspect, io_head);
				mref = mref_a->object;
				if (unlikely(!mref)) {
					MARS_ERR("invalid mref\n");
					continue;
				}

				atomic_dec(&brick->queue_count[PRIO_INDEX(mref)]);
				cork = atomic_read(&brick->queue_count[PRIO_INDEX(mref)]) > 0;
				
				_bio_ref_io(mref_a->output, mref, cork);

				bio_ref_put(mref_a->output, mref);
			}
		}
	}

	MARS_INF("bio submit thread has stopped.\n");
	return 0;
}

static int bio_switch(struct bio_brick *brick)
{
	int status = 0;
	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		
		if (!brick->bdev) {
			static int index = 0;
			const char *path = brick->brick_path;
			int flags = O_RDWR | O_EXCL | O_LARGEFILE;
			int prot = 0600;
			struct address_space *mapping;
			struct inode *inode;
			struct request_queue *q;
			mm_segment_t oldfs;

			oldfs = get_fs();
			set_fs(get_ds());
			brick->filp = filp_open(path, flags, prot);
			set_fs(oldfs);

			if (unlikely(!brick->filp || IS_ERR(brick->filp))) {
				status = PTR_ERR(brick->filp);
				brick->filp = NULL;
				MARS_ERR("cannot open '%s', status = %d\n", path, status);
				goto done;
			}
			
			if (unlikely(!(mapping = brick->filp->f_mapping) ||
				     !(inode = brick->filp->f_mapping->host))) {
				MARS_ERR("internal problem with '%s'\n", path);
				status = -EINVAL;
				goto done;
			}
			if (unlikely(!S_ISBLK(inode->i_mode) || !inode->i_bdev)) {
				MARS_ERR("sorry, '%s' is not a block device\n", path);
				status = -ENODEV;
				goto done;
			}

			mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));

			q = bdev_get_queue(inode->i_bdev);
			if (unlikely(!q)) {
				MARS_ERR("internal queue '%s' does not exist\n", path);
				status = -EINVAL;
				goto done;
			}

			MARS_INF("'%s' ra_pages OLD=%lu NEW=%d\n", path, q->backing_dev_info.ra_pages, brick->ra_pages);
			q->backing_dev_info.ra_pages = brick->ra_pages;

			brick->bvec_max = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);
			brick->total_size = inode->i_size;

			brick->response_thread = brick_thread_create(bio_response_thread, brick, "mars_bio_r%d", index);
			brick->submit_thread = brick_thread_create(bio_submit_thread, brick, "mars_bio_s%d", index);
			status = -ENOMEM;
			if (likely(brick->submit_thread && brick->response_thread)) {
				brick->bdev = inode->i_bdev;
				index++;
				status = 0;
			}
		}
	}
	
	mars_power_led_on((void*)brick, brick->power.button && brick->bdev != NULL);
	
 done:
	if (status < 0 || !brick->power.button) {
		if (brick->filp) {
			filp_close(brick->filp, NULL);
			brick->filp = NULL;
		}
		if (brick->submit_thread) {
			brick_thread_stop(brick->submit_thread);
			brick->submit_thread = NULL;
		}
		if (brick->response_thread) {
			brick_thread_stop(brick->response_thread);
		}
		brick->bdev = NULL;
		if (!brick->power.button) {
			mars_power_led_off((void*)brick, true);
			brick->total_size = 0;
		}
	}
	return status;
}


//////////////// informational / statistics ///////////////

static noinline
char *bio_statistics(struct bio_brick *brick, int verbose)
{
	char *res = brick_string_alloc(4096);
	int pos = 0;
	if (!res)
		return NULL;

	pos += report_timing(&timings[0], res + pos, 4096 - pos);
	pos += report_timing(&timings[1], res + pos, 4096 - pos);

	snprintf(res + pos, 4096 - pos,
		 "total "
		 "completed[0] = %d "
		 "completed[1] = %d "
		 "completed[2] = %d | "
		 "queued[0] = %d "
		 "queued[1] = %d "
		 "queued[2] = %d "
		 "flying[0] = %d "
		 "flying[1] = %d "
		 "flying[2] = %d "
		 "completing = %d\n",
		 atomic_read(&brick->total_completed_count[0]),
		 atomic_read(&brick->total_completed_count[1]),
		 atomic_read(&brick->total_completed_count[2]),
		 atomic_read(&brick->fly_count[0]),
		 atomic_read(&brick->queue_count[0]),
		 atomic_read(&brick->queue_count[1]),
		 atomic_read(&brick->queue_count[2]),
		 atomic_read(&brick->fly_count[1]),
		 atomic_read(&brick->fly_count[2]),
		 atomic_read(&brick->completed_count));

	return res;
}

static noinline
void bio_reset_statistics(struct bio_brick *brick)
{
	atomic_set(&brick->total_completed_count[0], 0);
	atomic_set(&brick->total_completed_count[1], 0);
	atomic_set(&brick->total_completed_count[2], 0);
}


//////////////// object / aspect constructors / destructors ///////////////

static int bio_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct bio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void bio_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct bio_mref_aspect *ini = (void*)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(bio);

////////////////////// brick constructors / destructors ////////////////////

static int bio_brick_construct(struct bio_brick *brick)
{
	spin_lock_init(&brick->lock);
	INIT_LIST_HEAD(&brick->queue_list[0]);
	INIT_LIST_HEAD(&brick->queue_list[1]);
	INIT_LIST_HEAD(&brick->queue_list[2]);
	INIT_LIST_HEAD(&brick->submitted_list[0]);
	INIT_LIST_HEAD(&brick->submitted_list[1]);
	INIT_LIST_HEAD(&brick->completed_list);
	init_waitqueue_head(&brick->submit_event);
	init_waitqueue_head(&brick->response_event);
	return 0;
}

static int bio_brick_destruct(struct bio_brick *brick)
{
	return 0;
}

static int bio_output_construct(struct bio_output *output)
{
	return 0;
}

static int bio_output_destruct(struct bio_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct bio_brick_ops bio_brick_ops = {
	.brick_switch = bio_switch,
	.brick_statistics = bio_statistics,
	.reset_statistics = bio_reset_statistics,
};

static struct bio_output_ops bio_output_ops = {
	.mars_get_info = bio_get_info,
	.mref_get = bio_ref_get,
	.mref_put = bio_ref_put,
	.mref_io = bio_ref_io,
};

const struct bio_input_type bio_input_type = {
	.type_name = "bio_input",
	.input_size = sizeof(struct bio_input),
};

static const struct bio_input_type *bio_input_types[] = {
	&bio_input_type,
};

const struct bio_output_type bio_output_type = {
	.type_name = "bio_output",
	.output_size = sizeof(struct bio_output),
	.master_ops = &bio_output_ops,
	.output_construct = &bio_output_construct,
	.output_destruct = &bio_output_destruct,
};

static const struct bio_output_type *bio_output_types[] = {
	&bio_output_type,
};

const struct bio_brick_type bio_brick_type = {
	.type_name = "bio_brick",
	.brick_size = sizeof(struct bio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &bio_brick_ops,
	.aspect_types = bio_aspect_types,
	.default_input_types = bio_input_types,
	.default_output_types = bio_output_types,
	.brick_construct = &bio_brick_construct,
	.brick_destruct = &bio_brick_destruct,
};
EXPORT_SYMBOL_GPL(bio_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_bio(void)
{
	MARS_INF("init_bio()\n");
	_bio_brick_type = (void*)&bio_brick_type;
	return bio_register_brick_type();
}

void __exit exit_mars_bio(void)
{
	MARS_INF("exit_bio()\n");
	bio_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS bio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_bio);
module_exit(exit_mars_bio);
#endif
