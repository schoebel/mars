/*
 * MARS Long Distance Replication Software
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*  Bio brick (interface to blkdev IO via kernel bios) */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>

#include "xio.h"
#include "../lib/lib_timing.h"
#include "lib_mapfree.h"

#include "xio_bio.h"
static struct timing_stats timings[2];

struct threshold bio_submit_threshold = {
	.thr_ban = &xio_global_ban,
	.thr_parent = &global_io_threshold,
	.thr_limit = BIO_SUBMIT_MAX_LATENCY,
	.thr_factor = 100,
	.thr_plus = 0,
};

struct threshold bio_io_threshold[2] = {
	[0] = {
		.thr_ban = &xio_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = BIO_IO_R_MAX_LATENCY,
		.thr_factor = 10,
		.thr_plus = 10000,
	},
	[1] = {
		.thr_ban = &xio_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = BIO_IO_W_MAX_LATENCY,
		.thr_factor = 10,
		.thr_plus = 10000,
	},
};

/************************ own type definitions ***********************/

/************************ own helper functions ***********************/

/* This is called from the kernel bio layer.
 */
static
void bio_callback(struct bio *bio)
{
	struct bio_aio_aspect *aio_a = bio->bi_private;
	struct bio_brick *brick;
	unsigned long flags;

	CHECK_PTR(aio_a, err);
	CHECK_PTR(aio_a->output, err);
	brick = aio_a->output->brick;
	CHECK_PTR(brick, err);

	aio_a->status_code = bio->bi_error;

	spin_lock_irqsave(&brick->lock, flags);
	list_del(&aio_a->io_head);
	list_add_tail(&aio_a->io_head, &brick->completed_list);
	atomic_inc(&brick->completed_count);
	spin_unlock_irqrestore(&brick->lock, flags);

	wake_up_interruptible(&brick->response_event);
	goto out_return;
err:
	XIO_FAT("cannot handle bio callback\n");
out_return:;
}

/* Map from kernel address/length to struct page (if not already known),
 * check alignment constraints, create bio from it.
 * Return the length (may be smaller than requested).
 */
static
int make_bio(struct bio_brick *brick,
	void *data,
	int len,
	loff_t pos,
	struct bio_aio_aspect *private,
	struct bio **_bio)
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
		XIO_ERR("bad bio len %d\n", rest_len);
		goto out;
	}

	sector = pos >> 9;		       /*  TODO: make dynamic */
	sector_offset = pos & ((1 << 9) - 1);  /*  TODO: make dynamic */
	data_offset = ((unsigned long)data) & ((1 << 9) - 1);  /*  TODO: make dynamic */

	if (unlikely(sector_offset > 0)) {
		XIO_ERR("odd sector offset %d\n", sector_offset);
		goto out;
	}
	if (unlikely(sector_offset != data_offset)) {
		XIO_ERR("bad alignment: sector_offset %d != data_offset %d\n", sector_offset, data_offset);
		goto out;
	}
	if (unlikely(rest_len & ((1 << 9) - 1))) {
		XIO_ERR("odd length %d\n", rest_len);
		goto out;
	}

	page_offset = ((unsigned long)data) & (PAGE_SIZE-1);
	page_len = rest_len + page_offset;
	bvec_count = (page_len - 1) / PAGE_SIZE + 1;
	if (bvec_count > brick->bvec_max) {
		bvec_count = brick->bvec_max;
	} else if (unlikely(bvec_count <= 0)) {
		XIO_WRN("bvec_count=%d\n", bvec_count);
		bvec_count = 1;
	}

	bio = bio_alloc(GFP_BRICK, bvec_count);
	status = -ENOMEM;

	for (i = 0; i < bvec_count && rest_len > 0; i++) {
		struct page *page;
		int this_rest = PAGE_SIZE - page_offset;
		int this_len = rest_len;

		if (this_len > this_rest)
			this_len = this_rest;

		page = brick_iomap(data, &page_offset, &this_len);
		if (unlikely(!page)) {
			XIO_ERR("cannot iomap() kernel address %p\n", data);
			status = -EINVAL;
			goto out;
		}

		bio->bi_io_vec[i].bv_page = page;
		bio->bi_io_vec[i].bv_len = this_len;
		bio->bi_io_vec[i].bv_offset = page_offset;

		data += this_len;
		rest_len -= this_len;
		result_len += this_len;
		page_offset = 0;
	}

	if (unlikely(rest_len != 0)) {
		XIO_ERR("computation of bvec_count %d was wrong, diff=%d\n", bvec_count, rest_len);
		status = -EINVAL;
		goto out;
	}

	bio->bi_vcnt = i;
	bio->bi_iter.bi_idx = 0;
	bio->bi_iter.bi_size = result_len;
	bio->bi_iter.bi_sector = sector;
	bio->bi_bdev = bdev;
	bio->bi_private = private;
	bio->bi_end_io = bio_callback;
	bio->bi_rw = 0; /*  must be filled in later */
	status = result_len;

out:
	if (unlikely(status < 0)) {
		XIO_ERR("error %d\n", status);
		if (bio) {
			bio_put(bio);
			bio = NULL;
		}
	}
	*_bio = bio;
	return status;
}

/***************** own brick * input * output operations *****************/

#define PRIO_INDEX(aio) ((aio)->io_prio + 1)

static int bio_get_info(struct bio_output *output, struct xio_info *info)
{
	struct bio_brick *brick = output->brick;
	struct inode *inode;
	int status = -ENOENT;

	if (unlikely(!brick->mf ||
		     !brick->mf->mf_filp ||
		     !brick->mf->mf_filp->f_mapping)) {
		goto done;
	}
	inode = brick->mf->mf_filp->f_mapping->host;
	if (unlikely(!inode))
		goto done;

	info->tf_align = 512;
	info->tf_min_size = 512;
	brick->total_size = i_size_read(inode);
	info->current_size = brick->total_size;
	XIO_DBG("determined device size = %lld\n", info->current_size);
	status = 0;

done:
	return status;
}

static int bio_io_get(struct bio_output *output, struct aio_object *aio)
{
	struct bio_aio_aspect *aio_a;
	int status = -EINVAL;

	CHECK_PTR(output, done);
	CHECK_PTR(output->brick, done);

	if (aio->obj_initialized) {
		obj_get(aio);
		return aio->io_len;
	}

	aio_a = bio_aio_get_aspect(output->brick, aio);
	CHECK_PTR(aio_a, done);
	aio_a->output = output;
	aio_a->bio = NULL;

	if (!aio->io_data) { /*  buffered IO. */
		if (unlikely(aio->io_len <= 0))
			goto done;
		status = -ENOMEM;
		aio->io_data = brick_block_alloc(aio->io_pos, (aio_a->alloc_len = aio->io_len));
		aio_a->do_dealloc = true;
	}

	status = make_bio(output->brick, aio->io_data, aio->io_len, aio->io_pos, aio_a, &aio_a->bio);
	if (unlikely(status < 0 || !aio_a->bio)) {
		XIO_ERR("could not create bio, status = %d\n", status);
		goto done;
	}

	if (unlikely(aio->io_prio < XIO_PRIO_HIGH))
		aio->io_prio = XIO_PRIO_HIGH;
	else if (unlikely(aio->io_prio > XIO_PRIO_LOW))
		aio->io_prio = XIO_PRIO_LOW;

	aio->io_len = status;
	obj_get_first(aio);
	status = 0;

done:
	return status;
}

static
void _bio_io_put(struct bio_output *output, struct aio_object *aio)
{
	struct bio_aio_aspect *aio_a;

	aio->io_total_size = output->brick->total_size;

	aio_a = bio_aio_get_aspect(output->brick, aio);
	CHECK_PTR(aio_a, err);

	if (likely(aio_a->bio)) {
		bio_put(aio_a->bio);
		aio_a->bio = NULL;
	}
	if (aio_a->do_dealloc) {
		brick_block_free(aio->io_data, aio_a->alloc_len);
		aio->io_data = NULL;
	}
	obj_free(aio);

	goto out_return;
err:
	XIO_FAT("cannot work\n");
out_return:;
}

#define BIO_AIO_PUT(output, aio)					\
	({								\
		if (obj_put(aio)) {					\
			_bio_io_put(output, aio);			\
		}							\
	})

static
void bio_io_put(struct bio_output *output, struct aio_object *aio)
{
	BIO_AIO_PUT(output, aio);
}

static
void _bio_io_io(struct bio_output *output, struct aio_object *aio, bool cork)
{
	struct bio_brick *brick = output->brick;
	struct bio_aio_aspect *aio_a = bio_aio_get_aspect(output->brick, aio);
	struct bio *bio;
	unsigned long long latency;
	unsigned long flags;
	int rw;
	int status = -EINVAL;

	CHECK_PTR(aio_a, err);
	bio = aio_a->bio;
	CHECK_PTR(bio, err);

	obj_get(aio);
	atomic_inc(&brick->fly_count[PRIO_INDEX(aio)]);

	bio_get(bio);

	rw = aio->io_rw & 1;
	if (brick->do_noidle && !cork)
		rw |= REQ_NOIDLE;
	if (!aio->io_skip_sync) {
		if (brick->do_sync)
			rw |= REQ_SYNC;
	}

	aio_a->start_stamp = cpu_clock(raw_smp_processor_id());
	spin_lock_irqsave(&brick->lock, flags);
	list_add_tail(&aio_a->io_head, &brick->submitted_list[rw & 1]);
	spin_unlock_irqrestore(&brick->lock, flags);

	bio->bi_rw = rw;
	latency = TIME_STATS(
		&timings[rw & 1],
		submit_bio(rw, bio)
		);

	threshold_check(&bio_submit_threshold, latency);

	status = 0;
#ifdef BIO_EOPNOTSUPP /* missing since b25de9d6da49b1a8760a89672283128aa8c78345 */
	if (unlikely(bio_flagged(bio, BIO_EOPNOTSUPP)))
		status = -EOPNOTSUPP;
#endif

	if (likely(status >= 0))
		goto done;

	bio_put(bio);
	atomic_dec(&brick->fly_count[PRIO_INDEX(aio)]);

err:
	XIO_ERR("IO error %d\n", status);
	CHECKED_CALLBACK(aio, status, done);
	atomic_dec(&xio_global_io_flying);

done:;
}

static
void bio_io_io(struct bio_output *output, struct aio_object *aio)
{
	CHECK_PTR(aio, fatal);

	obj_get(aio);
	atomic_inc(&xio_global_io_flying);

	if (aio->io_prio == XIO_PRIO_LOW ||
	    (aio->io_prio == XIO_PRIO_NORMAL && aio->io_rw)) {
		struct bio_aio_aspect *aio_a = bio_aio_get_aspect(output->brick, aio);
		struct bio_brick *brick = output->brick;
		unsigned long flags;

		spin_lock_irqsave(&brick->lock, flags);
		list_add_tail(&aio_a->io_head, &brick->queue_list[PRIO_INDEX(aio)]);
		atomic_inc(&brick->queue_count[PRIO_INDEX(aio)]);
		spin_unlock_irqrestore(&brick->lock, flags);
		brick->submitted = true;

		wake_up_interruptible(&brick->submit_event);
		goto out_return;
	}

	/*  realtime IO: start immediately */
	_bio_io_io(output, aio, false);
	BIO_AIO_PUT(output, aio);
	goto out_return;
fatal:
	XIO_FAT("cannot handle aio %p on output %p\n", aio, output);
out_return:;
}

static
int bio_response_thread(void *data)
{
	struct bio_brick *brick = data;

	XIO_INF("bio response thread has started on '%s'.\n", brick->brick_path);

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

		wait_event_interruptible_timeout(
			brick->response_event,
			atomic_read(&brick->completed_count) > 0,
			sleeptime);

		spin_lock_irqsave(&brick->lock, flags);
		list_replace_init(&brick->completed_list, &tmp_list);
		spin_unlock_irqrestore(&brick->lock, flags);

		count = 0;
		for (;;) {
			struct list_head *tmp;
			struct bio_aio_aspect *aio_a;
			struct aio_object *aio;
			unsigned long long latency;
			int code;

			if (list_empty(&tmp_list)) {
				if (brick_thread_should_stop() &&
				    atomic_read(&brick->fly_count[0]) +
				    atomic_read(&brick->fly_count[1]) +
				    atomic_read(&brick->fly_count[2]) <= 0)
					goto done;
				break;
			}

			tmp = tmp_list.next;
			list_del_init(tmp);
			atomic_dec(&brick->completed_count);

			aio_a = container_of(tmp, struct bio_aio_aspect, io_head);
			aio = aio_a->object;

			latency = cpu_clock(raw_smp_processor_id()) - aio_a->start_stamp;
			threshold_check(&bio_io_threshold[aio->io_rw & 1], latency);

			code = aio_a->status_code;

			if (code < 0) {
				XIO_ERR("IO error %d\n", code);
			} else {
				aio_checksum(aio);
				aio->io_flags |= AIO_UPTODATE;
			}

			SIMPLE_CALLBACK(aio, code);

			atomic_dec(&brick->fly_count[PRIO_INDEX(aio)]);
			atomic_inc(&brick->total_completed_count[PRIO_INDEX(aio)]);
			count++;

			if (likely(aio_a->bio))
				bio_put(aio_a->bio);
			BIO_AIO_PUT(aio_a->output, aio);

			atomic_dec(&xio_global_io_flying);
		}

		/* Try to detect slow requests as early as possible,
		 * even before they have completed.
		 */
		for (i = 0; i < 2; i++) {
			unsigned long long eldest = 0;

			spin_lock_irqsave(&brick->lock, flags);
			if (!list_empty(&brick->submitted_list[i])) {
				struct bio_aio_aspect *aio_a;

				aio_a = container_of(brick->submitted_list[i].next, struct bio_aio_aspect, io_head);
				eldest = aio_a->start_stamp;
			}
			spin_unlock_irqrestore(&brick->lock, flags);

			if (eldest)
				threshold_check(&bio_io_threshold[i], cpu_clock(raw_smp_processor_id()) - eldest);
		}

		if (count) {
			brick->submitted = true;
			wake_up_interruptible(&brick->submit_event);
		}
	}
done:
	XIO_INF("bio response thread has stopped.\n");
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

	XIO_INF("bio submit thread has started on '%s'.\n", brick->brick_path);

	while (!brick_thread_should_stop()) {
		int prio;

		wait_event_interruptible_timeout(
			brick->submit_event,
			brick->submitted,
			HZ / 2);

		brick->submitted = false;

		for (prio = 0; prio < XIO_PRIO_NR; prio++) {
			LIST_HEAD(tmp_list);
			unsigned long flags;

			if (prio == XIO_PRIO_NR-1 && !_bg_should_run(brick))
				break;

			spin_lock_irqsave(&brick->lock, flags);
			list_replace_init(&brick->queue_list[prio], &tmp_list);
			spin_unlock_irqrestore(&brick->lock, flags);

			while (!list_empty(&tmp_list)) {
				struct list_head *tmp = tmp_list.next;
				struct bio_aio_aspect *aio_a;
				struct aio_object *aio;
				bool cork;

				list_del_init(tmp);

				aio_a = container_of(tmp, struct bio_aio_aspect, io_head);
				aio = aio_a->object;
				if (unlikely(!aio)) {
					XIO_ERR("invalid aio\n");
					continue;
				}

				atomic_dec(&brick->queue_count[PRIO_INDEX(aio)]);
				cork = atomic_read(&brick->queue_count[PRIO_INDEX(aio)]) > 0;

				_bio_io_io(aio_a->output, aio, cork);

				BIO_AIO_PUT(aio_a->output, aio);
			}
		}
	}

	XIO_INF("bio submit thread has stopped.\n");
	return 0;
}

static int bio_switch(struct bio_brick *brick)
{
	int status = 0;

	if (brick->power.button) {
		if (brick->power.on_led)
			goto done;

		xio_set_power_off_led((void *)brick, false);

		if (!brick->bdev) {
			static int index;
			const char *path = brick->brick_path;
			int flags = O_RDWR | O_EXCL | O_LARGEFILE;
			struct address_space *mapping;
			struct inode *inode = NULL;
			struct request_queue *q;

			brick->mf = mapfree_get(path, flags);
			if (unlikely(!brick->mf || !brick->mf->mf_filp)) {
				status = -ENOENT;
				XIO_ERR("cannot open file '%s'\n", path);
				goto done;
			}
			mapfree_pages(brick->mf, -1);
			mapping = brick->mf->mf_filp->f_mapping;
			if (likely(mapping))
				inode = mapping->host;
			if (unlikely(!mapping || !inode)) {
				XIO_ERR("internal problem with '%s'\n", path);
				status = -EINVAL;
				goto done;
			}
			if (unlikely(!S_ISBLK(inode->i_mode) || !inode->i_bdev)) {
				XIO_ERR("sorry, '%s' is not a block device\n", path);
				status = -ENODEV;
				goto done;
			}

			mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));

			q = bdev_get_queue(inode->i_bdev);
			if (unlikely(!q)) {
				XIO_ERR("internal queue '%s' does not exist\n", path);
				status = -EINVAL;
				goto done;
			}

			XIO_INF("'%s' ra_pages OLD=%lu NEW=%d\n",
				path,
				q->backing_dev_info.ra_pages,
				brick->ra_pages);
			q->backing_dev_info.ra_pages = brick->ra_pages;

			brick->bvec_max = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);
			if (brick->bvec_max > BIO_MAX_PAGES)
				brick->bvec_max = BIO_MAX_PAGES;
			else if (brick->bvec_max <= 1)
				brick->bvec_max = 1;
			brick->total_size = i_size_read(inode);
			XIO_INF("'%s' size=%lld bvec_max=%d\n",
				 path, brick->total_size, brick->bvec_max);

			brick->response_thread = brick_thread_create(bio_response_thread,
				brick,
				"xio_bio_r%d",
				index);
			brick->submit_thread = brick_thread_create(bio_submit_thread, brick, "xio_bio_s%d", index);
			status = -ENOMEM;
			if (likely(brick->submit_thread && brick->response_thread)) {
				brick->bdev = inode->i_bdev;
				brick->mode_ptr = &brick->mf->mf_mode;
				index++;
				status = 0;
			}
		}
	}

	xio_set_power_on_led((void *)brick, brick->power.button && brick->bdev != NULL);

done:
	if (status < 0 || !brick->power.button) {
		if (brick->submit_thread) {
			brick_thread_stop(brick->submit_thread);
			brick->submit_thread = NULL;
		}
		if (brick->response_thread) {
			brick_thread_stop(brick->response_thread);
			brick->response_thread = NULL;
		}
		if (brick->mf) {
			mapfree_put(brick->mf);
			brick->mf = NULL;
		}
		brick->mode_ptr = NULL;
		brick->bdev = NULL;
		if (!brick->power.button) {
			xio_set_power_off_led((void *)brick, true);
			brick->total_size = 0;
		}
	}
	return status;
}

/*************** informational * statistics **************/

static noinline
char *bio_statistics(struct bio_brick *brick, int verbose)
{
	char *res = brick_string_alloc(4096);
	int pos = 0;

	pos += report_timing(&timings[0], res + pos, 4096 - pos);
	pos += report_timing(&timings[1], res + pos, 4096 - pos);

	snprintf(res + pos, 4096 - pos,
		 "total completed[0] = %d completed[1] = %d completed[2] = %d | queued[0] = %d queued[1] = %d queued[2] = %d flying[0] = %d flying[1] = %d flying[2] = %d completing = %d\n",
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

/*************** object * aspect constructors * destructors **************/

static int bio_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct bio_aio_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void bio_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct bio_aio_aspect *ini = (void *)_ini;

	(void)ini;
}

XIO_MAKE_STATICS(bio);

/********************* brick constructors * destructors *******************/

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

/************************ static structs ***********************/

static struct bio_brick_ops bio_brick_ops = {
	.brick_switch = bio_switch,
	.brick_statistics = bio_statistics,
	.reset_statistics = bio_reset_statistics,
};

static struct bio_output_ops bio_output_ops = {
	.xio_get_info = bio_get_info,
	.aio_get = bio_io_get,
	.aio_put = bio_io_put,
	.aio_io = bio_io_io,
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

/***************** module init stuff ************************/

int __init init_xio_bio(void)
{
	XIO_INF("init_bio()\n");
	_bio_brick_type = (void *)&bio_brick_type;
	return bio_register_brick_type();
}

void exit_xio_bio(void)
{
	XIO_INF("exit_bio()\n");
	bio_unregister_brick_type();
}
