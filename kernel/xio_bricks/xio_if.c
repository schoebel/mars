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

/* Interface to a Linux device.
 * 1 Input, 0 Outputs.
 */


#define REQUEST_MERGING
#define ALWAYS_UNPLUG			true
#define PREFETCH_LEN			PAGE_SIZE

/*  low-level device parameters */
#define IF_MAX_SEGMENT_SIZE		PAGE_SIZE
#define USE_MAX_SECTORS			(IF_MAX_SEGMENT_SIZE >> 9)
#define USE_MAX_PHYS_SEGMENTS		(IF_MAX_SEGMENT_SIZE >> 9)
#define USE_MAX_SEGMENT_SIZE		IF_MAX_SEGMENT_SIZE
#define USE_LOGICAL_BLOCK_SIZE		512
#define USE_SEGMENT_BOUNDARY		(PAGE_SIZE-1)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/bio.h>
#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "xio.h"
#include "../lib/lib_limiter.h"

#ifndef XIO_MAJOR
#define XIO_MAJOR			(DRBD_MAJOR + 1)
#endif

/************************ global tuning ***********************/

int if_throttle_start_size;

struct rate_limiter if_throttle = {
	.lim_max_rate = 5000,
};

/************************ own type definitions ***********************/

#include "xio_if.h"

#define IF_HASH_MAX			(PAGE_SIZE / sizeof(struct if_hash_anchor))
#define IF_HASH_CHUNK			(PAGE_SIZE * 32)

struct if_hash_anchor {
	spinlock_t hash_lock;
	struct list_head hash_anchor;
};

/************************ own static definitions ***********************/

/*  TODO: check bounds, ensure that free minor numbers are recycled */
static int device_minor;

/*************** object * aspect constructors * destructors **************/

/************************ linux operations ***********************/

static
void _if_start_io_acct(struct if_input *input, struct bio_wrapper *biow)
{
	struct bio *bio = biow->bio;
	const int rw = bio_data_dir(bio);
	const int cpu = part_stat_lock();

	(void)cpu;
	part_round_stats(cpu, &input->disk->part0);
	part_stat_inc(cpu, &input->disk->part0, ios[rw]);
	part_stat_add(cpu, &input->disk->part0, sectors[rw], bio->bi_iter.bi_size >> 9);
	part_inc_in_flight(&input->disk->part0, rw);
	part_stat_unlock();
	biow->start_time = jiffies;
}

static
void _if_end_io_acct(struct if_input *input, struct bio_wrapper *biow)
{
	unsigned long duration = jiffies - biow->start_time;
	struct bio *bio = biow->bio;
	const int rw = bio_data_dir(bio);
	const int cpu = part_stat_lock();

	(void)cpu;
	part_stat_add(cpu, &input->disk->part0, ticks[rw], duration);
	part_round_stats(cpu, &input->disk->part0);
	part_dec_in_flight(&input->disk->part0, rw);
	part_stat_unlock();
}

/* callback
 */
static
void if_endio(struct generic_callback *cb)
{
	struct if_aio_aspect *aio_a = cb->cb_private;
	struct if_input *input;
	int k;
	int rw;
	int error;

	LAST_CALLBACK(cb);
	if (unlikely(!aio_a || !aio_a->object)) {
		XIO_FAT("aio_a = %p aio = %p, something is very wrong here!\n", aio_a, aio_a->object);
		goto out_return;
	}
	input = aio_a->input;
	CHECK_PTR(input, err);

	rw = aio_a->object->io_rw;

	for (k = 0; k < aio_a->bio_count; k++) {
		struct bio_wrapper *biow;
		struct bio *bio;

		biow = aio_a->orig_biow[k];
		aio_a->orig_biow[k] = NULL;
		CHECK_PTR(biow, err);

		CHECK_ATOMIC(&biow->bi_comp_cnt, 1);
		if (!atomic_dec_and_test(&biow->bi_comp_cnt))
			continue;

		bio = biow->bio;
		CHECK_PTR_NULL(bio, err);

		_if_end_io_acct(input, biow);

		error = CALLBACK_ERROR(aio_a->object);
		if (unlikely(error < 0)) {
			int bi_size = bio->bi_iter.bi_size;

			XIO_ERR("NYI: error=%d RETRY LOGIC %u\n", error, bi_size);
		} else { /*  bio conventions are slightly different... */
			error = 0;
			bio->bi_iter.bi_size = 0;
		}
		bio->bi_error = error;
		bio_endio(bio);
		bio_put(bio);
		brick_mem_free(biow);
	}
	atomic_dec(&input->flying_count);
	if (rw)
		atomic_dec(&input->write_flying_count);
	else
		atomic_dec(&input->read_flying_count);
	goto out_return;
err:
	XIO_FAT("error in callback, giving up\n");
out_return:;
}

/* Kick off plugged aios
 */
static
void _if_unplug(struct if_input *input)
{
	/* struct if_brick *brick = input->brick; */
	LIST_HEAD(tmp_list);
	unsigned long flags;

#ifdef CONFIG_MARS_DEBUG
	might_sleep();
#endif

	spin_lock_irqsave(&input->req_lock, flags);
	if (!list_empty(&input->plug_anchor)) {
		/*  move over the whole list */
		list_replace_init(&input->plug_anchor, &tmp_list);
		atomic_set(&input->plugged_count, 0);
	}
	spin_unlock_irqrestore(&input->req_lock, flags);

	while (!list_empty(&tmp_list)) {
		struct if_aio_aspect *aio_a;
		struct aio_object *aio;
		int hash_index;

		aio_a = container_of(tmp_list.next, struct if_aio_aspect, plug_head);
		list_del_init(&aio_a->plug_head);

		hash_index = aio_a->hash_index;
		spin_lock_irqsave(&input->hash_table[hash_index].hash_lock, flags);
		list_del_init(&aio_a->hash_head);
		spin_unlock_irqrestore(&input->hash_table[hash_index].hash_lock, flags);

		aio = aio_a->object;

		if (unlikely(aio_a->current_len > aio_a->max_len))
			XIO_ERR("request len %d > %d\n", aio_a->current_len, aio_a->max_len);
		aio->io_len = aio_a->current_len;

		atomic_inc(&input->flying_count);
		atomic_inc(&input->total_fire_count);
		if (aio->io_rw)
			atomic_inc(&input->write_flying_count);
		else
			atomic_inc(&input->read_flying_count);
		if (aio->io_skip_sync)
			atomic_inc(&input->total_skip_sync_count);

		GENERIC_INPUT_CALL(input, aio_io, aio);
		GENERIC_INPUT_CALL(input, aio_put, aio);
	}
}

/* accept a linux bio, convert to aio and call buf_io() on it.
 */
static
blk_qc_t if_make_request(struct request_queue *q, struct bio *bio)
{
	struct if_input *input = q->queuedata;
	struct if_brick *brick = input->brick;

	/* Original flags of the source bio
	 */
	const int  rw = bio_data_dir(bio);
	const int  sectors = bio_sectors(bio);

	const bool ahead = bio_flagged(bio, __REQ_RAHEAD) && rw == READ;
	const bool barrier = bio_flagged(bio, __REQ_SOFTBARRIER);
	const bool syncio = bio_flagged(bio, __REQ_SYNC);
	const bool unplug = false;
	const bool meta = bio_flagged(bio, __REQ_META);
	const bool discard = bio_flagged(bio, __REQ_DISCARD);
	const bool noidle = bio_flagged(bio, __REQ_NOIDLE);

	const int  prio = bio_prio(bio);

	/* Transform into XIO flags
	 */
	const int  io_prio =
		(prio == IOPRIO_CLASS_RT || (meta | syncio)) ?
		XIO_PRIO_HIGH :
		(prio == IOPRIO_CLASS_IDLE) ?
		XIO_PRIO_LOW :
		XIO_PRIO_NORMAL;
	const bool do_unplug = ALWAYS_UNPLUG | unplug | noidle;
	const bool do_skip_sync = brick->skip_sync && !(barrier | syncio);

	struct bio_wrapper *biow;
	struct aio_object *aio = NULL;
	struct if_aio_aspect *aio_a;

	struct bio_vec bvec;
	struct bvec_iter i;

	loff_t pos = ((loff_t)bio->bi_iter.bi_sector) << 9; /*	TODO: make dynamic */
	int total_len = bio->bi_iter.bi_size;

	bool assigned = false;
	int error = -EINVAL;

	bind_to_channel(brick->say_channel, current);

	might_sleep();

	blk_queue_split(q, &bio, q->bio_split);

	if (unlikely(!sectors)) {
		_if_unplug(input);
		/* THINK: usually this happens only at write barriers.
		 * We have no "barrier" operation in XIO, since
		 * callback semantics should always denote
		 * "writethrough accomplished".
		 * In case of exceptional semantics, we need to do
		 * something here. For now, we do just nothing.
		 */
		error = 0;
		bio->bi_error = error;
		bio_endio(bio);
		goto done;
	}

	/*  throttling of too big write requests */
	if (rw && if_throttle_start_size > 0) {
		int kb = (total_len + 512) / 1024;

		if (kb >= if_throttle_start_size)
			rate_limit_sleep(&if_throttle, kb);
	}

	(void)ahead; /*  shut up gcc */
	if (unlikely(discard)) { /*  NYI */
		error = 0;
		bio->bi_error = error;
		bio_endio(bio);
		goto done;
	}

	biow = brick_mem_alloc(sizeof(struct bio_wrapper));
	biow->bio = bio;
	atomic_set(&biow->bi_comp_cnt, 0);

	if (rw)
		atomic_inc(&input->total_write_count);
	else
		atomic_inc(&input->total_read_count);
	_if_start_io_acct(input, biow);

	/* Get a reference to the bio.
	 * Will be released after bio_endio().
	 */
	bio_get(bio);

	/* FIXME: THIS IS PROVISIONARY (use event instead)
	 */
	while (unlikely(!brick->power.on_led))
		brick_msleep(100);

	bio_for_each_segment(bvec, bio, i) {
		struct page *page = bvec.bv_page;
		int bv_len = bvec.bv_len;
		int offset = bvec.bv_offset;

		void *data;

#ifdef ARCH_HAS_KMAP
#error FIXME/TODO: the current infrastructure cannot deal with HIGHMEM / kmap()
#error HINT: XIO is supposed to run on big 64bit (storage) servers.
#endif
		data = page_address(page);
		error = -EINVAL;
		if (unlikely(!data))
			break;

		data += offset;

		while (bv_len > 0) {
			struct list_head *tmp;
			int hash_index;
			int this_len = 0;
			unsigned long flags;

			aio = NULL;
			aio_a = NULL;

			hash_index = (pos / IF_HASH_CHUNK) % IF_HASH_MAX;

#ifdef REQUEST_MERGING
			spin_lock_irqsave(&input->hash_table[hash_index].hash_lock, flags);
			for (tmp = input->hash_table[hash_index].hash_anchor.next; tmp != &input->hash_table[hash_index].hash_anchor; tmp = tmp->next) {
				struct if_aio_aspect *tmp_a;
				struct aio_object *tmp_aio;
				int i;

				tmp_a = container_of(tmp, struct if_aio_aspect, hash_head);
				tmp_aio = tmp_a->object;
				if (tmp_a->orig_page != page || tmp_aio->io_rw != rw || tmp_a->bio_count >= MAX_BIO || tmp_a->current_len + bv_len > tmp_a->max_len)
					continue;

				if (tmp_aio->io_data + tmp_a->current_len == data) {
					goto merge_end;
				}
				continue;

merge_end:
				tmp_a->current_len += bv_len;
				aio = tmp_aio;
				aio_a = tmp_a;
				this_len = bv_len;
				if (!do_skip_sync)
					aio->io_skip_sync = false;

				for (i = 0; i < aio_a->bio_count; i++) {
					if (aio_a->orig_biow[i]->bio == bio)
						goto unlock;
				}

				CHECK_ATOMIC(&biow->bi_comp_cnt, 0);
				atomic_inc(&biow->bi_comp_cnt);
				aio_a->orig_biow[aio_a->bio_count++] = biow;
				assigned = true;
				goto unlock;
			} /*  foreach hash collision list member */

unlock:
			spin_unlock_irqrestore(&input->hash_table[hash_index].hash_lock, flags);
#endif
			if (!aio) {
				int prefetch_len;

				error = -ENOMEM;
				aio = if_alloc_aio(brick);
				aio_a = if_aio_get_aspect(brick, aio);
				if (unlikely(!aio_a))
					goto err;

#ifdef PREFETCH_LEN
				prefetch_len = PREFETCH_LEN - offset;
/**/
				if (prefetch_len > total_len)
					prefetch_len = total_len;
				if (pos + prefetch_len > brick->dev_size)
					prefetch_len = brick->dev_size - pos;
				if (prefetch_len < bv_len)
					prefetch_len = bv_len;
#else
				prefetch_len = bv_len;
#endif

				SETUP_CALLBACK(aio, if_endio, aio_a);

				aio_a->input = input;
				aio->io_rw = aio->io_may_write = rw;
				aio->io_pos = pos;
				aio->io_len = prefetch_len;
				aio->io_data = data; /*  direct IO */
				aio->io_prio = io_prio;
				aio_a->orig_page = page;

				error = GENERIC_INPUT_CALL(input, aio_get, aio);
				if (unlikely(error < 0))
					goto err;

				this_len = aio->io_len; /*  now may be shorter than originally requested. */
				aio_a->max_len = this_len;
				if (this_len > bv_len)
					this_len = bv_len;
				aio_a->current_len = this_len;
				if (rw)
					atomic_inc(&input->total_aio_write_count);
				else
					atomic_inc(&input->total_aio_read_count);
				CHECK_ATOMIC(&biow->bi_comp_cnt, 0);
				atomic_inc(&biow->bi_comp_cnt);
				aio_a->orig_biow[0] = biow;
				aio_a->bio_count = 1;
				assigned = true;

				/* When a bio with multiple biovecs is split into
				 * multiple aios, only the last one should be
				 * working in synchronous writethrough mode.
				 */
				aio->io_skip_sync = true;
				if (!do_skip_sync && i.bi_idx + 1 >= bio->bi_iter.bi_idx)
					aio->io_skip_sync = false;

				atomic_inc(&input->plugged_count);

				aio_a->hash_index = hash_index;
				spin_lock_irqsave(&input->hash_table[hash_index].hash_lock, flags);
				list_add_tail(&aio_a->hash_head, &input->hash_table[hash_index].hash_anchor);
				spin_unlock_irqrestore(&input->hash_table[hash_index].hash_lock, flags);

				spin_lock_irqsave(&input->req_lock, flags);
				list_add_tail(&aio_a->plug_head, &input->plug_anchor);
				spin_unlock_irqrestore(&input->req_lock, flags);
			} /*  !aio */

			pos += this_len;
			data += this_len;
			bv_len -= this_len;
		} /*  while bv_len > 0 */
	} /*  foreach bvec */

	error = 0;

err:
	if (error < 0) {
		XIO_ERR("cannot submit request from bio, status=%d\n", error);
		if (!assigned) {
			bio->bi_error = error;
			bio_endio(bio);
		}
	}

	if (do_unplug ||
	   (brick && brick->max_plugged > 0 && atomic_read(&input->plugged_count) > brick->max_plugged)) {
		_if_unplug(input);
	}

done:
	remove_binding_from(brick->say_channel, current);

	return BLK_QC_T_NONE;
}

static
int xio_congested(void *data, int bdi_bits)
{
	struct if_input *input = data;
	int ret = 0;

	if (bdi_bits & (1 << WB_sync_congested) &&
	    atomic_read(&input->read_flying_count) > 0) {
		ret |= (1 << WB_sync_congested);
	}
	if (bdi_bits & (1 << WB_async_congested) &&
	    atomic_read(&input->write_flying_count) > 0) {
		ret |= (1 << WB_async_congested);
	}
	return ret;
}

static
loff_t if_get_capacity(struct if_brick *brick)
{
	/* Don't read always, read only when unknown.
	 * brick->dev_size may be different from underlying sizes,
	 * e.g. when the size symlink indicates a logically smaller
	 * device than physically.
	 */
	if (brick->dev_size <= 0) {
		struct xio_info info = {};
		struct if_input *input = brick->inputs[0];
		int status;

		status = GENERIC_INPUT_CALL(input, xio_get_info, &info);
		if (unlikely(status < 0)) {
			XIO_ERR("cannot get device info, status=%d\n", status);
			return 0;
		}
		XIO_INF("determined default capacity: %lld bytes\n", info.current_size);
		brick->dev_size = info.current_size;
	}
	return brick->dev_size;
}

static
void if_set_capacity(struct if_input *input, loff_t capacity)
{
	CHECK_PTR(input->disk, done);
	CHECK_PTR(input->disk->disk_name, done);
	XIO_INF("new capacity of '%s': %lld bytes\n", input->disk->disk_name, capacity);
	input->capacity = capacity;
	set_capacity(input->disk, capacity >> 9);
	if (likely(input->bdev && input->bdev->bd_inode))
		i_size_write(input->bdev->bd_inode, capacity);
done:;
}

static const struct block_device_operations if_blkdev_ops;

static int if_switch(struct if_brick *brick)
{
	struct if_input *input = brick->inputs[0];
	struct request_queue *q;
	struct gendisk *disk;
	int minor;
	int status = 0;

	down(&brick->switch_sem);

	/*  brick is in operation */
	if (brick->power.button && brick->power.on_led) {
		loff_t capacity;

		capacity = if_get_capacity(brick);
		if (capacity > 0 && capacity != input->capacity) {
			XIO_INF("changing capacity from %lld to %lld\n",
				(long long)input->capacity,
				(long long)capacity);
			if_set_capacity(input, capacity);
		}
	}

	/*  brick should be switched on */
	if (brick->power.button && brick->power.off_led) {
		loff_t capacity;

		xio_set_power_off_led((void *)brick,  false);
		brick->say_channel = get_binding(current);

		status = -ENOMEM;
		q = blk_alloc_queue(GFP_BRICK);
		if (!q) {
			XIO_ERR("cannot allocate device request queue\n");
			goto is_down;
		}
		q->queuedata = input;
		input->q = q;

		disk = alloc_disk(1);
		if (!disk) {
			XIO_ERR("cannot allocate gendisk\n");
			goto is_down;
		}

		minor = device_minor++; /* TODO: protect against races (e.g. atomic_t) */
		set_disk_ro(disk, true);

		disk->queue = q;
		disk->major = XIO_MAJOR; /* TODO: make this dynamic for >256 devices */
		disk->first_minor = minor;
		disk->fops = &if_blkdev_ops;
		snprintf(disk->disk_name, sizeof(disk->disk_name),  "%s", brick->brick_name);
		disk->private_data = input;
		input->disk = disk;
		capacity = if_get_capacity(brick);
		XIO_DBG("created device name %s, capacity=%lld\n", disk->disk_name, capacity);
		if_set_capacity(input, capacity);

		blk_queue_make_request(q, if_make_request);
		blk_set_stacking_limits(&q->limits);
		blk_queue_max_hw_sectors(q, USE_MAX_SECTORS);
		blk_queue_max_segments(q, PAGE_SIZE);
		blk_queue_max_segment_size(q, USE_MAX_SEGMENT_SIZE);
		blk_queue_logical_block_size(q, USE_LOGICAL_BLOCK_SIZE);
		blk_queue_segment_boundary(q, USE_SEGMENT_BOUNDARY);
		blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
		blk_queue_max_write_same_sectors(q, 0);
		q->queue_lock = &input->req_lock; /*  needed! */

		input->bdev = bdget(MKDEV(disk->major, minor));
		/* we have no partitions. we contain only ourselves. */
		input->bdev->bd_contains = input->bdev;

		q->backing_dev_info.congested_fn = xio_congested;
		q->backing_dev_info.congested_data = input;

		/*  point of no return */
		XIO_DBG("add_disk()\n");
		add_disk(disk);
		set_disk_ro(disk, false);

		/*  report success */
		xio_set_power_on_led((void *)brick, true);
		status = 0;
	}

	/*  brick should be switched off */
	if (!brick->power.button && !brick->power.off_led) {
		int opened;
		int plugged;
		int flying;

		xio_set_power_on_led((void *)brick, false);
		disk = input->disk;
		if (!disk)
			goto is_down;

		opened = atomic_read(&brick->open_count);
		if (unlikely(opened > 0)) {
			XIO_INF("device '%s' is open %d times, cannot shutdown\n", disk->disk_name, opened);
			status = -EBUSY;
			goto done; /*  don't indicate "off" status */
		}
		plugged = atomic_read(&input->plugged_count);
		if (unlikely(plugged > 0)) {
			XIO_INF("device '%s' has %d plugged requests, cannot shutdown\n", disk->disk_name, plugged);
			status = -EBUSY;
			goto done; /*  don't indicate "off" status */
		}
		flying = atomic_read(&input->flying_count);
		if (unlikely(flying > 0)) {
			XIO_INF("device '%s' has %d flying requests, cannot shutdown\n", disk->disk_name, flying);
			status = -EBUSY;
			goto done; /*  don't indicate "off" status */
		}
		XIO_DBG("calling del_gendisk()\n");
		del_gendisk(input->disk);
		/* There might be subtle races */
		while (atomic_read(&input->flying_count) > 0) {
			XIO_WRN("device '%s' unexpectedly has %d flying requests\n", disk->disk_name, flying);
			brick_msleep(1000);
		}
		if (input->bdev) {
			XIO_DBG("calling bdput()\n");
			bdput(input->bdev);
			input->bdev = NULL;
		}
		XIO_DBG("calling put_disk()\n");
		put_disk(input->disk);
		input->disk = NULL;
		q = input->q;
		if (q) {
			blk_cleanup_queue(q);
			input->q = NULL;
		}
		status = 0;
is_down:
		xio_set_power_off_led((void *)brick, true);
	}

done:
	up(&brick->switch_sem);
	return status;
}

/*************** interface to the outer world (kernel) **************/

static int if_open(struct block_device *bdev, fmode_t mode)
{
	struct if_input *input;
	struct if_brick *brick;

	if (unlikely(!bdev || !bdev->bd_disk)) {
		XIO_ERR("----------------------- INVAL ------------------------------\n");
		return -EINVAL;
	}

	input = bdev->bd_disk->private_data;

	if (unlikely(!input || !input->brick)) {
		XIO_ERR("----------------------- BAD IF SETUP ------------------------------\n");
		return -EINVAL;
	}
	brick = input->brick;

	down(&brick->switch_sem);

	if (unlikely(!brick->power.on_led)) {
		XIO_INF("----------------------- BUSY %d ------------------------------\n",
			atomic_read(&brick->open_count));
		up(&brick->switch_sem);
		return -EBUSY;
	}

	atomic_inc(&brick->open_count);

	XIO_INF("----------------------- OPEN %d ------------------------------\n", atomic_read(&brick->open_count));

	up(&brick->switch_sem);
	return 0;
}

static
void
if_release(struct gendisk *gd, fmode_t mode)
{
	struct if_input *input = gd->private_data;
	struct if_brick *brick = input->brick;
	int nr;

	XIO_INF("----------------------- CLOSE %d ------------------------------\n", atomic_read(&brick->open_count));

	if (atomic_dec_and_test(&brick->open_count)) {
		while ((nr = atomic_read(&input->flying_count)) > 0) {
			XIO_INF("%d IO requests not yet completed\n", nr);
			brick_msleep(1000);
		}

		XIO_DBG("status button=%d on_led=%d off_led=%d\n",
			brick->power.button,
			brick->power.on_led,
			brick->power.off_led);
		local_trigger();
	}
}

static const struct block_device_operations if_blkdev_ops = {
	.owner = THIS_MODULE,
	.open = if_open,
	.release = if_release,

};

/*************** informational * statistics **************/

static
char *if_statistics(struct if_brick *brick, int verbose)
{
	struct if_input *input = brick->inputs[0];
	char *res = brick_string_alloc(512);
	int tmp0 = atomic_read(&input->total_reada_count);
	int tmp1 = atomic_read(&input->total_read_count);
	int tmp2 = atomic_read(&input->total_aio_read_count);
	int tmp3 = atomic_read(&input->total_write_count);
	int tmp4 = atomic_read(&input->total_aio_write_count);

	snprintf(res, 512,
		 "total reada = %d "
		 "reads = %d "
		 "aio_reads = %d (%d%%) "
		 "writes = %d "
		 "aio_writes = %d (%d%%) "
		 "empty = %d "
		 "fired = %d "
		 "skip_sync = %d "
		 "| "
		 "plugged = %d "
		 "flying = %d "
		 "(reads = %d writes = %d)\n",
		 tmp0,
		 tmp1,
		 tmp2,
		 tmp1 ? tmp2 * 100 / tmp1 : 0,
		 tmp3,
		 tmp4,
		 tmp3 ? tmp4 * 100 / tmp3 : 0,
		 atomic_read(&input->total_empty_count),
		 atomic_read(&input->total_fire_count),
		 atomic_read(&input->total_skip_sync_count),
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
	atomic_set(&input->total_empty_count, 0);
	atomic_set(&input->total_fire_count, 0);
	atomic_set(&input->total_skip_sync_count, 0);
	atomic_set(&input->total_aio_read_count, 0);
	atomic_set(&input->total_aio_write_count, 0);
}

/***************** own brick * input * output operations *****************/

/*  none */

/*************** object * aspect constructors * destructors **************/

static int if_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct if_aio_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->plug_head);
	INIT_LIST_HEAD(&ini->hash_head);
	return 0;
}

static void if_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct if_aio_aspect *ini = (void *)_ini;

	CHECK_HEAD_EMPTY(&ini->plug_head);
	CHECK_HEAD_EMPTY(&ini->hash_head);
}

XIO_MAKE_STATICS(if);

/*********************** constructors * destructors ***********************/

static int if_brick_construct(struct if_brick *brick)
{
	sema_init(&brick->switch_sem, 1);
	atomic_set(&brick->open_count, 0);
	return 0;
}

static int if_brick_destruct(struct if_brick *brick)
{
	return 0;
}

static int if_input_construct(struct if_input *input)
{
	int i;

	input->hash_table = brick_block_alloc(0, PAGE_SIZE);
	for (i = 0; i < IF_HASH_MAX; i++) {
		spin_lock_init(&input->hash_table[i].hash_lock);
		INIT_LIST_HEAD(&input->hash_table[i].hash_anchor);
	}
	INIT_LIST_HEAD(&input->plug_anchor);
	spin_lock_init(&input->req_lock);
	atomic_set(&input->flying_count, 0);
	atomic_set(&input->read_flying_count, 0);
	atomic_set(&input->write_flying_count, 0);
	atomic_set(&input->plugged_count, 0);
	return 0;
}

static int if_input_destruct(struct if_input *input)
{
	int i;

	for (i = 0; i < IF_HASH_MAX; i++)
		CHECK_HEAD_EMPTY(&input->hash_table[i].hash_anchor);
	CHECK_HEAD_EMPTY(&input->plug_anchor);
	brick_block_free(input->hash_table, PAGE_SIZE);
	return 0;
}

static int if_output_construct(struct if_output *output)
{
	return 0;
}

/************************ static structs ***********************/

static struct if_brick_ops if_brick_ops = {
	.brick_switch = if_switch,
	.brick_statistics = if_statistics,
	.reset_statistics = if_reset_statistics,
};

static struct if_output_ops if_output_ops;

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
	.aspect_types = if_aspect_types,
	.default_input_types = if_input_types,
	.default_output_types = if_output_types,
	.brick_construct = &if_brick_construct,
	.brick_destruct = &if_brick_destruct,
};

/***************** module init stuff ************************/

void exit_xio_if(void)
{
	int status;

	XIO_INF("exit_if()\n");
	status = if_unregister_brick_type();
	unregister_blkdev(XIO_MAJOR, "xio");
}

int __init init_xio_if(void)
{
	int status;

	(void)if_aspect_types; /*  not used, shut up gcc */

	XIO_INF("init_if()\n");
	status = register_blkdev(XIO_MAJOR, "xio");
	if (status)
		return status;
	status = if_register_brick_type();
	if (status)
		goto err_device;
	return status;
err_device:
	XIO_ERR("init_if() status=%d\n", status);
	exit_xio_if();
	return status;
}
