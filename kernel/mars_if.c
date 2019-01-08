/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/* Interface to a Linux device.
 * 1 Input, 0 Outputs.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#define REQUEST_MERGING
//#define ALWAYS_UNPLUG false // FIXME: does not work! single requests left over!
#define ALWAYS_UNPLUG true
#define ALWAYS_UNPLUG_FROM_EXTERNAL true
#define PREFETCH_LEN PAGE_SIZE
//#define FRONT_MERGE // FIXME: this does not work.
//#define MODIFY_READAHEAD // don't use it, otherwise sequential IO will suffer

// low-level device parameters
#define USE_MAX_SECTORS         (MARS_MAX_SEGMENT_SIZE >> 9)
#define USE_MAX_PHYS_SEGMENTS   (MARS_MAX_SEGMENT_SIZE >> 9)
#define USE_MAX_SEGMENT_SIZE    MARS_MAX_SEGMENT_SIZE
#define USE_LOGICAL_BLOCK_SIZE  512
#define USE_SEGMENT_BOUNDARY    (PAGE_SIZE-1)

#define USE_CONGESTED_FN
//#define DENY_READA

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/bio.h>
#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "mars.h"
#include "lib_limiter.h"

//      remove_this
#ifdef bio_end_sector
#define HAS_VOID_RELEASE
#endif
#ifdef __bvec_iter_bvec
#define HAS_BVEC_ITER
#endif
/* adaptation to 4246a0b63bd8f56a1469b12eafeb875b1041a451 and 8ae126660fddbeebb9251a174e6fa45b6ad8f932 */
#ifndef bio_io_error
#define HAS_BI_ERROR
#else
#define HAS_MERGE_BVEC
#endif

/* 54efd50bfd873e2dbf784e0b21a8027ba4299a3e and 8ae126660fddbeebb9251a174e6fa45b6ad8f932,
 * detected via 4246a0b63bd8f56a1469b12eafeb875b1041a451
 */
#ifndef BIO_UPTODATE
#define NEED_BIO_SPLIT
#endif

//      end_remove_this
///////////////////////// global tuning ////////////////////////

int if_throttle_start_size = 0; // in kb
EXPORT_SYMBOL_GPL(if_throttle_start_size);

struct mars_limiter if_throttle = {
	.lim_max_rate = 5000,
};
EXPORT_SYMBOL_GPL(if_throttle);

///////////////////////// own type definitions ////////////////////////

#include "mars_if.h"

#define IF_HASH_MAX   (PAGE_SIZE / sizeof(struct if_hash_anchor))
#define IF_HASH_CHUNK (PAGE_SIZE * 32)

struct if_hash_anchor {
	spinlock_t hash_lock;
	struct list_head hash_anchor;
};

///////////////////////// own static definitions ////////////////////////

// TODO: check bounds, ensure that free minor numbers are recycled
static int device_minor = 0;

//////////////// object / aspect constructors / destructors ///////////////

///////////////////////// linux operations ////////////////////////

#ifdef part_stat_lock
static
void _if_start_io_acct(struct if_input *input, struct bio_wrapper *biow)
{
	struct bio *bio = biow->bio;
	const int rw = bio_data_dir(bio);
	const int cpu = part_stat_lock();
	(void)cpu;
	part_round_stats(cpu, &input->disk->part0);
	part_stat_inc(cpu, &input->disk->part0, ios[rw]);
//      remove_this
#ifdef HAS_BVEC_ITER
//      end_remove_this
	part_stat_add(cpu, &input->disk->part0, sectors[rw], bio->bi_iter.bi_size >> 9);
//      remove_this
#else
	part_stat_add(cpu, &input->disk->part0, sectors[rw], bio->bi_size >> 9);
#endif
//      end_remove_this
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

#else // part_stat_lock
#define _if_start_io_acct(...) do {} while (0)
#define _if_end_io_acct(...)   do {} while (0)
#endif

/* callback
 */
static
void if_endio(struct generic_callback *cb)
{
	struct if_mref_aspect *mref_a = cb->cb_private;
	struct if_input *input;
	int k;
	int rw;
	int error;

	LAST_CALLBACK(cb);
	if (unlikely(!mref_a || !mref_a->object)) {
		MARS_FAT("mref_a = %p mref = %p, something is very wrong here!\n", mref_a, mref_a->object);
		return;
	}
	input = mref_a->input;
	CHECK_PTR(input, err);

	mars_trace(mref_a->object, "if_endio");
	mars_log_trace(mref_a->object);

	rw = mref_a->object->ref_rw;
	MARS_IO("rw = %d bio_count = %d\n", rw, mref_a->bio_count);

	for (k = 0; k < mref_a->bio_count; k++) {
		struct bio_wrapper *biow;
		struct bio *bio;

		biow = mref_a->orig_biow[k];
		mref_a->orig_biow[k] = NULL;
		CHECK_PTR(biow, err);

		CHECK_ATOMIC(&biow->bi_comp_cnt, 1);
		if (!atomic_dec_and_test(&biow->bi_comp_cnt)) {
			continue;
		}

		bio = biow->bio;
		CHECK_PTR_NULL(bio, err);

		_if_end_io_acct(input, biow);

		error = CALLBACK_ERROR(mref_a->object);
		if (unlikely(error < 0)) {
//      remove_this
#ifdef HAS_BVEC_ITER
//      end_remove_this
			int bi_size = bio->bi_iter.bi_size;
//      remove_this
#else
			int bi_size = bio->bi_size;
#endif
//      end_remove_this
			MARS_ERR("NYI: error=%d RETRY LOGIC %u\n", error, bi_size);
		} else { // bio conventions are slightly different...
			error = 0;
//      remove_this
#ifdef HAS_BVEC_ITER
//      end_remove_this
			bio->bi_iter.bi_size = 0;
//      remove_this
#else
			bio->bi_size = 0;
#endif
//      end_remove_this
		}
		MARS_IO("calling end_io() rw = %d error = %d\n", rw, error);
//      remove_this
#ifdef HAS_BI_ERROR
//      end_remove_this
		bio->bi_error = error;
		bio_endio(bio);
//      remove_this
#else
		bio_endio(bio, error);
#endif
//      end_remove_this
		bio_put(bio);
		brick_mem_free(biow);
	}
	atomic_dec(&input->flying_count);
	if (rw) {
		atomic_dec(&input->write_flying_count);
	} else {
		atomic_dec(&input->read_flying_count);
	}
#ifdef IO_DEBUGGING
		{
			struct if_brick *brick = input->brick;
			char *txt = brick->ops->brick_statistics(brick, false);
			MARS_IO("%s", txt);
			brick_string_free(txt);
		}
#endif
	MARS_IO("finished.\n");
	return;

err:
	MARS_FAT("error in callback, giving up\n");
}

/* Kick off plugged mrefs
 */
static
void _if_unplug(struct if_input *input)
{
	//struct if_brick *brick = input->brick;
	LIST_HEAD(tmp_list);
	unsigned long flags;

#ifdef CONFIG_MARS_DEBUG
	might_sleep();
#endif

	MARS_IO("plugged_count = %d\n", atomic_read(&input->plugged_count));

	down(&input->kick_sem);
	traced_lock(&input->req_lock, flags);
#ifdef USE_TIMER
	del_timer(&input->timer);
#endif
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
		traced_lock(&input->hash_table[hash_index].hash_lock, flags);
		list_del_init(&mref_a->hash_head);
		traced_unlock(&input->hash_table[hash_index].hash_lock, flags);

                mref = mref_a->object;

		if (unlikely(mref_a->current_len > mref_a->max_len)) {
			MARS_ERR("request len %d > %d\n", mref_a->current_len, mref_a->max_len);
		}
		mref->ref_len = mref_a->current_len;

		mars_trace(mref, "if_unplug");

		atomic_inc(&input->flying_count);
		atomic_inc(&input->total_fire_count);
		if (mref->ref_rw) {
			atomic_inc(&input->write_flying_count);
		} else {
			atomic_inc(&input->read_flying_count);
		}
		if (mref->ref_skip_sync)
			atomic_inc(&input->total_skip_sync_count);

		GENERIC_INPUT_CALL(input, mref_io, mref);
		GENERIC_INPUT_CALL(input, mref_put, mref);
	}
#ifdef IO_DEBUGGING
	{
		struct if_brick *brick = input->brick;
		char *txt = brick->ops->brick_statistics(brick, false);
		MARS_IO("%s", txt);
		brick_string_free(txt);
	}
#endif
}

#ifndef BLK_MAX_REQUEST_COUNT
#ifdef USE_TIMER
static
void if_timer(unsigned long data)
{
	MARS_IO("\n");
	_if_unplug((void*)data);
}
#endif
#endif // BLK_MAX_REQUEST_COUNT

/* accept a linux bio, convert to mref and call buf_io() on it.
 */
static
/* see dece16353ef47d8d33f5302bc158072a9d65e26f */
#ifdef BLK_QC_T_NONE
#ifdef NEED_BIO_SPLIT
//      end_remove_this
blk_qc_t _if_make_request(struct request_queue *q, struct bio *bio)
//      remove_this
#else
blk_qc_t if_make_request(struct request_queue *q, struct bio *bio)
#endif
#elif defined(BIO_CPU_AFFINE)
int if_make_request(struct request_queue *q, struct bio *bio)
#else
#ifdef NEED_BIO_SPLIT
void _if_make_request(struct request_queue *q, struct bio *bio)
#else
void if_make_request(struct request_queue *q, struct bio *bio)
#endif
#endif
{
	struct if_input *input = q->queuedata;
	struct if_brick *brick = input->brick;

	/* Original flags of the source bio
	 */
	const int  rw      = bio_data_dir(bio);
	const int  sectors = bio_sectors(bio);
// adapt to different kernel versions (TBD: improve)
#if defined(BIO_RW_RQ_MASK) || defined(BIO_FLUSH)
	const bool ahead   = bio_rw_flagged(bio, BIO_RW_AHEAD) && rw == READ;
	const bool barrier = bio_rw_flagged(bio, BIO_RW_BARRIER);
	const bool syncio  = bio_rw_flagged(bio, BIO_RW_SYNCIO);
	const bool unplug  = bio_rw_flagged(bio, BIO_RW_UNPLUG);
	const bool meta    = bio_rw_flagged(bio, BIO_RW_META);
	const bool discard = bio_rw_flagged(bio, BIO_RW_DISCARD);
	const bool noidle  = bio_rw_flagged(bio, BIO_RW_NOIDLE);
#elif defined(REQ_FLUSH) && defined(REQ_SYNC)
#define _flagged(x) (bio->bi_rw & (x))
	const bool ahead   = _flagged(REQ_RAHEAD) && rw == READ;
	const bool barrier = _flagged(REQ_FLUSH);
	const bool syncio  = _flagged(REQ_SYNC);
	const bool unplug  = false;
	const bool meta    = _flagged(REQ_META);
	const bool discard = _flagged(REQ_DISCARD);
	const bool noidle  = _flagged(REQ_THROTTLED);
#else
#error Cannot decode the bio flags
#endif
	const int  prio    = bio_prio(bio);

	/* Transform into MARS flags
	 */
	const int  ref_prio =
		(prio == IOPRIO_CLASS_RT || (meta | syncio)) ?
		MARS_PRIO_HIGH :
		(prio == IOPRIO_CLASS_IDLE) ?
		MARS_PRIO_LOW :
		MARS_PRIO_NORMAL;
	const bool do_unplug = ALWAYS_UNPLUG | unplug | noidle;
	const bool do_skip_sync = brick->skip_sync && !(barrier | syncio);

	struct bio_wrapper *biow;
	struct mref_object *mref = NULL;
	struct if_mref_aspect *mref_a;
//      remove_this
#ifdef HAS_BVEC_ITER
//      end_remove_this
	struct bio_vec bvec;
	struct bvec_iter i;
	loff_t pos = ((loff_t)bio->bi_iter.bi_sector) << 9; // TODO: make dynamic
	int total_len = bio->bi_iter.bi_size;
//      remove_this
#else
	struct bio_vec *bvec;
	int i;
	loff_t pos = ((loff_t)bio->bi_sector) << 9; // TODO: make dynamic
	int total_len = bio->bi_size;
#endif
//      end_remove_this
	bool assigned = false;
        int error = -EINVAL;

	bind_to_channel(brick->say_channel, current);

	MARS_IO("bio %p "
		"size = %d "
		"rw = %d "
		"sectors = %d "
		"ahead = %d "
		"barrier = %d "
		"syncio = %d "
		"unplug = %d "
		"meta = %d "
		"discard = %d "
		"noidle = %d "
		"prio = %d "
		"pos = %lldd "
		"total_len = %d\n",
		bio,
		bio->bi_size,
		rw,
		sectors,
		ahead,
		barrier,
		syncio,
		unplug,
		meta,
		discard,
		noidle,
		prio,
		pos,
		total_len);

	might_sleep();

	if (unlikely(!sectors)) {
		_if_unplug(input);
		/* THINK: usually this happens only at write barriers.
		 * We have no "barrier" operation in MARS, since
		 * callback semantics should always denote
		 * "writethrough accomplished".
		 * In case of exceptional semantics, we need to do
		 * something here. For now, we do just nothing.
		 */
//      remove_this
#ifdef HAS_BI_ERROR
//      end_remove_this
		error = 0;
		bio->bi_error = error;
		bio_endio(bio);
//      remove_this
#else
		bio_endio(bio, error);
#endif
//      end_remove_this
		goto done;
	}

	// throttling of too big write requests
	if (rw && if_throttle_start_size > 0) {
		int kb = (total_len + 512) / 1024;
		if (kb >= if_throttle_start_size)
			mars_limit_sleep(&if_throttle, kb);
	}

#ifdef DENY_READA // provisinary -- we should introduce an equivalent of READA also to the MARS infrastructure
	if (ahead) {
		atomic_inc(&input->total_reada_count);
//      remove_this
#ifdef HAS_BI_ERROR
//      end_remove_this
		bio->bi_error = -EWOULDBLOCK;
		bio_endio(bio);
//      remove_this
#else
		bio_endio(bio, -EWOULDBLOCK);
#endif
//      end_remove_this
		error = 0;
		goto done;
	}
#else
	(void)ahead; // shut up gcc
#endif
	if (unlikely(discard)) { // NYI
		error = 0;
//      remove_this
#ifdef HAS_BI_ERROR
//      end_remove_this
		bio->bi_error = error;
		bio_endio(bio);
//      remove_this
#else
		bio_endio(bio, error);
#endif
//      end_remove_this
		goto done;
	}

	biow = brick_mem_alloc(sizeof(struct bio_wrapper));
	CHECK_PTR(biow, err);
	biow->bio = bio;
	atomic_set(&biow->bi_comp_cnt, 0);

	if (rw) {
		atomic_inc(&input->total_write_count);
	} else {
		atomic_inc(&input->total_read_count);
	}

	_if_start_io_acct(input, biow);

	/* Get a reference to the bio.
	 * Will be released after bio_endio().
	 */
	bio_get(bio);

	/* FIXME: THIS IS PROVISIONARY (use event instead)
	 */
	while (unlikely(!brick->power.led_on)) {
		brick_msleep(100);
	}

	down(&input->kick_sem);

	bio_for_each_segment(bvec, bio, i) {
//      remove_this
#ifdef HAS_BVEC_ITER
//      end_remove_this
		struct page *page = bvec.bv_page;
		int bv_len = bvec.bv_len;
		int offset = bvec.bv_offset;
//      remove_this
#else
		struct page *page = bvec->bv_page;
		int bv_len = bvec->bv_len;
		int offset = bvec->bv_offset;
#endif
//      end_remove_this
		void *data;

#ifdef ARCH_HAS_KMAP
#error FIXME: the current infrastructure cannot deal with HIGHMEM / kmap()
#endif
		data = page_address(page);
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
			traced_lock(&input->hash_table[hash_index].hash_lock, flags);
			for (tmp = input->hash_table[hash_index].hash_anchor.next; tmp != &input->hash_table[hash_index].hash_anchor; tmp = tmp->next) {
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
				if (!do_skip_sync) {
					mref->ref_skip_sync = false;
				}

				for (i = 0; i < mref_a->bio_count; i++) {
					if (mref_a->orig_biow[i]->bio == bio) {
						goto unlock;
					}
				}

				CHECK_ATOMIC(&biow->bi_comp_cnt, 0);
				atomic_inc(&biow->bi_comp_cnt);
				mref_a->orig_biow[mref_a->bio_count++] = biow;
				assigned = true;
				goto unlock;
			} // foreach hash collision list member

		unlock:
			traced_unlock(&input->hash_table[hash_index].hash_lock, flags);
#endif
			if (!mref) {
				int prefetch_len;
				error = -ENOMEM;
				mref = if_alloc_mref(brick);
				if (unlikely(!mref)) {
					up(&input->kick_sem);
					goto err;
				}
				mref_a = if_mref_get_aspect(brick, mref);
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
				if (pos + prefetch_len > brick->dev_size) {
					prefetch_len = brick->dev_size - pos;
				}
				if (prefetch_len < bv_len) {
					prefetch_len = bv_len;
				}
#else
				prefetch_len = bv_len;
#endif

				SETUP_CALLBACK(mref, if_endio, mref_a);

				mref_a->input = input;
				mref->ref_rw = mref->ref_may_write = rw;
				mref->ref_pos = pos;
				mref->ref_len = prefetch_len;
				mref->ref_data = data; // direct IO
				mref->ref_prio = ref_prio;
				mref_a->orig_page = page;

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

				CHECK_ATOMIC(&biow->bi_comp_cnt, 0);
				atomic_inc(&biow->bi_comp_cnt);
				mref_a->orig_biow[0] = biow;
				mref_a->bio_count = 1;
				assigned = true;

				/* When a bio with multiple biovecs is split into
				 * multiple mrefs, only the last one should be
				 * working in synchronous writethrough mode.
				 */
				mref->ref_skip_sync = true;
//      remove_this
#ifdef HAS_BVEC_ITER
//      end_remove_this
				if (!do_skip_sync && i.bi_idx + 1 >= bio->bi_iter.bi_idx) {
					mref->ref_skip_sync = false;
				}
//      remove_this
#else
				if (!do_skip_sync && i + 1 >= bio->bi_vcnt) {
					mref->ref_skip_sync = false;
				}
#endif
//      end_remove_this

				atomic_inc(&input->plugged_count);

				mref_a->hash_index = hash_index;
				traced_lock(&input->hash_table[hash_index].hash_lock, flags);
				list_add_tail(&mref_a->hash_head, &input->hash_table[hash_index].hash_anchor);
				traced_unlock(&input->hash_table[hash_index].hash_lock, flags);

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

#ifdef IO_DEBUGGING
	{
		char *txt = brick->ops->brick_statistics(brick, false);
		MARS_IO("%s", txt);
		brick_string_free(txt);
	}
#endif

	if (error < 0) {
		MARS_ERR("cannot submit request from bio, status=%d\n", error);
		if (!assigned) {
//      remove_this
#ifdef HAS_BI_ERROR
//      end_remove_this
			bio->bi_error = error;
			bio_endio(bio);
//      remove_this
#else
			bio_endio(bio, error);
#endif
//      end_remove_this
		}
	}

	if (do_unplug ||
	   (brick && brick->max_plugged > 0 && atomic_read(&input->plugged_count) > brick->max_plugged)) {
		_if_unplug(input);
	}
#ifdef USE_TIMER
	else {
		unsigned long flags;
		traced_lock(&input->req_lock, flags);
		if (timer_pending(&input->timer)) {
			del_timer(&input->timer);
		}
		input->timer.function = if_timer;
		input->timer.data = (unsigned long)input;
		input->timer.expires = jiffies + USE_TIMER;
		add_timer(&input->timer);
		traced_unlock(&input->req_lock, flags);
	}
#endif

done:
	remove_binding_from(brick->say_channel, current);

//      remove_this
/* see dece16353ef47d8d33f5302bc158072a9d65e26f */
#ifdef BLK_QC_T_NONE
//      end_remove_this
	return BLK_QC_T_NONE;
//      remove_this
#elif defined(BIO_CPU_AFFINE)
	return error;
#else
	return;
#endif
}

#ifdef NEED_BIO_SPLIT
static
#ifdef BLK_QC_T_NONE
blk_qc_t if_make_request(struct request_queue *q, struct bio *bio)
#else
void if_make_request(struct request_queue *q, struct bio *bio)
#endif
{
	blk_queue_split(q, &bio, q->bio_split);
#ifdef BLK_QC_T_NONE
	return _if_make_request(q, bio);
#else
	_if_make_request(q, bio);
#endif
}

#endif

#ifndef BLK_MAX_REQUEST_COUNT
//static
void if_unplug(struct request_queue *q)
{
	struct if_input *input = q->queuedata;
	int was_plugged = 1;
#if 1
	spin_lock_irq(q->queue_lock);
	was_plugged = blk_remove_plug(q);
	spin_unlock_irq(q->queue_lock);
#else
	queue_flag_clear_unlocked(QUEUE_FLAG_PLUGGED, q);
#endif

	was_plugged += atomic_read(&input->plugged_count);

	MARS_IO("block layer called UNPLUG was_plugged = %d\n", was_plugged);
	if (ALWAYS_UNPLUG_FROM_EXTERNAL || was_plugged) {
		_if_unplug(input);
	}
}
#endif

//static
int mars_congested(void *data, int bdi_bits)
{
	struct if_input *input = data;
	int ret = 0;

#ifdef WB_STAT_BATCH /* changed by 4452226ea276e74fc3e252c88d9bb7e8f8e44bf0 */
	if (bdi_bits & (1 << WB_sync_congested) &&
	    atomic_read(&input->read_flying_count) > 0) {
		ret |= (1 << WB_sync_congested);
	}
	if (bdi_bits & (1 << WB_async_congested) &&
	    atomic_read(&input->write_flying_count) > 0) {
		ret |= (1 << WB_async_congested);
	}
#else /* old code */
	if (bdi_bits & (1 << BDI_sync_congested) &&
	    atomic_read(&input->read_flying_count) > 0) {
		ret |= (1 << BDI_sync_congested);
	}
	if (bdi_bits & (1 << BDI_async_congested) &&
	    atomic_read(&input->write_flying_count) > 0) {
		ret |= (1 << BDI_async_congested);
	}
#endif
	return ret;
}

//      remove_this
#ifdef HAS_MERGE_BVEC
static
int mars_merge_bvec(struct request_queue *q, struct bvec_merge_data *bvm, struct bio_vec *bvec)
{
	unsigned int bio_size = bvm->bi_size;
	if (!bio_size) {
		return bvec->bv_len;
	}
	return 128;
}
#endif

//      end_remove_this
static
loff_t if_get_capacity(struct if_brick *brick)
{
	/* Don't read always, read only when unknown.
	 * brick->dev_size may be different from underlying sizes,
	 * e.g. when the size symlink indicates a logically smaller
	 * device than physically.
	 */
	if (brick->dev_size <= 0) {
		struct mars_info info = {};
		struct if_input *input = brick->inputs[0];
		int status;

		status = GENERIC_INPUT_CALL(input, mars_get_info, &info);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot get device info, status=%d\n", status);
			return 0;
		}
		MARS_INF("determined default capacity: %lld bytes\n", info.current_size);
		brick->dev_size = info.current_size;
	}
	return brick->dev_size;
}

static
void if_set_capacity(struct if_input *input, loff_t capacity)
{
	CHECK_PTR(input->disk, done);
	CHECK_PTR(input->disk->disk_name, done);
	MARS_INF("new capacity of '%s': %lld bytes\n", input->disk->disk_name, capacity);
	input->capacity = capacity;
	set_capacity(input->disk, capacity >> 9);
	if (likely(input->bdev && input->bdev->bd_inode)) {
		i_size_write(input->bdev->bd_inode, capacity);
	}
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

	// brick is in operation
	if (brick->power.button && brick->power.led_on) {
		loff_t capacity;
		capacity = if_get_capacity(brick);
		if (capacity > 0 && capacity != input->capacity) {
			MARS_INF("changing capacity from %lld to %lld\n", (long long)input->capacity, (long long)capacity);
			if_set_capacity(input, capacity);
		}
	}

	// brick should be switched on
	if (brick->power.button && brick->power.led_off) {
		loff_t capacity;

		mars_power_led_off((void*)brick,  false);
		brick->say_channel = get_binding(current);

		status = -ENOMEM;
		q = blk_alloc_queue(GFP_MARS);
		if (!q) {
			MARS_ERR("cannot allocate device request queue\n");
			goto is_down;
		}
		q->queuedata = input;
		input->q = q;
		
		disk = alloc_disk(1);
		if (!disk) {
			MARS_ERR("cannot allocate gendisk\n");
			goto is_down;
		}

		minor = device_minor++; //TODO: protect against races (e.g. atomic_t)
		set_disk_ro(disk, true);

		disk->queue = q;
		disk->major = MARS_MAJOR; //TODO: make this dynamic for >256 devices
		disk->first_minor = minor;
		disk->fops = &if_blkdev_ops;
		snprintf(disk->disk_name, sizeof(disk->disk_name),  "mars/%s", brick->brick_name);
		disk->private_data = input;
		input->disk = disk;
		capacity = if_get_capacity(brick);
		MARS_DBG("created device name %s, capacity=%lld\n", disk->disk_name, capacity);
		if_set_capacity(input, capacity);
		
		blk_queue_make_request(q, if_make_request);
#ifdef USE_MAX_SECTORS
#ifdef MAX_SEGMENT_SIZE
		MARS_DBG("blk_queue_max_sectors()\n");
		blk_queue_max_sectors(q, USE_MAX_SECTORS);
#else
		MARS_DBG("blk_queue_max_hw_sectors()\n");
		blk_queue_max_hw_sectors(q, USE_MAX_SECTORS);
#endif
#endif
#ifdef USE_MAX_PHYS_SEGMENTS
#ifdef MAX_SEGMENT_SIZE
		MARS_DBG("blk_queue_max_phys_segments()\n");
		blk_queue_max_phys_segments(q, USE_MAX_PHYS_SEGMENTS);
#else
		MARS_DBG("blk_queue_max_segments()\n");
		blk_queue_max_segments(q, USE_MAX_PHYS_SEGMENTS);
#endif
#endif
#ifdef USE_MAX_HW_SEGMENTS
		MARS_DBG("blk_queue_max_hw_segments()\n");
		blk_queue_max_hw_segments(q, USE_MAX_HW_SEGMENTS);
#endif
#ifdef USE_MAX_SEGMENT_SIZE
		MARS_DBG("blk_queue_max_segment_size()\n");
		blk_queue_max_segment_size(q, USE_MAX_SEGMENT_SIZE);
#endif
#ifdef USE_LOGICAL_BLOCK_SIZE
		MARS_DBG("blk_queue_logical_block_size()\n");
		blk_queue_logical_block_size(q, USE_LOGICAL_BLOCK_SIZE);
#endif
#ifdef USE_SEGMENT_BOUNDARY
		MARS_DBG("blk_queue_segment_boundary()\n");
		blk_queue_segment_boundary(q, USE_SEGMENT_BOUNDARY);
#endif
#ifdef QUEUE_ORDERED_DRAIN
		MARS_DBG("blk_queue_ordered()\n");
		blk_queue_ordered(q, QUEUE_ORDERED_DRAIN, NULL);
#endif
		MARS_DBG("blk_queue_bounce_limit()\n");
		blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
#ifndef BLK_MAX_REQUEST_COUNT
		MARS_DBG("unplug_fn\n");
		q->unplug_fn = if_unplug;
#endif
		MARS_DBG("queue_lock\n");
		q->queue_lock = &input->req_lock; // needed!
		
		input->bdev = bdget(MKDEV(disk->major, minor));
		/* we have no partitions. we contain only ourselves. */
		input->bdev->bd_contains = input->bdev;

#ifdef MODIFY_READAHEAD
		MARS_INF("ra_pages OLD = %lu NEW = %d\n", q->backing_dev_info.ra_pages, brick->readahead);
		q->backing_dev_info.ra_pages = brick->readahead;
#endif
#ifdef USE_CONGESTED_FN
		MARS_DBG("congested_fn\n");
		q->backing_dev_info.congested_fn = mars_congested;
		q->backing_dev_info.congested_data = input;
#endif
//      remove_this
#ifdef HAS_MERGE_BVEC
		MARS_DBG("blk_queue_merge_bvec()\n");
		blk_queue_merge_bvec(q, mars_merge_bvec);
#endif

//      end_remove_this
		// point of no return
		MARS_DBG("add_disk()\n");
		add_disk(disk);
#if 1
		set_disk_ro(disk, false);
#else
		set_device_ro(input->bdev, 0); // TODO: implement modes
#endif

		// report success
		mars_power_led_on((void*)brick, true);
		status = 0;
	}

	// brick should be switched off
	if (!brick->power.button && !brick->power.led_off) {
		int opened;
		int plugged;
		int flying;

		mars_power_led_on((void*)brick, false);
		disk = input->disk;
		if (!disk)
			goto is_down;

		opened = atomic_read(&brick->open_count);
		if (unlikely(opened > 0)) {
			MARS_INF("device '%s' is open %d times, cannot shutdown\n", disk->disk_name, opened);
			status = -EBUSY;
			goto done; // don't indicate "off" status
		}
		plugged = atomic_read(&input->plugged_count);
		if (unlikely(plugged > 0)) {
			MARS_INF("device '%s' has %d plugged requests, cannot shutdown\n", disk->disk_name, plugged);
			status = -EBUSY;
			goto done; // don't indicate "off" status
		}
		flying = atomic_read(&input->flying_count);
		if (unlikely(flying > 0)) {
			MARS_INF("device '%s' has %d flying requests, cannot shutdown\n", disk->disk_name, flying);
			status = -EBUSY;
			goto done; // don't indicate "off" status
		}
		MARS_DBG("calling del_gendisk()\n");
		del_gendisk(input->disk);
		/* There might be subtle races */
		while (atomic_read(&input->flying_count) > 0) {
			MARS_WRN("device '%s' unexpectedly has %d flying requests\n", disk->disk_name, flying);
			brick_msleep(1000);
		}
		if (input->bdev) {
			MARS_DBG("calling bdput()\n");
			bdput(input->bdev);
			input->bdev = NULL;
		}
		MARS_DBG("calling put_disk()\n");
		put_disk(input->disk);
		input->disk = NULL;
		q = input->q;
		if (q) {
			blk_cleanup_queue(q);
			input->q = NULL;
		}
		status = 0;
	is_down:
		mars_power_led_off((void*)brick, true);
	}

done:
	up(&brick->switch_sem);
	return status;
}

//////////////// interface to the outer world (kernel) ///////////////

static int if_open(struct block_device *bdev, fmode_t mode)
{
	struct if_input *input;
	struct if_brick *brick;

	if (unlikely(!bdev || !bdev->bd_disk)) {
		MARS_ERR("----------------------- INVAL ------------------------------\n");
		return -EINVAL;
	}

	input = bdev->bd_disk->private_data;

	if (unlikely(!input || !input->brick)) {
		MARS_ERR("----------------------- BAD IF SETUP ------------------------------\n");
		return -EINVAL;
	}
	brick = input->brick;

	down(&brick->switch_sem);

	if (unlikely(!brick->power.led_on)) {
		MARS_INF("----------------------- BUSY %d ------------------------------\n", atomic_read(&brick->open_count));
		up(&brick->switch_sem);
		return -EBUSY;
	}

	atomic_inc(&brick->open_count);

	MARS_INF("----------------------- OPEN %d ------------------------------\n", atomic_read(&brick->open_count));

	up(&brick->switch_sem);
	return 0;
}

static
//      remove_this
#ifdef HAS_VOID_RELEASE
//      end_remove_this
void
//      remove_this
#else
int
#endif
//      end_remove_this
if_release(struct gendisk *gd, fmode_t mode)
{
	struct if_input *input = gd->private_data;
	struct if_brick *brick = input->brick;
	int nr;

	MARS_INF("----------------------- CLOSE %d ------------------------------\n", atomic_read(&brick->open_count));

	if (atomic_dec_and_test(&brick->open_count)) {
		while ((nr = atomic_read(&input->flying_count)) > 0) {
			MARS_INF("%d IO requests not yet completed\n", nr);
			brick_msleep(1000);
		}

		MARS_DBG("status button=%d led_on=%d led_off=%d\n", brick->power.button, brick->power.led_on, brick->power.led_off);
		mars_trigger();
	}
//      remove_this
#ifndef HAS_VOID_RELEASE
	return 0;
#endif
//      end_remove_this
}

static const struct block_device_operations if_blkdev_ops = {
	.owner =   THIS_MODULE,
	.open =    if_open,
	.release = if_release,

};

//////////////// informational / statistics ///////////////

static
char *if_statistics(struct if_brick *brick, int verbose)
{
	struct if_input *input = brick->inputs[0];
	char *res = brick_string_alloc(512);
	int tmp0 = atomic_read(&input->total_reada_count); 
	int tmp1 = atomic_read(&input->total_read_count); 
	int tmp2 = atomic_read(&input->total_mref_read_count);
	int tmp3 = atomic_read(&input->total_write_count); 
	int tmp4 = atomic_read(&input->total_mref_write_count);

	if (!res)
		return NULL;
	snprintf(res, 512,
		 "total reada = %d "
		 "reads = %d "
		 "mref_reads = %d (%d%%) "
		 "writes = %d "
		 "mref_writes = %d (%d%%) "
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
	atomic_set(&input->total_mref_read_count, 0);
	atomic_set(&input->total_mref_write_count, 0);
}

////////////////// own brick / input / output operations //////////////////

// none

//////////////// object / aspect constructors / destructors ///////////////

static int if_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct if_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->plug_head);
	INIT_LIST_HEAD(&ini->hash_head);
	return 0;
}

static void if_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct if_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->plug_head);
	CHECK_HEAD_EMPTY(&ini->hash_head);
}

MARS_MAKE_STATICS(if);

//////////////////////// constructors / destructors ////////////////////////

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
	if (unlikely(!input->hash_table)) {
		MARS_ERR("cannot allocate hash table\n");
		return -ENOMEM;
	}
	for (i = 0; i < IF_HASH_MAX; i++) {
		spin_lock_init(&input->hash_table[i].hash_lock);
		INIT_LIST_HEAD(&input->hash_table[i].hash_anchor);
	}
	INIT_LIST_HEAD(&input->plug_anchor);
	sema_init(&input->kick_sem, 1);
	spin_lock_init(&input->req_lock);
	atomic_set(&input->flying_count, 0);
	atomic_set(&input->read_flying_count, 0);
	atomic_set(&input->write_flying_count, 0);
	atomic_set(&input->plugged_count, 0);
#ifdef USE_TIMER
	init_timer(&input->timer);
#endif
	return 0;
}

static int if_input_destruct(struct if_input *input)
{
	int i;
	for (i = 0; i < IF_HASH_MAX; i++) {
		CHECK_HEAD_EMPTY(&input->hash_table[i].hash_anchor);
	}
	CHECK_HEAD_EMPTY(&input->plug_anchor);
	brick_block_free(input->hash_table, PAGE_SIZE);
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
EXPORT_SYMBOL_GPL(if_brick_type);

////////////////// module init stuff /////////////////////////

void exit_mars_if(void)
{
	int status;
	MARS_INF("exit_if()\n");
	status = if_unregister_brick_type();
	unregister_blkdev(MARS_MAJOR, "mars");
}

int __init init_mars_if(void)
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
	exit_mars_if();
	return status;
}
