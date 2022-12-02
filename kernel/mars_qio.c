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


/* Qio brick = adaptor between the MARS brick intrastructure
 * and the Linux-internal kernel interfaces.
 *
 * The low-level part is in lib_qio_*.[ch]
 *
 * Uses Queued IO, replacing the historic aio brick type.
 * Now everything lives in kernel space, avoiding __user pointers.
 *
 * MARS needs non-aligned IO supporting byte addresses in
 * persistent /mars. Just working on page offsets is not sufficient,
 * due to strategic reasons which are off topic here.
 *
 * Via iterators, we are rather close on top of the page cache.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "brick_wait.h"
#include "mars.h"

#ifdef ENABLE_MARS_QIO

/* ///////////////////////// own type definitions //////////////////////// */

#include "mars_qio.h"

/* ///////////////////// thresholds and timing reports //////////////////// */

/*  0 = infinite
 * >0 = expire hanging requests after seconds.
 */
int mars_qio_hang_timeout_s = 30;

/* 0 = expire requests individually, each by each.
 *     certain hardward may create holes due to this.
 * 1 = try to workaround hardware problems (e.g. holes), but no guarantee.
 *     ask the hardware vendor.
 */
int mars_qio_workaround_hw_problems = 0;

/* We only need the threshold checks for overall IO latency.
 * This is useful for
 * (a) monitoring of any hardware problems,
 *     or overloads by queueing, etc.
 *     A simple use case is very slow (old) hardware, but
 *     some people believe that it could work miracles.
 *     Here is an information source, e.g. for sysadmin
 *     reports to the management.
 * (b) global banning, protecting against _mass overload_
 *     caused by too many IO requests fired onto
 *     /dev/mars/$too_many_resources or similarly.
 *     Typically, this happens on _unplanned_ DDOS attacks,
 *     and some other horror scenarios.
 *     All I can do is giving you some hints, and the rest
 *     needs to be done by senior sysadmins.
 *
 * Separate latency checks for the submission path could be added,
 * but left for now.
 *
 * Anyone misconfiguring a low-level latency (e.g. via
 * nr_requests parameters and/or some IO scheduler properties)
 * will have to check any effects on her own.
 */
struct threshold qio_io_threshold[2] = {
	[0] = {
		.thr_ban = &mars_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = QIO_IO_R_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
	[1] = {
		.thr_ban = &mars_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = QIO_IO_W_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
};

#define MAX_REQUEUE 32

#define QIO_MAX_JIFFIES 2

/* ///////////////////// lowlevel interface to kernel //////////////////// */

/* Intended for long-term maintenace, e.g. adaptations to
 * better locking methods etc.
 */
static inline
void qio_lock(struct qio_anchors *anch)
{
	mutex_lock(&anch->prio_mutex);
}

static inline
void qio_unlock(struct qio_anchors *anch)
{
	mutex_unlock(&anch->prio_mutex);
}

static inline
void _enqueue_mref_a(struct qio_anchors *anch,
		     struct qio_mref_aspect *mref_a)
{
	qio_lock(anch);
	list_del(&mref_a->io_head);
	list_add_tail(&mref_a->io_head, &anch->submitted_list);
	qio_unlock(anch);
}

static inline
struct qio_mref_aspect *_dequeue_mref_a(struct qio_anchors *anch)
{
	struct qio_mref_aspect *mref_a = NULL;

	qio_lock(anch);
	if (!list_empty(&anch->submitted_list)) {
		struct list_head *tmp = anch->submitted_list.next;

		list_del_init(tmp);
		mref_a = container_of(tmp, struct qio_mref_aspect, io_head);
	}
	qio_unlock(anch);

	return mref_a;
}

static inline
void _check_mref_a(struct qio_anchors *anch,
		    struct qio_mref_aspect *mref_a,
		    int err)
{
	qio_lock(anch);
	if (unlikely(READ_ONCE(mref_a->has_expired))) {
		MARS_DBG("QIO %p had expired, err=%d\n",
			 mref_a, err);
	} else if (unlikely(!list_empty(&mref_a->io_head))) {
		list_del_init(&mref_a->io_head);
	}
	qio_unlock(anch);
}


static
int __qio_wait_for_kernel(struct qio_brick *brick, struct qio_mref_aspect *mref_a)
{
	struct file *file = brick->file;
	struct qio_anchors *anch = mref_a->anch;
	int err;

	err =
		(qio_rw_operations.qio_rw_wait)(file,
						mref_a->is_write,
						mref_a->use_nowait,
						&mref_a->qio_rw);

	_check_mref_a(anch, mref_a, err);

	return err;
}

static
int __qio_submit_to_kernel(struct qio_brick *brick,
			   struct qio_mref_aspect *mref_a,
			   bool nowait)
{
	struct mref_object *mref = mref_a->object;
	struct file *file = brick->file;
	bool is_write;
	int status = -EBADR;

#ifdef CONFIG_MARS_DEBUG
	CHECK_PTR(brick, done);
	CHECK_PTR(mref_a, done);
	CHECK_PTR(mref, done);
	CHECK_PTR(mref->ref_data, done);
	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("invalid ref_len=%d at ref_pos=%lld is_active=%d is_write=%d\n",
			 mref->ref_len, mref->ref_pos,
			 READ_ONCE(mref_a->is_active),
			 READ_ONCE(mref_a->is_write));
	}
#endif

	if (unlikely(READ_ONCE(mref_a->is_active))) {
		status = -EINVAL;
		goto done;
	}
	is_write = mref_a->is_write;
	WRITE_ONCE(mref_a->is_active, true);
	if (is_write) {
		status =
			(qio_rw_operations.qio_write_start)(
				file,
				mref->ref_data,
				mref->ref_len,
				&mref->ref_pos,
				&mref_a->qio_rw,
				!nowait);
	} else {
		status =
			(qio_rw_operations.qio_read_start)(
				file,
				mref->ref_data,
				mref->ref_len,
				&mref->ref_pos,
				&mref_a->qio_rw,
				nowait);
	}
 done:
	return status;
}

/* ///////////////////////// own helper functions //////////////////////// */

static
loff_t get_total_size(struct qio_brick *brick)
{
	loff_t known_pos;

	if (unlikely(!brick->mf))
		return 0;

	/* Workaround for races in the page cache.
	 * It appears that concurrent reads and writes seem to
	 * result in inconsistent reads in some very rare cases, due to
	 * races. Sometimes, the inode claims that the file has been already
	 * appended by a write operation, but the data has not actually hit
	 * the page cache, such that a concurrent read gets NULL blocks.
	 * AFAICS this type of race is not avoidable, whatever I try to do.
	 * It looks like a dilemma or trilemma.
	 * The i_size update cannot be fully atomic with respect to
	 * the semantics of the underlying disk / hardware behaviour.
	 * MARS tries to do its best for compensation of power outages
	 * ocurring at any imaginable point in time.
	 * However, I cannot work miracles. I just try to give my best.
	 */
	known_pos = mf_dirty_length(brick->mf, DIRTY_COMPLETING);
	return known_pos;
}

static
void cross_eof(struct qio_brick *brick,
	       struct qio_mref_aspect *mref_a,
	       struct mref_object *mref)
{
	int ref_len;
	loff_t end_pos;
	loff_t eof_pos;
	loff_t usable_len;

	ref_len = mref->ref_len;
	if (unlikely(ref_len <= 0)) {
		/* Nothing to do here */
		return;
	}
	end_pos = mref->ref_pos + (loff_t)ref_len;
	/* Re-get current size
	 */
	eof_pos = get_total_size(brick);
	mref->ref_total_size = eof_pos;

	if (end_pos <= eof_pos)
		return;

	/* Shorten reads crossing EOF,
	 * but not when starting exactly at EOF
	 * for pipe-like semantics.
	 */
	usable_len = eof_pos - mref->ref_pos;
	if (usable_len > 0 && usable_len < INT_MAX && mref->ref_len > usable_len)
		mref->ref_len = usable_len;
}

static
int _qio_ref_get(struct qio_brick *brick, struct qio_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	loff_t total_size;
	int len;
	bool may_write;

	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("bad ref_len=%d\n", mref->ref_len);
		return -EILSEQ;
	}
	if (unlikely(!brick->mf))
		return -ENOENT;

	total_size = get_total_size(brick);
	if (unlikely(total_size < 0)) {
		return total_size;
	}
	mref->ref_total_size = total_size;

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	/* Check for reads crossing the EOF boundary (special case)
	 */
	may_write = (mref->ref_flags & (MREF_WRITE | MREF_MAY_WRITE)) != 0;
	if (!may_write) {
		cross_eof(brick, mref_a, mref);
		if (unlikely(mref->ref_len <= 0)) {
			/* Exactly on EOF */
			return 0;
		}
	}

	/* Buffered IO.
	 */
	len = mref->ref_len;
	if (!mref->ref_data) {
		mref_a->alloc_len = len;
		mref_a->do_dealloc = true;
		mref->ref_data =
			brick_block_alloc(mref->ref_pos, len);
	}

	_mref_get_first(mref);
	return len;
}

static
void _qio_ref_put(struct qio_brick *brick, struct qio_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;

#ifdef CONFIG_MARS_DEBUG
	CHECK_PTR(mref_a, done);
	CHECK_PTR(mref, done);
#endif
	if (!_mref_put(mref))
		goto done;

	if (brick->mf) {
		struct file *file = brick->mf->mf_filp;

#ifdef CONFIG_MARS_DEBUG
		CHECK_PTR(file, done);
#endif
		if (file->f_mapping && file->f_mapping->host) {
			mref->ref_total_size = get_total_size(brick);
		}
	}

	if (mref_a->do_dealloc) {
		brick_block_free(mref->ref_data, mref_a->alloc_len);
		mref->ref_data = NULL;
	}
	qio_free_mref(mref);

 done:
	return;
}

static
void _qio_complete_mref_a(struct qio_brick *brick, struct qio_mref_aspect *mref_a, int err)
{
	struct mref_object *mref;
	struct lamport_time latency;
	long long latency_ns;
	bool was_write;

	mref = mref_a->object;
	CHECK_PTR(mref, fatal);

	if (unlikely(err < 0)) {
		struct lamport_time duration;
		struct qio_anchors *anch;
		bool list_member = false;

		anch = mref_a->anch;
		if (anch) {
			qio_lock(anch);
			if (unlikely(!list_empty(&mref_a->io_head))) {
				list_del_init(&mref_a->io_head);
				list_member = true;
			}
			qio_unlock(anch);
		}
		if (err == -EAGAIN)
			goto no_report;

		duration = lamport_time_sub(mref_a->completion_stamp,
					    mref_a->started_stamp);

		MARS_ERR("QIO error %d memb=%d duration=%lld.%09lu at pos=%lld len=%d (mref=%p ref_data=%p)\n",
			 err, list_member,
			 duration.tv_sec, duration.tv_nsec,
			 mref->ref_pos, mref->ref_len, mref, mref->ref_data);
	} else {
		mref_checksum(mref);
		mref->ref_flags |= MREF_UPTODATE;
	}

 no_report:
#ifdef CONFIG_MARS_DEBUG
	CHECK_PTR_NULL(brick->mf, skip_mf);
#endif
	was_write = mref_a->is_write;
	if (was_write && err >= 0) {
		mf_dirty_append(brick->mf, DIRTY_COMPLETING,
				mref->ref_pos + mref->ref_len);
	}
	mapfree_set(brick->mf,
		    mref->ref_pos,
		    mref->ref_pos + mref->ref_len);
	if (was_write && err >= 0) {
		/* Needs to be done before callback, which might modify
		 * mref->.+
		 */
		mf_dirty_append(brick->mf, DIRTY_FINISHED,
				mref->ref_pos + mref->ref_len);
	}

#ifdef CONFIG_MARS_DEBUG
 skip_mf:
#endif
	latency = lamport_time_sub(mref_a->dequeue_stamp, mref_a->started_stamp);
	latency_ns = lamport_time_to_ns(&latency);
	threshold_check(&qio_io_threshold[was_write], latency_ns);

#ifdef CONFIG_MARS_DEBUG
	brick->complet_pos = mref->ref_pos;
	brick->complet_len = mref->ref_len;
#endif
	if (err < 0)
		brick->error = err;

	CHECKED_CALLBACK(mref, err, callback_err);

 done:
	if (was_write) {
		atomic_dec(&brick->flying_writes);
	} else {
		atomic_dec(&brick->flying_reads);
	}
	_qio_ref_put(brick, mref_a);
	atomic_dec(&mars_global_io_flying);
	return;

 callback_err:
	MARS_ERR("QIO %p callback err=%d\n",
		 brick, err);
	goto done;
fatal:
	MARS_FAT("bad mref pointer %p, giving up...\n",
		 mref);
}

static
bool now_expired(struct qio_mref_aspect *mref_a,
		 struct lamport_time *last_hanging_stamp,
		 struct lamport_time *now)
{
	int touched_s;
	int latency_s;

	if (!mars_qio_hang_timeout_s)
		return false;

	touched_s = mref_a->dequeue_stamp.tv_sec;
	if (!touched_s)
		touched_s = mref_a->started_stamp.tv_sec;

	latency_s =
		last_hanging_stamp->tv_sec - touched_s;
	if (latency_s > mars_qio_hang_timeout_s)
		return true;

	latency_s =
		now->tv_sec - touched_s;
	if (latency_s > mars_qio_hang_timeout_s * 2)
		return true;

	return false;
}

static
void _qio_complete_all_hanging(struct qio_anchors *anch,
			       struct lamport_time *hanging_stamp,
			       int err)
{
	struct lamport_time now;
	struct qio_brick *brick = anch->brick;
	struct list_head *io_list = &anch->submitted_list;
	struct list_head *tmp;

	get_real_lamport(&now);

 restart:
	barrier();
	qio_lock(anch);
	/* Keep the original order, as best as possible */
	tmp = io_list->next;
	while (tmp != io_list) {
		struct list_head *old_tmp;
		struct qio_mref_aspect *mref_a =
			container_of(tmp, struct qio_mref_aspect, io_head);

		/* check whether the request is old enough for failing */
		if (!now_expired(mref_a, hanging_stamp, &now)) {
			/* Not (yet) expired.
			 */
			tmp = tmp->next;
			brick_yield();
			continue;
		}
		/* Now expired.
		 */
		old_tmp = tmp;
		if (mars_qio_workaround_hw_problems == 1) {
			/* Do not give up the lock.
			 * This locks out concurrent submitters.
			 * We are trying to survive, not to win
			 * any benchmarks.
			 * Although this is a CPU burner, we want
			 * to do our best by avoiding inode updates
			 * due to "succesful" callbacks (whether the
			 * physical completion is strict, or maybe
			 * corresponds to whatever).
			 * Advanced sysadmins may not only activate
			 * this workaround only when appropriate, but may
			 * also abort this crude operational emergency via
			 * "echo 0 > /proc/sys/mars/..."
			 */
			tmp = tmp->next;
			list_del_init(old_tmp);
			_qio_complete_mref_a(brick, mref_a, err);
			brick_yield();
			continue;
		}

		/* _We_ have won the race, so any parallel or successive
		 * interrupts (resp callbacks) should not believe
		 * they had won.
		 */
		WRITE_ONCE(mref_a->has_expired, true);
		tmp = tmp->next;
		list_del_init(old_tmp);
		qio_unlock(anch);

		_qio_complete_mref_a(brick, mref_a, err);

		/* Well, repeat with the next candidate.
		 * IMPORTANT: the completion order may be non-ordered
		 * by hardware properties.
		 * We cannot guarantee that no holes may occur.
		 * Sorry, but operationality takes preference here.
		 * You may increase mars_qio_hang_timeout_s to "infinity"
		 * if you dislike the hardware behaviour.
		 */
		brick_yield();
		get_real_lamport(&now);
		goto restart;
	}
	qio_unlock(anch);
}

static
void qio_complete_all_hanging(struct qio_anchors *anch, int err)
{
	struct qio_brick *brick = anch->brick;

	_qio_complete_all_hanging(anch, &brick->last_hanging_stamp, err);
}

static
void _qio_ref_io(struct qio_brick *brick, struct qio_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	struct qio_anchors *anch;
	struct lamport_time now;
	bool is_write;
	int err = -EINVAL;

	get_real_lamport(&now);
	mref_a->started_stamp = now;
	brick->last_started_stamp = now;

	is_write = (mref->ref_flags & MREF_WRITE);
	mref_a->is_write = is_write;
	if (is_write)
		mref_a->use_nowait = true;

	/* statistics */
	atomic_inc(&mars_global_io_flying);
	if (is_write) {
		atomic_inc(&brick->flying_writes);
	} else {
		atomic_inc(&brick->flying_reads);
	}

	if (unlikely(!brick->mf || !brick->mf->mf_filp)) {
		goto fail_fast;
	}

	mapfree_set(brick->mf, mref->ref_pos, -1);

	/* Check for reads crossing the EOF boundary (special case)
	 */
	if (!is_write)
		cross_eof(brick, mref_a, mref);

	/* determine the right queue, depending on read/write */
	anch = &brick->thread_anch[is_write & 1];
	mref_a->anch = anch;

#ifdef CONFIG_MARS_DEBUG
	brick->submit_pos = mref->ref_pos;
	brick->submit_len = mref->ref_len;
#endif

	/* Hopefully, the kernel-side submission path
	 * will be fast.
	 * There might be exceptions, such as delays from
	 * nr_requests and siblings.
	 * TODO: react more sophisticated on suchalike.
	 */
	err = __qio_submit_to_kernel(brick, mref_a, mref_a->use_nowait);
	if (unlikely(err < 0)) {
		/* Delegate to the callback thread:
		 * (a) Do no hinder parallelism of submission
		 *     by a sequential bottleneck.
		 * (b) EGAIN may occur, and it may require
		 *     a wait queue anyway.
		 * (c) prevent resource deadlocks.
		 *     Our QIO queues may grow higher than
		 *     other queues, like TCP window queues, etc.
		 */
		mref_a->qio_error = err;
	}

	/* Submission has succeeded.
	 * Assume that hardware is operational.
	 */
	brick->last_hanging_stamp = now;

	/* Do not expose to worker threads earlier.
	 */
	_enqueue_mref_a(anch, mref_a);

	WRITE_ONCE(anch->should_wake_now, true);
	brick_wake_smp(&anch->event);

 done:
	return;

	/* Not yet enqueued.
	 * Complete directly by reporting the fatal error.
	 * Do not use in masses.
	 */
 fail_fast:
	_qio_complete_mref_a(brick, mref_a, err);
	goto done;
}

/* ////////////////// qio thread thingies ////////////////// */

static inline
bool _qio_thread_should_run(struct qio_anchors *anch,
			    struct qio_brick *brick)
{
	return
		READ_ONCE(anch->should_wake_now) ||
		!READ_ONCE(anch->should_terminate) ||
		atomic_read(&brick->flying_reads) +
		atomic_read(&brick->flying_writes) > 0;
}

static
void check_hanging_requests(struct qio_anchors *anch,
			    struct qio_brick *brick)
{
	int latency_s;

	if (!mars_qio_hang_timeout_s ||
	    !brick->last_completion_stamp.tv_sec)
		return;

	latency_s =
		brick->last_completion_stamp.tv_sec -
		brick->last_started_stamp.tv_sec;
	if (latency_s <= mars_qio_hang_timeout_s)
		return;

	/* check once again, realtime */
	if (!brick->last_hanging_stamp.tv_sec)
		get_real_lamport(&brick->last_hanging_stamp);

	qio_complete_all_hanging(anch, -ETIME);
}

static
int qio_thread(void *private)
{
	struct qio_anchors *anch = private;
	struct qio_brick *brick = anch->brick;
	unsigned long sleep_jiffies = 0;
	unsigned long last_jiffies = 0;

	MARS_DBG("QIO thread %d has started on '%s'\n",
		 anch->anch_prio, brick->brick_path);

	while (_qio_thread_should_run(anch, brick)) {
		struct qio_mref_aspect *mref_a;
		struct mref_object *mref;
		struct lamport_time now;
		int err;

		mref_a = _dequeue_mref_a(anch);
		if (!mref_a) {
			bool got_wake_signal;

			if (!brick->power.button) {
				check_hanging_requests(anch, brick);
			}
			got_wake_signal = false;
			brick_wait_smp(
				anch->event,
				(got_wake_signal = READ_ONCE(anch->should_wake_now)) ||
				!_qio_thread_should_run(anch, brick),
				sleep_jiffies);
			WRITE_ONCE(anch->should_wake_now, false);

			/* Fast path, controlled via flag.
			 * See the lectures from Dijkstra.
			 */
			if (got_wake_signal) {
				cond_resched();
				continue;
			}

			/* The page cache is very fast, in terms of reaction delay.
			 * Our first few slow-path rounds should work as a polling
			 * loop.
			 * After a while, we should pause for at least 1 jiffies,
			 * in order to avoid a CPU burner.
			 * Much more than 1 jiffies might lead to unnecessary delays.
			 * So we try some compromize, as explained by Dijkstra
			 * and his grand sons in spirit.
			 * When in doubt: refer to the Dekker algorithm, and measure
			 * its performance upon massive contention.
			 */
			if (sleep_jiffies < QIO_MAX_JIFFIES) {
				unsigned long now_jiffies = jiffies;

				if (!last_jiffies)
					last_jiffies = now_jiffies;
				else if (now_jiffies > last_jiffies)
					sleep_jiffies++;
				cond_resched();
			}
			continue;
		}
		last_jiffies = jiffies;
		sleep_jiffies = 0;

		get_real_lamport(&now);
		mref_a->dequeue_stamp = now;
#ifdef CONFIG_MARS_DEBUG
		brick->last_dequeue_stamp = now;
#endif

		mref = mref_a->object;
		mapfree_set(brick->mf, mref->ref_pos, -1);

		err = mref_a->qio_error;
		if (err == -EAGAIN &&
		    !READ_ONCE(anch->should_terminate)) {
			/* Re-submit again.
			 * This may happen regularly, since the
			 * page cache requires us to poll,
			 * at least when using wwait for achieving
			 * high IO parallelism.
			 */
			WRITE_ONCE(mref_a->is_active, false);
			mref_a->qio_rw.qio_phase = 0;
			err = __qio_submit_to_kernel(brick, mref_a, false);
			mref_a->qio_error = err;

			/* Polling now over, or should we retry? */
			if (err == -EAGAIN &&
			    mref_a->nr_requeue++ <= MAX_REQUEUE) {
				/* Re-enqueue for a limited number of
				 * rounds.
				 */
				_enqueue_mref_a(anch, mref_a);
				brick_yield();
				continue;
			}
		}
		if (unlikely(err < 0)) {
			/* We need to give up directly.
			 * This one never hit the page cache, AFAIC.
			 */
			goto do_complete;
		}

		err =
			__qio_wait_for_kernel(brick, mref_a);

		get_real_lamport(&now);
		mref_a->completion_stamp = now;
	do_complete:
		brick->last_hanging_stamp = now;

		_qio_complete_mref_a(brick, mref_a, err);
	}

	MARS_DBG("QIO thread %d stopping on '%s'\n",
		 anch->anch_prio, brick->brick_path);

	WRITE_ONCE(anch->has_terminated, true);
	return 0;
}

/* ////////////////// own brick / input / output operations ////////////////// */

static
atomic_t thread_series_nr = ATOMIC_INIT(0);


static
bool qio_switch_on(struct qio_brick *brick)
{
	const char *path = brick->brick_path;
	struct mapfree_info *mf;
	struct file *file;
	int flags = O_RDWR | O_LARGEFILE;
	int i;
	int series_nr;
	char class = 'A';
	bool fully_operational;

	mf = brick->mf;
	if (mf) {
		file = mf->mf_filp;
		if (file)
			goto make_threads;
	}

	if (brick->o_creat) {
		flags |= (O_NOFOLLOW | O_CREAT);
		MARS_DBG("using O_CREAT on %s\n", path);
	}

	brick->error = 0;
	mf = mapfree_get(path, flags, &brick->error);
	if (unlikely(!mf)) {
		MARS_ERR("QIO could not open file='%s' flags=%d error=%d\n",
			 path, flags, brick->error);
		return false;
	}
	file = mf->mf_filp;
	if (unlikely(!file)) {
		MARS_ERR("QIO file='%s' flags=%d invalid filp\n",
			 path, flags);
		mapfree_put(mf);
		return false;
	}
	brick->mf = mf;
	brick->file = file;

	series_nr = atomic_inc_return(&thread_series_nr);
	if (brick->last_submitted_stamp.tv_sec) {
		brick->last_hanging_stamp.tv_sec = 0;
		brick->last_submitted_stamp.tv_sec = 0;
		brick->last_completion_stamp.tv_sec = 0;
	}

 make_threads:
	fully_operational = true;
	for (i = 0; i < 2; i++) {
		struct qio_anchors *anch = &brick->thread_anch[i];

		/* Thread had been already started, and
		 * and may be currently stopping.
		 */
		if (anch->thread)
			brick_wake_smp(&anch->event);

		/* Check for races against old threads.
		 * Switches may change more frequently than any
		 * slowed-down thread.
		 * NB: we try to compensate furious operational
		 * problems as seen by sysadmins (e.g. caused
		 * by semi-defective hardware etc).
		 * Thus we use classical kthreads here, no
		 * sophisticated lowlevel technology.
		 */
		if (READ_ONCE(anch->should_terminate) &&
		    !READ_ONCE(anch->has_terminated)) {
			fully_operational = false;
			/* retry after the old thread has actually terminated */
			continue;
		}
		if (anch->thread)
			continue;
		
		WRITE_ONCE(anch->should_terminate, false);
		WRITE_ONCE(anch->has_terminated, false);
		anch->thread =
			brick_thread_create(qio_thread, anch,
					    "mars_qio%c%d",
					    class + i,
					    series_nr);
		if (unlikely(!anch->thread)) {
			MARS_ERR("cannot create QIO thread %c\n",
				 class + i);
			/* Retry thread creation next time */
			fully_operational = false;
		}
	}
	return fully_operational;
}

static
bool qio_switch_off(struct qio_brick *brick)
{
	struct mapfree_info *mf;
	int nr_flying;
	int nr_running;
	int i;

 retry:
	mb();
	nr_running = 0;
	nr_flying =
		atomic_read(&brick->flying_reads) +
		atomic_read(&brick->flying_writes);
	for (i = 0; i < 2; i++) {
		struct qio_anchors *anch = &brick->thread_anch[i];
		bool is_dirty;

		WRITE_ONCE(anch->should_terminate, true);
		if (!anch->thread)
			continue;
		nr_running++;
		brick_wake_smp(&anch->event);
		if (nr_flying > 0)
			continue;
		qio_lock(anch);
		is_dirty =
			!list_empty(&anch->submitted_list);
		qio_unlock(anch);
		if (is_dirty)
			continue;
		if (!READ_ONCE(anch->has_terminated)) {
			continue;
		}
		brick_thread_stop(anch->thread);
		anch->thread = NULL;
	}
	if (nr_flying > 0) {
		MARS_DBG("QIO %d requests are flying\n",
			 nr_flying);
		/* Not yet fully off */
		brick_yield();
		goto retry;
	}
	if (nr_running) {
		MARS_DBG("QIO threads %d not yet terminated\n",
			 nr_running);
		/* Not yet fully off */
		brick_yield();
		goto retry;
	}
	mf = brick->mf;
	brick->mf = NULL;
	if (mf) {
		MARS_DBG("closing mf=%p filename='%s'\n",
			 mf, mf->mf_name);
		mapfree_put(mf);
	}
	/* New we should be fully off */
	return true;
}

static
int qio_get_info(struct qio_output *output, struct mars_info *info)
{
	struct qio_brick *brick;
	struct file *file;

	if (unlikely(!output))
		return -EINVAL;

	brick = output->brick;
	if (unlikely(!brick ||
		     !brick->file))
		return -EINVAL;
	file = brick->file;
	if (unlikely(!file))
		return -EINVAL;

	if (unlikely(!file->f_mapping ||
		     !file->f_mapping->host))
		return -EINVAL;

	info->tf_align = 1;
	info->tf_min_size = 1;
	info->current_size = get_total_size(brick);

	MARS_DBG("determined file size = %lld\n", info->current_size);
	return 0;
}

static
int qio_ref_get(struct qio_output *output, struct mref_object *mref)
{
	struct qio_brick *brick = output->brick;
	struct qio_mref_aspect *mref_a;
	int res;

	mref_a = qio_mref_get_aspect(brick, mref);
	res = _qio_ref_get(brick, mref_a);
	return res;
}

static
void qio_ref_put(struct qio_output *output, struct mref_object *mref)
{
	struct qio_brick *brick = output->brick;
	struct qio_mref_aspect *mref_a;

	mref_a = qio_mref_get_aspect(brick, mref);
	_qio_ref_put(brick, mref_a);
}

static
void qio_ref_io(struct qio_output *output, struct mref_object *mref)
{
	struct qio_brick *brick = NULL;
	struct qio_mref_aspect *mref_a = NULL;

	CHECK_PTR(output, fatal);
	brick = output->brick;
	CHECK_PTR(brick, fatal);
	CHECK_PTR(mref, fatal);
	CHECK_PTR(mref->ref_data, fatal);

	_mref_check(mref);

	if (unlikely(!brick->power.led_on)) {
		SIMPLE_CALLBACK(mref, -EBADFD);
		return;
	}

	_mref_get(mref);

	mref_a = qio_mref_get_aspect(brick, mref);
	CHECK_PTR(mref_a, fatal);

	_qio_ref_io(brick, mref_a);
	return;

fatal:
	MARS_FAT("bad pointer %p %p %p %p (%p), giving up...\n",
		 output, brick, mref, mref_a,
		 mref ? mref->ref_data : NULL);
}

static
int qio_switch(struct qio_brick *brick)
{
	if (brick->power.button) {
		bool success = false;

		if (brick->power.led_on)
			goto done;
		mars_power_led_off((void *)brick, false);
		/* Intermediate states may happen:
		 * !success means: not yet fully on
		 */
		success = qio_switch_on(brick);
		if (success) {
			mars_power_led_on((void *)brick, true);
		}
	} else {
		bool success = false;
		if (brick->power.led_off)
			goto done;
		mars_power_led_on((void *)brick, false);
		/* Intermediate states may happen:
		 * !success means: not yet fully off
		 */
		success = qio_switch_off(brick);
		if (success) {
			mars_power_led_off((void *)brick, true);
			mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_FROM_REMOTE);
		}
	}
done:
	return 0;
}


/* //////////////// informational / statistics /////////////// */

static
char *qio_statistics(struct qio_brick *brick, int verbose)
{
	char *res = brick_string_alloc(4096);
	if (!res)
		return NULL;

	snprintf(res, 4095,
		 "last started=%lld.%09ld "
		 "submitted=%lld.%09ld "
#ifdef CONFIG_MARS_DEBUG
		 "dequeue=%lld.%09ld "
#endif
		 "completed=%lld.%09ld "
		 "hanging=%lld.%09ld | "
		 "flying reads=%d "
		 "writes=%d | "
#ifdef CONFIG_MARS_DEBUG
		 "submit=%lld+%d "
		 "complet=%lld+%d "
#endif
		 "error=%d\n",
		 brick->last_started_stamp.tv_sec,
		 brick->last_started_stamp.tv_nsec,
		 brick->last_submitted_stamp.tv_sec,
		 brick->last_submitted_stamp.tv_nsec,
#ifdef CONFIG_MARS_DEBUG
		 brick->last_dequeue_stamp.tv_sec,
		 brick->last_dequeue_stamp.tv_nsec,
#endif
		 brick->last_completion_stamp.tv_sec,
		 brick->last_completion_stamp.tv_nsec,
		 brick->last_hanging_stamp.tv_sec,
		 brick->last_hanging_stamp.tv_nsec,
		 atomic_read(&brick->flying_reads),
		 atomic_read(&brick->flying_writes),
#ifdef CONFIG_MARS_DEBUG
		 brick->submit_pos,
		 brick->submit_len,
		 brick->complet_pos,
		 brick->complet_len,
#endif
		 brick->error);

	return res;
}

static
void qio_reset_statistics(struct qio_brick *brick)
{
}

/* //////////////// object / aspect constructors / destructors /////////////// */

static
int qio_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct qio_mref_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->io_head);
	init_qio_rw(&ini->qio_rw);
	return 0;
}

static
void qio_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct qio_mref_aspect *ini = (void *)_ini;

	exit_qio_rw(&ini->qio_rw);
	CHECK_HEAD_EMPTY(&ini->io_head);
}

MARS_MAKE_STATICS(qio);

/* ////////////////////// brick constructors / destructors //////////////////// */

static
int qio_brick_construct(struct qio_brick *brick)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct qio_anchors *anch = &brick->thread_anch[i];

		anch->brick = brick;
		anch->anch_prio = i;
		mutex_init(&anch->prio_mutex);
		INIT_LIST_HEAD(&anch->submitted_list);
		init_waitqueue_head(&anch->event);
	}
	return 0;
}

static
int qio_brick_destruct(struct qio_brick *brick)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct qio_anchors *anch = &brick->thread_anch[i];

		CHECK_HEAD_EMPTY(&anch->submitted_list);
	}
	return 0;
}

static
int qio_output_construct(struct qio_output *output)
{
	return 0;
}

static
int qio_output_destruct(struct qio_output *output)
{
	return 0;
}

/* ///////////////////////// static structs //////////////////////// */

static
struct qio_brick_ops qio_brick_ops = {
	.brick_switch = qio_switch,
	.brick_statistics = qio_statistics,
	.reset_statistics = qio_reset_statistics,
};

static
struct qio_output_ops qio_output_ops = {
	.mars_get_info = qio_get_info,
	.mref_get = qio_ref_get,
	.mref_put = qio_ref_put,
	.mref_io = qio_ref_io,
};

const struct qio_input_type qio_input_type = {
	.type_name = "qio_input",
	.input_size = sizeof(struct qio_input),
};

static
const struct qio_input_type *qio_input_types[] = {
	&qio_input_type,
};

const struct qio_output_type qio_output_type = {
	.type_name = "qio_output",
	.output_size = sizeof(struct qio_output),
	.master_ops = &qio_output_ops,
	.output_construct = &qio_output_construct,
	.output_destruct = &qio_output_destruct,
};

static
const struct qio_output_type *qio_output_types[] = {
	&qio_output_type,
};

const struct qio_brick_type qio_brick_type = {
	.type_name = "qio_brick",
	.brick_size = sizeof(struct qio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &qio_brick_ops,
	.aspect_types = qio_aspect_types,
	.default_input_types = qio_input_types,
	.default_output_types = qio_output_types,
	.brick_construct = &qio_brick_construct,
	.brick_destruct = &qio_brick_destruct,
};
EXPORT_SYMBOL_GPL(qio_brick_type);

#endif /* ENABLE_MARS_QIO */

/* ////////////////// module init stuff ///////////////////////// */

int __init init_mars_qio(void)
{
#ifdef ENABLE_MARS_QIO
	MARS_INF("init_qio()\n");
	_qio_brick_type = (void *)&qio_brick_type;
	return qio_register_brick_type();
#else
	return 0;
#endif
}

void exit_mars_qio(void)
{
#ifdef ENABLE_MARS_QIO
	MARS_INF("exit_qio()\n");
	qio_unregister_brick_type();
#endif
}
