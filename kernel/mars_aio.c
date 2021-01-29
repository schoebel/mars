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


//#define BRICK_DEBUGGING
#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "mars.h"
#include "lib_timing.h"
#include "lib_mapfree.h"

#include "mars_aio.h"

#if !defined(MARS_HAS_PREPATCH_V2) && !defined(MARS_HAS_PREPATCH)
#warning You are compiling without pre-patch, resulting in BAD IO PERFORMANCE
#endif

#define MARS_MAX_AIO      512
#define MARS_MAX_AIO_READ 32

/* Self-tune aio_max_nr when possible.
 * This works only when the pre-patch has
 * EXPORT_SYNBOL_GPL(aio_max_nr) and has
 * defined HAS_AIO_MAX.
*/
#ifdef HAS_AIO_MAX
static DEFINE_MUTEX(aio_max_lock);
int aio_max_nr_current = 0;
int aio_max_nr_max = 0;
#endif

struct timing_stats timings[3] = {};

struct threshold aio_submit_threshold = {
	.thr_ban = &mars_global_ban,
	.thr_parent = &global_io_threshold,
	.thr_limit = AIO_SUBMIT_MAX_LATENCY,
	.thr_factor = 10,
	.thr_plus = 10000,
};
EXPORT_SYMBOL_GPL(aio_submit_threshold);

struct threshold aio_io_threshold[2] = {
	[0] = {
		.thr_ban = &mars_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = AIO_IO_R_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
	[1] = {
		.thr_ban = &mars_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = AIO_IO_W_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
};
EXPORT_SYMBOL_GPL(aio_io_threshold);

struct threshold aio_sync_threshold = {
	.thr_ban = &mars_global_ban,
	.thr_limit = AIO_SYNC_MAX_LATENCY,
	.thr_factor = 100,
	.thr_plus = 0,
};
EXPORT_SYMBOL_GPL(aio_sync_threshold);

int aio_sync_mode = 2;
EXPORT_SYMBOL_GPL(aio_sync_mode);

///////////////////////// own type definitions ////////////////////////

////////////////// some helpers //////////////////

#ifdef ENABLE_MARS_AIO

static inline
void _enqueue(struct aio_threadinfo *tinfo, struct aio_mref_aspect *mref_a, int prio, bool at_end)
{
#if 1
	prio++;
	if (unlikely(prio < 0)) {
		prio = 0;
	} else if (unlikely(prio >= MARS_PRIO_NR)) {
		prio = MARS_PRIO_NR - 1;
	}
#else
	prio = 0;
#endif

	mref_a->enqueue_stamp = cpu_clock(raw_smp_processor_id());

	mutex_lock(&tinfo->mutex);

	if (at_end) {
		list_add_tail(&mref_a->io_head, &tinfo->mref_list[prio]);
	} else {
		list_add(&mref_a->io_head, &tinfo->mref_list[prio]);
	}
	tinfo->queued[prio]++;
	atomic_inc(&tinfo->queued_sum);

	mutex_unlock(&tinfo->mutex);

#ifdef MARS_AIO_DEBUG
	atomic_inc(&tinfo->total_enqueue_count);
#endif

	wake_up_interruptible_all(&tinfo->event);
}

static inline
struct aio_mref_aspect *_dequeue(struct aio_threadinfo *tinfo)
{
	struct aio_mref_aspect *mref_a = NULL;
	int prio;

	mutex_lock(&tinfo->mutex);

	for (prio = 0; prio < MARS_PRIO_NR; prio++) {
		struct list_head *start = &tinfo->mref_list[prio];
		struct list_head *tmp = start->next;
		if (tmp != start) {
			list_del_init(tmp);
			tinfo->queued[prio]--;
			atomic_dec(&tinfo->queued_sum);
			mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
			goto done;
		}
	}

done:
	mutex_unlock(&tinfo->mutex);

	if (likely(mref_a && mref_a->object)) {
		unsigned long long latency;
		int rw = mref_a->object->ref_flags & MREF_WRITE ? 1 : 0;

		latency = cpu_clock(raw_smp_processor_id()) - mref_a->enqueue_stamp;
		threshold_check(&aio_io_threshold[rw], latency);
	}
	return mref_a;
}

////////////////// own brick / input / output operations //////////////////

static
loff_t get_total_size(struct aio_output *output)
{
	/* Workaround for races in the page cache.
	 * It appears that concurrent reads and writes seem to
	 * result in inconsistent reads in some very rare cases, due to
	 * races. Sometimes, the inode claims that the file has been already
	 * appended by a write operation, but the data has not actually hit
	 * the page cache, such that a concurrent read gets NULL blocks.
	 */
	return mf_dirty_length(output->mf, DIRTY_COMPLETED);
}

static int aio_ref_get(struct aio_output *output, struct mref_object *mref)
{
	loff_t total_size;

	if (unlikely(!output->brick->power.led_on))
		return -EBADFD;

	if (unlikely(!output->mf)) {
		MARS_ERR("brick is not switched on\n");
		return -EILSEQ;
	}

	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("bad ref_len=%d\n", mref->ref_len);
		return -EILSEQ;
	}

	total_size = get_total_size(output);
	if (unlikely(total_size < 0)) {
		return total_size;
	}
	mref->ref_total_size = total_size;

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	/* Buffered IO.
	 */
	if (!mref->ref_data) {
		struct aio_mref_aspect *mref_a = aio_mref_get_aspect(output->brick, mref);
		if (unlikely(!mref_a)) {
			MARS_ERR("bad mref_a\n");
			return -EILSEQ;
		}
		if (unlikely(mref->ref_len <= 0)) {
			MARS_ERR("bad ref_len = %d\n", mref->ref_len);
			return -ENOMEM;
		}
		mref->ref_data = brick_block_alloc(mref->ref_pos, (mref_a->alloc_len = mref->ref_len));
		if (unlikely(!mref->ref_data)) {
			MARS_ERR("ENOMEM %d bytes\n", mref->ref_len);
			return -ENOMEM;
		}
		mref_a->do_dealloc = true;
#ifdef MARS_AIO_DEBUG
		atomic_inc(&output->total_alloc_count);
		atomic_inc(&output->alloc_count);
#endif
	}

	_mref_get_first(mref);
	return mref->ref_len;
}

static void aio_ref_put(struct aio_output *output, struct mref_object *mref)
{
	struct file *file;
	struct aio_mref_aspect *mref_a;

	if (!_mref_put(mref)) {
		goto done;
	}

	if (output->mf && (file = output->mf->mf_filp) && file->f_mapping && file->f_mapping->host) {
		mref->ref_total_size = get_total_size(output);
	}

	mref_a = aio_mref_get_aspect(output->brick, mref);
	if (mref_a && mref_a->do_dealloc) {
		brick_block_free(mref->ref_data, mref_a->alloc_len);
#ifdef MARS_AIO_DEBUG
		atomic_dec(&output->alloc_count);
#endif
	}
	aio_free_mref(mref);
 done:;
}

static
void _complete(struct aio_output *output, struct aio_mref_aspect *mref_a, int err)
{
	struct mref_object *mref;
	bool was_write;

	CHECK_PTR(mref_a, fatal);
	mref = mref_a->object;
	CHECK_PTR(mref, fatal);

	mars_trace(mref, "aio_endio");

	if (err < 0) {
		MARS_ERR("IO error %d at pos=%lld len=%d (mref=%p ref_data=%p)\n", err, mref->ref_pos, mref->ref_len, mref, mref->ref_data);
	} else {
		mref_checksum(mref);
		mref->ref_flags |= MREF_UPTODATE;
	}

	was_write = (mref->ref_flags & MREF_WRITE);
	if (was_write) {
		/* Needs to be done before callback, which might modify
		 * mref->.+
		 */
		mf_dirty_append(output->mf, DIRTY_FINISHED, mref->ref_pos + mref->ref_len);
	}

	CHECKED_CALLBACK(mref, err, err_found);

done:
	if (was_write) {
		atomic_dec(&output->write_count);
	} else {
		atomic_dec(&output->read_count);
	}

	aio_ref_put(output, mref);
	atomic_dec(&output->work_count);
	atomic_dec(&mars_global_io_flying);
	return;

err_found:
	MARS_FAT("giving up...\n");
	goto done;

fatal:
	MARS_FAT("bad pointer, giving up...\n");
}

static
void _complete_mref(struct aio_output *output, struct mref_object *mref, int err)
{
	struct aio_mref_aspect *mref_a;
	_mref_check(mref);
	mref_a = aio_mref_get_aspect(output->brick, mref);
	CHECK_PTR(mref_a, fatal);
	_complete(output, mref_a, err);
	return;

fatal:
	MARS_FAT("bad pointer, giving up...\n");
}

static
void _complete_all(struct list_head *tmp_list, struct aio_output *output, int err)
{
	while (!list_empty(tmp_list)) {
		struct list_head *tmp = tmp_list->next;
		struct aio_mref_aspect *mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
		list_del_init(tmp);
		_complete(output, mref_a, err);
	}
}

static void aio_ref_io(struct aio_output *output, struct mref_object *mref)
{
	struct aio_threadinfo *tinfo = &output->tinfo[0];
	struct aio_mref_aspect *mref_a;
	int err = -EINVAL;

	_mref_check(mref);

	if (unlikely(!output->brick->power.led_on)) {
		SIMPLE_CALLBACK(mref, -EBADFD);
		return;
	}

	_mref_get(mref);
	atomic_inc(&mars_global_io_flying);
	atomic_inc(&output->work_count);

	// statistics
	if (mref->ref_flags & MREF_WRITE) {
#ifdef MARS_AIO_DEBUG
		atomic_inc(&output->total_write_count);
#endif
		atomic_inc(&output->write_count);
	} else {
#ifdef MARS_AIO_DEBUG
		atomic_inc(&output->total_read_count);
#endif
		atomic_inc(&output->read_count);
	}

	if (unlikely(!output->mf || !output->mf->mf_filp)) {
		goto done;
	}

	mapfree_set(output->mf, mref->ref_pos, -1);

	MARS_IO("AIO flags=%ux pos=%lld len=%d data=%p\n",
		mref->ref_flags, mref->ref_pos, mref->ref_len, mref->ref_data);

	mref_a = aio_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		goto done;
	}

	_enqueue(tinfo, mref_a, mref->ref_prio, true);
	return;

done:
	_complete_mref(output, mref, err);
}

static int aio_submit(struct aio_output *output, struct aio_mref_aspect *mref_a, bool use_fdsync)
{
	struct mref_object *mref = mref_a->object;
	mm_segment_t oldfs;
	int res;
	__u32 rw = mref->ref_flags & MREF_WRITE ? 1 : 0;
	struct iocb iocb = {
		.aio_data = (__u64)mref_a,
		.aio_lio_opcode = use_fdsync ? IOCB_CMD_FDSYNC : (rw ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD),
		.aio_fildes = output->fd,
		.aio_buf = (unsigned long)mref->ref_data,
		.aio_nbytes = mref->ref_len,
		.aio_offset = mref->ref_pos,
		// .aio_reqprio = something(mref->ref_prio) field exists, but not yet implemented in kernelspace :(
	};
	struct iocb *iocbp = &iocb;
	struct timing_stats *this_timing = &timings[rw];
	unsigned long long latency;

	mars_trace(mref, "aio_submit");

	if (unlikely(output->fd < 0)) {
		MARS_ERR("bad fd = %d\n", output->fd);
		res = -EBADF;
		goto done;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	latency = TIME_STATS(
		this_timing,
#ifdef MARS_HAS_PREPATCH_V2
		res = ksys_io_submit(output->ctxp, 1, &iocbp)
#else
		res = sys_io_submit(output->ctxp, 1, &iocbp)
#endif
		);
	set_fs(oldfs);

	threshold_check(&aio_submit_threshold, latency);

#ifdef MARS_AIO_DEBUG
	atomic_inc(&output->total_submit_count);
#endif

	if (likely(res >= 0)) {
		atomic_inc(&output->submit_count);
	} else if (likely(res == -EAGAIN)) {
#ifdef MARS_AIO_DEBUG
		atomic_inc(&output->total_again_count);
#endif
	} else {
		MARS_ERR("error = %d\n", res);
	}
	wake_up_interruptible_all(&output->tinfo[1].event);

done:
	return res;
}

static int aio_submit_dummy(struct aio_output *output)
{
	mm_segment_t oldfs;
	int res;
	int dummy;
	struct iocb iocb = {
		.aio_buf = (__u64)&dummy,
	};
	struct iocb *iocbp = &iocb;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
#ifdef MARS_HAS_PREPATCH_V2
	res = ksys_io_submit(output->ctxp, 1, &iocbp);
#else
	res = sys_io_submit(output->ctxp, 1, &iocbp);
#endif
	set_fs(oldfs);

	if (likely(res >= 0)) {
		atomic_inc(&output->submit_count);
	}
	return res;
}

static
int aio_start_thread(
	struct aio_output *output,
	struct aio_threadinfo *tinfo,
	int(*fn)(void*),
	char class)
{
	int j;

	for (j = 0; j < MARS_PRIO_NR; j++) {
		INIT_LIST_HEAD(&tinfo->mref_list[j]);
	}
	tinfo->output = output;
	mutex_init(&tinfo->mutex);
	init_waitqueue_head(&tinfo->event);
	init_waitqueue_head(&tinfo->terminate_event);
	tinfo->should_terminate = false;
	tinfo->terminated = false;
	tinfo->thread = brick_thread_create(fn, tinfo, "mars_aio_%c%d", class, output->index);
	if (unlikely(!tinfo->thread)) {
		MARS_ERR("cannot create thread\n");
		return -ENOENT;
	}
	return 0;
}

static
void aio_stop_thread(struct aio_output *output, int i, bool do_submit_dummy)
{
	struct aio_threadinfo *tinfo = &output->tinfo[i];
	struct task_struct *thread = tinfo->thread;

	if (thread) {
		MARS_DBG("stopping thread %d ...\n", i);
		tinfo->should_terminate = true;

		// workaround for waking up the receiver thread. TODO: check whether signal handlong could do better.
		if (do_submit_dummy) {
			MARS_DBG("submitting dummy for wakeup %d...\n", i);
			use_fake_mm();
			aio_submit_dummy(output);
			if (likely(current->mm)) {
				unuse_fake_mm();
			}
		}
		wake_up_interruptible_all(&tinfo->event);

		// wait for termination
		MARS_DBG("waiting for thread %d ...\n", i);
		wait_event_interruptible_timeout(
			tinfo->terminate_event,
			tinfo->terminated,
			(60 - i * 2) * HZ);
		if (likely(tinfo->terminated)) {
			brick_thread_stop(tinfo->thread);
		} else {
			MARS_ERR("thread %d did not terminate - leaving a zombie\n", i);
		}
	}
}

static
int aio_sync(struct file *file)
{
	int err;

	switch (aio_sync_mode) {
	case 1:
#if defined(S_BIAS) || (defined(RHEL_MAJOR) && (RHEL_MAJOR < 7))
		err = vfs_fsync_range(file, file->f_path.dentry, 0, LLONG_MAX, 1);
#else
		err = vfs_fsync_range(file, 0, LLONG_MAX, 1);
#endif
		break;
	case 2:
#if defined(S_BIAS) || (defined(RHEL_MAJOR) && (RHEL_MAJOR < 7))
		err = vfs_fsync_range(file, file->f_path.dentry, 0, LLONG_MAX, 0);
#else
		err = vfs_fsync_range(file, 0, LLONG_MAX, 0);
#endif
		break;
	default:
		err = filemap_write_and_wait_range(file->f_mapping, 0, LLONG_MAX);
	}

	return err;
}

static
void aio_sync_all(struct aio_output *output, struct list_head *tmp_list)
{
	unsigned long long latency;
	int err;

	output->fdsync_active = true;
#ifdef MARS_AIO_DEBUG
	atomic_inc(&output->total_fdsync_count);
#endif
	
	latency = TIME_STATS(
		&timings[2],
		err = aio_sync(output->mf->mf_filp)
		);
	
	threshold_check(&aio_sync_threshold, latency);

	output->fdsync_active = false;
	wake_up_interruptible_all(&output->fdsync_event);
	if (err < 0) {
		MARS_ERR("FDSYNC error %d\n", err);
	}
	
	/* Signal completion for the whole list.
	 * No locking needed, it's on the stack.
	 */
	_complete_all(tmp_list, output, err);
}

/* Workaround for non-implemented aio_fsync()
 */
static
int aio_sync_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	
	MARS_DBG("sync thread has started on '%s'.\n", output->brick->brick_path);
	//set_user_nice(current, -20);

	while (!tinfo->should_terminate || atomic_read(&tinfo->queued_sum) > 0) {
		LIST_HEAD(tmp_list);
		int i;

		output->fdsync_active = false;
		wake_up_interruptible_all(&output->fdsync_event);

		wait_event_interruptible_timeout(
			tinfo->event,
			atomic_read(&tinfo->queued_sum) > 0 ||
			tinfo->should_terminate,
			HZ / 4);

		mutex_lock(&tinfo->mutex);
		for (i = 0; i < MARS_PRIO_NR; i++) {
			struct list_head *start = &tinfo->mref_list[i];
			if (!list_empty(start)) {
				// move over the whole list
				list_replace_init(start, &tmp_list);
				atomic_sub(tinfo->queued[i], &tinfo->queued_sum);
				tinfo->queued[i] = 0;
				break;
			}
		}
		mutex_unlock(&tinfo->mutex);

		if (!list_empty(&tmp_list)) {
			aio_sync_all(output, &tmp_list);
		}
	}

	MARS_DBG("sync thread has stopped.\n");
	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	return 0;
}

static int aio_event_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct aio_brick *brick = output->brick;
	struct aio_threadinfo *other = &output->tinfo[2];
	struct io_event *events;
	int err = -ENOMEM;
	
	events = brick_mem_alloc(sizeof(struct io_event) * MARS_MAX_AIO_READ);

	MARS_DBG("event thread has started.\n");
	//set_user_nice(current, -20);

	use_fake_mm();
	if (!current->mm)
		goto err;

	err = aio_start_thread(output, &output->tinfo[2], aio_sync_thread, 'y');
	if (unlikely(err < 0))
		goto err;

	while (!tinfo->should_terminate || atomic_read(&tinfo->queued_sum) > 0) {
		mm_segment_t oldfs;
		int count;
		int i;
		struct timespec timeout = {
			.tv_nsec =
				tinfo->should_terminate ||
				!brick->power.button ? 0 : 100000,
		};

		if (unlikely(!(void*)output->ctxp)) {
			MARS_ERR("Oops, context vanished. queued_sum = %d\n", atomic_read(&tinfo->queued_sum));
			break;
		}

#ifdef CONFIG_MARS_DEBUG
		if (mars_hang_mode & 1) {
			brick_msleep(100);
			continue;
		}
#endif

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		/* TODO: don't timeout upon termination.
		 * Probably we should submit a dummy request.
		 */
#ifdef MARS_HAS_PREPATCH_V2
		count = ksys_io_getevents(output->ctxp, 1, MARS_MAX_AIO_READ, events, &timeout);
#else
		count = sys_io_getevents(output->ctxp, 1, MARS_MAX_AIO_READ, events, &timeout);
#endif
		set_fs(oldfs);

		if (count > 0) {
			atomic_sub(count, &output->submit_count);
		} else if (!count) {
			wait_event_interruptible_timeout(
				tinfo->event,
				atomic_read(&output->submit_count) > 0 ||
				tinfo->should_terminate,
				HZ / 4);
			continue;
		}

		for (i = 0; i < count; i++) {
			struct aio_mref_aspect *mref_a = (void*)events[i].data;
			struct mref_object *mref;
			int err = events[i].res;

			if (!mref_a) {
				continue; // this was a dummy request
			}
			mref = mref_a->object;

			MARS_IO("AIO done %p pos = %lld len = %d flags = %ux\n",
				mref, mref->ref_pos, mref->ref_len,
				mref->ref_flags);

			mapfree_set(output->mf, mref->ref_pos, mref->ref_pos + mref->ref_len);
			if (mref->ref_flags & MREF_WRITE)
				mf_dirty_append(output->mf, DIRTY_COMPLETED, mref->ref_pos + mref->ref_len);

			/* Workaround for never implemented aio_fsync operation,
			 * see also upstream commit 723c038475b78edc9327eb952f95f9881cc9d7.
			 * FIXME: don't use aio anymore at all in the long-term future.
			 */
			if (output->brick->o_fdsync &&
			    err >= 0 &&
			    (mref->ref_flags & MREF_WRITE) &&
			    !(mref->ref_flags & MREF_SKIP_SYNC) &&
			    !mref_a->resubmit++) {
				mars_trace(mref, "aio_fsync");
				_enqueue(other, mref_a, mref->ref_prio, true);
				continue;
			}

			_complete(output, mref_a, err);

		}
	}
	err = 0;

 err:
	MARS_DBG("event thread has stopped, err = %d\n", err);

	aio_stop_thread(output, 2, false);

	unuse_fake_mm();

	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	brick_mem_free(events);
	return err;
}

#if 1
/* This should go to fs/open.c (as long as vfs_submit() is not implemented)
 */
#include <linux/fdtable.h>
void fd_uninstall(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	unsigned long flags;

	MARS_DBG("fd = %d\n", fd);
	if (unlikely(fd < 0)) {
		MARS_ERR("bad fd = %d\n", fd);
		return;
	}
	spin_lock_irqsave(&files->file_lock, flags);
	fdt = files_fdtable(files);
	rcu_assign_pointer(fdt->fd[fd], NULL);
	spin_unlock_irqrestore(&files->file_lock, flags);
}
EXPORT_SYMBOL(fd_uninstall);
#endif

static
atomic_t ioctx_count = ATOMIC_INIT(0);
static DEFINE_MUTEX(_fd_lock);

static
void _destroy_ioctx(struct aio_output *output)
{
	int fd;

	if (unlikely(!output))
		goto done;

	aio_stop_thread(output, 1, true);

	use_fake_mm();

	if (likely(output->ctxp)) {
		mm_segment_t oldfs;
		int err;

		MARS_DBG("ioctx count = %d destroying %p\n", atomic_read(&ioctx_count), (void*)output->ctxp);
		oldfs = get_fs();
		set_fs(KERNEL_DS);
#ifdef MARS_HAS_PREPATCH_V2
		err = ksys_io_destroy(output->ctxp);
#else
		err = sys_io_destroy(output->ctxp);
#endif
		set_fs(oldfs);
		atomic_dec(&ioctx_count);
		MARS_DBG("ioctx count = %d status = %d\n", atomic_read(&ioctx_count), err);
		output->ctxp = 0;
#ifdef HAS_AIO_MAX
		mutex_lock(&aio_max_lock);
		aio_max_nr_current -= MARS_MAX_AIO;
		mutex_unlock(&aio_max_lock);
#endif
	}

	fd = output->fd;
	if (likely(fd >= 0)) {
		MARS_DBG("destroying fd %d\n", fd);
		mutex_lock(&_fd_lock);
		fd_uninstall(fd);
		put_unused_fd(fd);
		output->fd = -1;
		mutex_unlock(&_fd_lock);
	}

 done:
	if (likely(current->mm)) {
		unuse_fake_mm();
	}
}

/* TODO: this is provisionary. We only need it for sys_io_submit()
 * which uses userspace concepts like file handles.
 * This should be replaced by a future kernelsapce vfs_submit() or
 * do_submit() which currently does not exist :(
 * Or, the whole aio brick should be replaced by something else.
 * A good candidate could be the new {read,write}_iter() infrastructure.
 * But only present at newer kernels.
 * Unfortunately I will have to support old kernels for a while :(
 */
static int _get_fd(void)
{
	struct files_struct *files;
	int err = -EINVAL;
	int count = 0;

	do {
		mutex_lock(&_fd_lock);

		files = current->files;
		CHECK_PTR(files, done);

		/* Workaround upstream bug:
		 * Commit 8a81252b774b53e628a8a0fe18e2b8fc236d92cc
		 * forgot to initialize the new field resize_wait in
		 * fs/file.c in the initializer of init_files.
		 * We detect whether this commit is present via neighbor
		 * commit a7928c1578c550bd6f4dec62d65132e6db226c57
		 * which removed the ancient define for blk_pm_request.
		 * Once the bug is fixed in all relevant upstream LTS kernels
		 * and in all relevant distro kernels, this hack should be
		 * removed again.
		 */
#ifndef blk_pm_request
		/* Upstream commit 2055da97389a605c8a00d163d40903afbe413921
		 * changed the field name.
		 * Detected via 8ada92799ec4de00f4bc0f10b1ededa256c1ab22
		 */
#ifdef wait_event_killable_timeout
#define XXX_NAME head
#else
#define XXX_NAME task_list
#endif
		if (unlikely(!files->resize_wait.XXX_NAME.next)) {
			files->resize_in_progress = false;
			init_waitqueue_head(&files->resize_wait);
		}
#endif

		/* see f938612dd97d481b8b5bf960c992ae577f081c17
		 * and 1a7bd2265fc57f29400d57f66275cc5918e30aa6
		 */
#if defined(get_unused_fd) || defined(get_unused_fd_flags)
		err = get_unused_fd();
#else
		err = get_unused_fd_flags(0);
#endif
		mutex_unlock(&_fd_lock);
		/* safety workaround: skip standard Unix filehandles */
	} while (err >= 0 && err <= 2 && count++ < 3);
 done:
	return err;
}

static
int _create_ioctx(struct aio_output *output)
{
	struct file *file;
	mm_segment_t oldfs;
	int err = -EINVAL;

	CHECK_PTR_NULL(output, done);
	CHECK_PTR_NULL(output->mf, done);
	file = output->mf->mf_filp;
	CHECK_PTR_NULL(file, done);

	err = _get_fd();
	MARS_DBG("file %p '%s' new fd = %d\n", file, output->mf->mf_name, err);
	if (unlikely(err < 0)) {
		MARS_ERR("cannot get fd, err=%d\n", err);
		goto done;
	}
	output->fd = err;
	fd_install(err, file);

	use_fake_mm();

	err = -ENOMEM;
	if (unlikely(!current->mm)) {
		MARS_ERR("cannot fake mm\n");
		goto done;
	}

#ifdef HAS_AIO_MAX
	/* Self-tune aio_max_nr when possible. */
	mutex_lock(&aio_max_lock);
	aio_max_nr_current += MARS_MAX_AIO;
	if (aio_max_nr_current > aio_max_nr_max) {
		int diff = aio_max_nr_current - aio_max_nr_max;

		aio_max_nr += diff;
		aio_max_nr_max = aio_max_nr_current;
	}
	mutex_unlock(&aio_max_lock);
#endif

	MARS_DBG("ioctx count = %d old = %p\n", atomic_read(&ioctx_count), (void*)output->ctxp);
	output->ctxp = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
#ifdef MARS_HAS_PREPATCH_V2
	err = ksys_io_setup(MARS_MAX_AIO, &output->ctxp);
#else
	err = sys_io_setup(MARS_MAX_AIO, &output->ctxp);
#endif
	set_fs(oldfs);
	if (likely(output->ctxp))
		atomic_inc(&ioctx_count);
	MARS_DBG("ioctx count = %d new = %p status = %d\n", atomic_read(&ioctx_count), (void*)output->ctxp, err);
	if (unlikely(err < 0)) {
		MARS_ERR("io_setup failed, err=%d\n", err);
		goto done;
	}
	
	err = aio_start_thread(output, &output->tinfo[1], aio_event_thread, 'e');
	if (unlikely(err < 0)) {
		MARS_ERR("could not start event thread\n");
		goto done;
	}

 done:
	if (likely(current->mm)) {
		unuse_fake_mm();
	}
	return err;
}

static int aio_submit_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct file *file;
	int err = -EINVAL;

	MARS_DBG("submit thread has started.\n");

	file = output->mf->mf_filp;

	use_fake_mm();

	while (!tinfo->should_terminate || atomic_read(&output->read_count) + atomic_read(&output->write_count) + atomic_read(&tinfo->queued_sum) > 0) {
		struct aio_mref_aspect *mref_a;
		struct mref_object *mref;
		int sleeptime;
		int status;

		wait_event_interruptible_timeout(
			tinfo->event,
			atomic_read(&tinfo->queued_sum) > 0 ||
			tinfo->should_terminate,
			HZ / 4);

		mref_a = _dequeue(tinfo);
		if (!mref_a) {
			continue;
		}

		mref = mref_a->object;
		status = -EINVAL;
		CHECK_PTR(mref, error);

		mapfree_set(output->mf, mref->ref_pos, -1);

		if (mref->ref_flags & MREF_WRITE) {
			mf_dirty_append(output->mf, DIRTY_SUBMITTED, mref->ref_pos + mref->ref_len);
		}

		mref->ref_total_size = get_total_size(output);

		/* Check for reads crossing the EOF boundary (special case)
		 */
		if (!(mref->ref_flags & MREF_WRITE) &&
		    mref->ref_pos + mref->ref_len > mref->ref_total_size) {
			loff_t len;

			/* Timeout handling, ONLY possible for reads
			 * beyond EOF.
			 * Currently not used! Needed for a future feature.
			 */
			if (mref->ref_timeout > 0) {
				if (!mref_a->start_jiffies)
					mref_a->start_jiffies = jiffies;
				if ((long long)jiffies - mref_a->start_jiffies <= mref->ref_timeout) {
					if (atomic_read(&tinfo->queued_sum) <= 0) {
#ifdef MARS_AIO_DEBUG
						atomic_inc(&output->total_msleep_count);
#endif
						brick_msleep(1000 * 4 / HZ);
					}
					_enqueue(tinfo, mref_a, MARS_PRIO_LOW, true);
					continue;
				}

				MARS_DBG("ENODATA %lld\n", len);
				_complete(output, mref_a, -ENODATA);
				continue;
			}
			/* Shorten reads crossing EOF.
			 */
			len = mref->ref_total_size - mref->ref_pos;
			if (len > 0 && mref->ref_len > len)
				mref->ref_len = len;
		}

		sleeptime = 1;
		for (;;) {
			status = aio_submit(output, mref_a, false);

			if (likely(status != -EAGAIN)) {
				break;
			}
#ifdef MARS_AIO_DEBUG
			atomic_inc(&output->total_delay_count);
#endif
			brick_msleep(sleeptime);
			if (sleeptime < 100) {
				sleeptime++;
			}
		}

	error:
		if (unlikely(status < 0)) {
			MARS_IO("submit_count = %d status = %d\n", atomic_read(&output->submit_count), status);
			_complete_mref(output, mref, status);
		}
	}

	MARS_DBG("submit thread has stopped, status = %d.\n", err);

	if (likely(current->mm)) {
		unuse_fake_mm();
	}

	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	return err;
}

static int aio_get_info(struct aio_output *output, struct mars_info *info)
{
	struct file *file;

	if (unlikely(!output ||
		     !output->mf ||
		     !(file = output->mf->mf_filp) ||
		     !file->f_mapping ||
		     !file->f_mapping->host))
		return -EINVAL;

	info->tf_align = 1;
	info->tf_min_size = 1;
	info->current_size = get_total_size(output);

	MARS_DBG("determined file size = %lld\n", info->current_size);

	return 0;
}

//////////////// informational / statistics ///////////////

static noinline
char *aio_statistics(struct aio_brick *brick, int verbose)
{
	struct aio_output *output = brick->outputs[0];
	char *res = brick_string_alloc(4096);
	char *sync = NULL;
	int pos = 0;
	if (!res)
		return NULL;

	pos += report_timing(&timings[0], res + pos, 4096 - pos);
	pos += report_timing(&timings[1], res + pos, 4096 - pos);
	pos += report_timing(&timings[2], res + pos, 4096 - pos);

	snprintf(res + pos, 4096 - pos,
#ifdef MARS_AIO_DEBUG
		 "total "
		 "reads = %d "
		 "writes = %d "
		 "allocs = %d "
		 "submits = %d "
		 "again = %d "
		 "delays = %d "
		 "msleeps = %d "
		 "fdsyncs = %d "
		 "fdsync_waits = %d "
		 "map_free = %d | "
#endif
		 "flying reads = %d "
		 "writes = %d "
#ifdef MARS_AIO_DEBUG
		 "allocs = %d "
#endif
		 "submits = %d "
		 "q0 = %d "
		 "q1 = %d "
		 "q2 = %d "
#ifdef MARS_AIO_DEBUG
		 "| total "
		 "q0 = %d "
		 "q1 = %d "
		 "q2 = %d "
#endif
		 "%s\n",
#ifdef MARS_AIO_DEBUG
		 atomic_read(&output->total_read_count),
		 atomic_read(&output->total_write_count),
		 atomic_read(&output->total_alloc_count),
		 atomic_read(&output->total_submit_count),
		 atomic_read(&output->total_again_count),
		 atomic_read(&output->total_delay_count),
		 atomic_read(&output->total_msleep_count),
		 atomic_read(&output->total_fdsync_count),
		 atomic_read(&output->total_fdsync_wait_count),
		 atomic_read(&output->total_mapfree_count),
#endif
		 atomic_read(&output->read_count),
		 atomic_read(&output->write_count),
#ifdef MARS_AIO_DEBUG
		 atomic_read(&output->alloc_count),
#endif
		 atomic_read(&output->submit_count),
		 atomic_read(&output->tinfo[0].queued_sum),
		 atomic_read(&output->tinfo[1].queued_sum),
		 atomic_read(&output->tinfo[2].queued_sum),
#ifdef MARS_AIO_DEBUG
		 atomic_read(&output->tinfo[0].total_enqueue_count),
		 atomic_read(&output->tinfo[1].total_enqueue_count),
		 atomic_read(&output->tinfo[2].total_enqueue_count),
#endif
		 sync ? sync : "");

	brick_string_free(sync);

	return res;
}

static noinline
void aio_reset_statistics(struct aio_brick *brick)
{
#ifdef MARS_AIO_DEBUG
	struct aio_output *output = brick->outputs[0];
	int i;

	atomic_set(&output->total_read_count, 0);
	atomic_set(&output->total_write_count, 0);
	atomic_set(&output->total_alloc_count, 0);
	atomic_set(&output->total_submit_count, 0);
	atomic_set(&output->total_again_count, 0);
	atomic_set(&output->total_delay_count, 0);
	atomic_set(&output->total_msleep_count, 0);
	atomic_set(&output->total_fdsync_count, 0);
	atomic_set(&output->total_fdsync_wait_count, 0);
	atomic_set(&output->total_mapfree_count, 0);
	for (i = 0; i < 3; i++) {
		struct aio_threadinfo *tinfo = &output->tinfo[i];

		atomic_set(&tinfo->total_enqueue_count, 0);
	}
#endif
}

#endif /* ENABLE_MARS_AIO */
//////////////// object / aspect constructors / destructors ///////////////

static int aio_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct aio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void aio_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct aio_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->io_head);
}

MARS_MAKE_STATICS(aio);

#ifdef ENABLE_MARS_AIO
////////////////////// brick constructors / destructors ////////////////////

static int aio_brick_construct(struct aio_brick *brick)
{
	return 0;
}

static int aio_switch(struct aio_brick *brick)
{
	static int index;
	struct aio_output *output = brick->outputs[0];
	const char *path = output->brick->brick_path;
	int flags = O_RDWR | O_LARGEFILE;
	int status = 0;

	MARS_DBG("power.button = %d\n", brick->power.button);
	if (!brick->power.button)
		goto cleanup;

	if (brick->power.led_on || output->mf)
		goto done;

	mars_power_led_off((void*)brick, false);

	flags |= O_LARGEFILE;
	if (brick->o_creat) {
		flags |= (O_NOFOLLOW | O_CREAT);
		MARS_DBG("using O_CREAT on %s\n", path);
	}
	if (brick->o_direct) {
		flags |= O_DIRECT;
		MARS_DBG("using O_DIRECT on %s\n", path);
	}

	output->error = 0;
	output->mf = mapfree_get(path, flags, &output->error);
	if (unlikely(!output->mf)) {
		MARS_ERR("could not open file = '%s' flags = %d error = %d\n",
			 path, flags, output->error);
		status = output->error;
		if (!status)
			status = -ENOENT;
		goto err;
	} 

	output->index = ++index;

	status = _create_ioctx(output);
	if (unlikely(status < 0)) {
		MARS_ERR("could not create ioctx, status = %d\n", status);
		goto err;
	}

	status = aio_start_thread(output, &output->tinfo[0], aio_submit_thread, 's');
	if (unlikely(status < 0)) {
		MARS_ERR("could not start theads, status = %d\n", status);
		goto err;
	}

	MARS_DBG("opened file '%s'\n", path);
	brick->mode_ptr = &output->mf->mf_mode;
	mars_power_led_on((void*)brick, true);

done:
	return 0;

err:
	MARS_ERR("status = %d\n", status);
cleanup:
	if (brick->power.led_off) {
		goto done;
	}

	mars_power_led_on((void*)brick, false);

	for (;;) {
		int count = atomic_read(&output->work_count);
		if (count <= 0)
			break;
		MARS_DBG("working on %d requests\n", count);
		brick_msleep(1000);
	}

	aio_stop_thread(output, 0, false);

	brick->mode_ptr = NULL;

	_destroy_ioctx(output);

	mars_power_led_off((void*)brick,
			  (output->tinfo[0].thread == NULL &&
			   output->tinfo[1].thread == NULL &&
			   output->tinfo[2].thread == NULL));

	MARS_DBG("switch off led_off = %d status = %d\n", brick->power.led_off, status);
	if (brick->power.led_off) {
		if (output->mf) {
			MARS_DBG("closing file = '%s'\n", output->mf->mf_name);
			mapfree_put(output->mf);
			output->mf = NULL;
		}
	}
	return status;
}

static int aio_output_construct(struct aio_output *output)
{
	init_waitqueue_head(&output->fdsync_event);
	output->fd = -1;
	return 0;
}

static int aio_output_destruct(struct aio_output *output)
{
	if (unlikely(output->fd >= 0)) {
		MARS_ERR("active fd = %d detected\n", output->fd);
	}
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct aio_brick_ops aio_brick_ops = {
	.brick_switch = aio_switch,
	.brick_statistics = aio_statistics,
	.reset_statistics = aio_reset_statistics,
};

static struct aio_output_ops aio_output_ops = {
	.mref_get = aio_ref_get,
	.mref_put = aio_ref_put,
	.mref_io = aio_ref_io,
	.mars_get_info = aio_get_info,
};

const struct aio_input_type aio_input_type = {
	.type_name = "aio_input",
	.input_size = sizeof(struct aio_input),
};

static const struct aio_input_type *aio_input_types[] = {
	&aio_input_type,
};

const struct aio_output_type aio_output_type = {
	.type_name = "aio_output",
	.output_size = sizeof(struct aio_output),
	.master_ops = &aio_output_ops,
	.output_construct = &aio_output_construct,
	.output_destruct = &aio_output_destruct,
};

static const struct aio_output_type *aio_output_types[] = {
	&aio_output_type,
};

#endif /* ENABLE_MARS_AIO */

const struct aio_brick_type aio_brick_type = {
	.type_name = "aio_brick",
	.brick_size = sizeof(struct aio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
#ifdef ENABLE_MARS_AIO
	.master_ops = &aio_brick_ops,
	.aspect_types = aio_aspect_types,
	.default_input_types = aio_input_types,
	.default_output_types = aio_output_types,
	.brick_construct = &aio_brick_construct,
#else /* ENABLE_MARS_AIO */
	.aspect_types = aio_aspect_types,	/* dummy, shut up gcc */
#endif /* ENABLE_MARS_AIO */
};
EXPORT_SYMBOL_GPL(aio_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_aio(void)
{
	MARS_DBG("init_aio()\n");
	_aio_brick_type = (void*)&aio_brick_type;
	return aio_register_brick_type();
}

void exit_mars_aio(void)
{
	MARS_DBG("exit_aio()\n");
	aio_unregister_brick_type();
}
