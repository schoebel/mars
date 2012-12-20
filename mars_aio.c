// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "mars.h"
#include "lib_timing.h"

#include "mars_aio.h"

#define MARS_MAX_AIO      1024
#define MARS_MAX_AIO_READ 32

static struct timing_stats timings[3] = {};

struct threshold aio_submit_threshold = {
	.thr_ban = &mars_global_ban,
	.thr_limit = AIO_SUBMIT_MAX_LATENCY,
	.thr_factor = 10,
	.thr_plus = 10000,
};
EXPORT_SYMBOL_GPL(aio_submit_threshold);

struct threshold aio_io_threshold[2] = {
	[0] = {
		.thr_ban = &mars_global_ban,
		.thr_limit = AIO_IO_R_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
	[1] = {
		.thr_ban = &mars_global_ban,
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

///////////////////////// own type definitions ////////////////////////

////////////////// some helpers //////////////////

static inline
void _enqueue(struct aio_threadinfo *tinfo, struct aio_mref_aspect *mref_a, int prio, bool at_end)
{
	unsigned long flags;
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

	traced_lock(&tinfo->lock, flags);

	if (at_end) {
		list_add_tail(&mref_a->io_head, &tinfo->mref_list[prio]);
	} else {
		list_add(&mref_a->io_head, &tinfo->mref_list[prio]);
	}
	tinfo->queued[prio]++;
	atomic_inc(&tinfo->queued_sum);

	traced_unlock(&tinfo->lock, flags);

	atomic_inc(&tinfo->total_enqueue_count);

	wake_up_interruptible_all(&tinfo->event);
}

static inline
struct aio_mref_aspect *_dequeue(struct aio_threadinfo *tinfo)
{
	struct aio_mref_aspect *mref_a = NULL;
	int prio;
	unsigned long flags = 0;

	traced_lock(&tinfo->lock, flags);

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
	traced_unlock(&tinfo->lock, flags);

	if (likely(mref_a && mref_a->object)) {
		unsigned long long latency;
		latency = cpu_clock(raw_smp_processor_id()) - mref_a->enqueue_stamp;
		threshold_check(&aio_io_threshold[mref_a->object->ref_rw & 1], latency);
	}
	return mref_a;
}

////////////////// own brick / input / output operations //////////////////

static int aio_ref_get(struct aio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;

	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("bad ref_len=%d\n", mref->ref_len);
		return -EILSEQ;
	}

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	if (file) {
		loff_t total_size = i_size_read(file->f_mapping->host);
		mref->ref_total_size = total_size;
		/* Only check reads.
		 * Writes behind EOF are always allowed (sparse files)
		 */
		if (!mref->ref_may_write) {
			loff_t len = total_size - mref->ref_pos;
			if (unlikely(len <= 0)) {
				/* Special case: allow reads starting _exactly_ at EOF when a timeout is specified.
				 */
				if (len < 0 || mref->ref_timeout <= 0) {
					MARS_DBG("ENODATA %lld\n", len);
					return -ENODATA;
				}
			}
			// Shorten below EOF, but allow special case
			if (mref->ref_len > len && len > 0) {
				mref->ref_len = len;
			}
		}
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
#if 0 // ???
		mref->ref_flags = 0;
#endif
		mref_a->do_dealloc = true;
		atomic_inc(&output->total_alloc_count);
		atomic_inc(&output->alloc_count);
	}

	_mref_get_first(mref);
	return mref->ref_len;
}

static void aio_ref_put(struct aio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;
	struct aio_mref_aspect *mref_a;

	if (!_mref_put(mref)) {
		goto done;
	}

	if (file) {
		mref->ref_total_size = i_size_read(file->f_mapping->host);
	}

	mref_a = aio_mref_get_aspect(output->brick, mref);
	if (mref_a && mref_a->do_dealloc) {
		brick_block_free(mref->ref_data, mref_a->alloc_len);
		atomic_dec(&output->alloc_count);
	}
	aio_free_mref(mref);
 done:;
}

static
void _complete(struct aio_output *output, struct mref_object *mref, int err)
{
	_mref_check(mref);

	mars_trace(mref, "aio_endio");

	if (err < 0) {
		MARS_ERR("IO error %d at pos=%lld len=%d (mref=%p ref_data=%p)\n", err, mref->ref_pos, mref->ref_len, mref, mref->ref_data);
	} else {
		mref_checksum(mref);
		mref->ref_flags |= MREF_UPTODATE;
	}

	CHECKED_CALLBACK(mref, err, err_found);

done:
	if (mref->ref_rw) {
		atomic_dec(&output->write_count);
	} else {
		atomic_dec(&output->read_count);
	}

	aio_ref_put(output, mref);
	atomic_dec(&mars_global_io_flying);
	return;

err_found:
	MARS_FAT("giving up...\n");
	goto done;
}

static
void _complete_all(struct list_head *tmp_list, struct aio_output *output, int err)
{
	while (!list_empty(tmp_list)) {
		struct list_head *tmp = tmp_list->next;
		struct aio_mref_aspect *mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
		list_del_init(tmp);
		_complete(output, mref_a->object, err);
	}
}

static void aio_ref_io(struct aio_output *output, struct mref_object *mref)
{
	struct aio_threadinfo *tinfo = &output->tinfo[0];
	struct aio_mref_aspect *mref_a;
	int err = -EINVAL;

	_mref_get(mref);
	atomic_inc(&mars_global_io_flying);

	// statistics
	if (mref->ref_rw) {
		atomic_inc(&output->total_write_count);
		atomic_inc(&output->write_count);
	} else {
		atomic_inc(&output->total_read_count);
		atomic_inc(&output->read_count);
	}

	if (unlikely(!output->filp)) {
		goto done;
	}

	MARS_IO("AIO rw=%d pos=%lld len=%d data=%p\n", mref->ref_rw, mref->ref_pos, mref->ref_len, mref->ref_data);

	mref_a = aio_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		goto done;
	}

	_enqueue(tinfo, mref_a, mref->ref_prio, true);
	return;

done:
	_complete(output, mref, err);
}

static int aio_submit(struct aio_output *output, struct aio_mref_aspect *mref_a, bool use_fdsync)
{
	struct mref_object *mref = mref_a->object;
	mm_segment_t oldfs;
	int res;
	struct iocb iocb = {
		.aio_data = (__u64)mref_a,
		.aio_lio_opcode = use_fdsync ? IOCB_CMD_FDSYNC : (mref->ref_rw != 0 ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD),
		.aio_fildes = output->fd,
		.aio_buf = (unsigned long)mref->ref_data,
		.aio_nbytes = mref->ref_len,
		.aio_offset = mref->ref_pos,
		// .aio_reqprio = something(mref->ref_prio) field exists, but not yet implemented in kernelspace :(
	};
	struct iocb *iocbp = &iocb;
	unsigned long long latency;

	mars_trace(mref, "aio_submit");

	oldfs = get_fs();
	set_fs(get_ds());
	latency = TIME_STATS(&timings[mref->ref_rw & 1], res = sys_io_submit(output->ctxp, 1, &iocbp));
	set_fs(oldfs);

	threshold_check(&aio_submit_threshold, latency);

	atomic_inc(&output->total_submit_count);

	if (likely(res >= 0)) {
		atomic_inc(&output->submit_count);
	} else if (unlikely(res != -EAGAIN)) {
		MARS_ERR("error = %d\n", res);
	}

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
	set_fs(get_ds());
	res = sys_io_submit(output->ctxp, 1, &iocbp);
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
	spin_lock_init(&tinfo->lock);
	init_waitqueue_head(&tinfo->event);
	init_waitqueue_head(&tinfo->terminate_event);
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

	if (tinfo->thread) {
		MARS_INF("stopping thread %d ...\n", i);
		brick_thread_stop_nowait(tinfo->thread);

		// workaround for waking up the receiver thread. TODO: check whether signal handlong could do better.
		if (do_submit_dummy) {
			MARS_INF("submitting dummy for wakeup %d...\n", i);
			aio_submit_dummy(output);
		}

		// wait for termination
		MARS_INF("waiting for thread %d ...\n", i);
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

	err = filemap_write_and_wait_range(file->f_mapping, 0, LLONG_MAX);

	return err;
}

static
void aio_sync_all(struct aio_output *output, struct list_head *tmp_list)
{
	unsigned long long latency;
	int err;

	output->fdsync_active = true;
	atomic_inc(&output->total_fdsync_count);
	
	latency = TIME_STATS(
		&timings[2],
		err = aio_sync(output->filp)
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

#ifdef USE_CLEVER_SYNC
static
int sync_cmp(struct pairing_heap_sync *_a, struct pairing_heap_sync *_b)
{
	struct aio_mref_aspect *a = container_of(_a, struct aio_mref_aspect, heap_head);
	struct aio_mref_aspect *b = container_of(_b, struct aio_mref_aspect, heap_head);
	struct mref_object *ao = a->object;
	struct mref_object *bo = b->object;
	if (unlikely(!ao || !bo)) {
		MARS_ERR("bad object pointers\n");
		return 0;
	}
	if (ao->ref_pos < bo->ref_pos)
		return -1;
	if (ao->ref_pos > bo->ref_pos)
		return 1;
	return 0;
}

_PAIRING_HEAP_FUNCTIONS(static,sync,sync_cmp);

static
void aio_clever_move(struct list_head *tmp_list, int prio, struct q_sync *q_sync)
{
	while (!list_empty(tmp_list)) {
		struct list_head *tmp = tmp_list->next;
		struct aio_mref_aspect *mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
		list_del_init(tmp);
		ph_insert_sync(&q_sync->heap[prio], &mref_a->heap_head);
	}
}

static
void aio_clever_sync(struct aio_output *output, struct q_sync *q_sync)
{
	int i;
	int max = 64;
	for (i = 0; i < MARS_PRIO_NR; i++) {
		struct pairing_heap_sync **heap = &q_sync->heap[i];
		if (*heap) {
			return;
		}
	}
}
#endif

/* Workaround for non-implemented aio_fsync()
 */
static
int aio_sync_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
#ifdef USE_CLEVER_SYNC
	struct q_sync q_sync = {};
#endif
	
	MARS_INF("sync thread has started on '%s'.\n", output->brick->brick_path);
	//set_user_nice(current, -20);

	while (!brick_thread_should_stop() || atomic_read(&tinfo->queued_sum) > 0) {
		LIST_HEAD(tmp_list);
		unsigned long flags;
		int i;

		output->fdsync_active = false;
		wake_up_interruptible_all(&output->fdsync_event);

		wait_event_interruptible_timeout(
			tinfo->event,
			atomic_read(&tinfo->queued_sum) > 0,
			HZ / 4);

		traced_lock(&tinfo->lock, flags);
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
		traced_unlock(&tinfo->lock, flags);

		if (!list_empty(&tmp_list)) {
#ifdef USE_CLEVER_SYNC
			aio_clever_move(&tmp_list, i, &q_sync);
#else
			aio_sync_all(output, &tmp_list);
#endif
		}
#ifdef USE_CLEVER_SYNC
		aio_clever_sync(output, &q_sync);
#endif
	}

	MARS_INF("sync thread has stopped.\n");
	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	return 0;
}

static int aio_event_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct aio_threadinfo *other = &output->tinfo[2];
	int err = -ENOMEM;
	
	MARS_INF("event thread has started.\n");
	//set_user_nice(current, -20);

	use_fake_mm();
	if (!current->mm)
		goto err;

	err = aio_start_thread(output, &output->tinfo[2], aio_sync_thread, 'y');
	if (unlikely(err < 0))
		goto err;

	while (!brick_thread_should_stop() || atomic_read(&tinfo->queued_sum) > 0) {
		mm_segment_t oldfs;
		int count;
		int i;
		struct timespec timeout = {
			.tv_sec = 1,
		};
		struct io_event events[MARS_MAX_AIO_READ];

		oldfs = get_fs();
		set_fs(get_ds());
		/* TODO: don't timeout upon termination.
		 * Probably we should submit a dummy request.
		 */
		count = sys_io_getevents(output->ctxp, 1, MARS_MAX_AIO_READ, events, &timeout);
		set_fs(oldfs);

		if (likely(count > 0)) {
			atomic_sub(count, &output->submit_count);
		}

		//MARS_INF("count = %d\n", count);
		for (i = 0; i < count; i++) {
			struct aio_mref_aspect *mref_a = (void*)events[i].data;
			struct mref_object *mref;
			int err = events[i].res;

			if (!mref_a) {
				continue; // this was a dummy request
			}
			mref = mref_a->object;

			MARS_IO("AIO done %p pos = %lld len = %d rw = %d\n", mref, mref->ref_pos, mref->ref_len, mref->ref_rw);

			if (output->brick->o_fdsync
			   && err >= 0 
			   && mref->ref_rw != READ
			   && !mref->ref_skip_sync
			   && !mref_a->resubmit++) {
				// workaround for non-implemented AIO FSYNC operation
				if (!output->filp->f_op->aio_fsync) {
					mars_trace(mref, "aio_fsync");
					_enqueue(other, mref_a, mref->ref_prio, true);
					continue;
				}
				err = aio_submit(output, mref_a, true);
				if (likely(err >= 0))
					continue;
			}

			_complete(output, mref, err);

		}
	}
	err = 0;

 err:
	MARS_INF("event thread has stopped, err = %d\n", err);

	aio_stop_thread(output, 2, false);

	unuse_fake_mm();

	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
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
	MARS_INF("fd = %d\n", fd);
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	rcu_assign_pointer(fdt->fd[fd], NULL);
	spin_unlock(&files->file_lock);
}
EXPORT_SYMBOL(fd_uninstall);
#endif

static
void _mapfree_pages(struct aio_output *output, bool force)
{
	struct aio_brick *brick = output->brick;
	struct address_space *mapping;
	pgoff_t start;
	pgoff_t end;
	pgoff_t gap;

	if (brick->linear_cache_size <= 0)
		goto done;

	if (!force && ++output->rounds < brick->linear_cache_rounds)
		goto done;

	if (unlikely(!output->filp || !(mapping = output->filp->f_mapping)))
		goto done;

	if (unlikely(brick->linear_cache_rounds <= 0))
		brick->linear_cache_rounds = 1024;

	if (force) {
		start = 0;
		end = -1;
	} else {
		gap = brick->linear_cache_size * (1024 * 1024 / PAGE_SIZE);
		end = output->min_pos / PAGE_SIZE - gap;
		output->min_pos = 0;
		if (end <= 0)
			goto done;

		start = end - gap * 4;
		if (start < 0)
			start = 0;
	}

	output->rounds = 0;
	atomic_inc(&output->total_mapfree_count);

	invalidate_mapping_pages(mapping, start, end);

done:;
}

static int aio_submit_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct file *file = output->filp;
	mm_segment_t oldfs;
	int err = -EINVAL;

	CHECK_PTR_NULL(file, done);

	/* TODO: this is provisionary. We only need it for sys_io_submit()
	 * which uses userspace concepts like file handles.
	 * This should be accompanied by a future kernelsapce vfs_submit() or
	 * do_submit() which currently does not exist :(
	 * FIXME: corresponding cleanup NYI
	 */
	err = get_unused_fd();
	MARS_INF("fd = %d\n", err);
	if (unlikely(err < 0))
		goto done;
	output->fd = err;
	fd_install(err, file);

	MARS_INF("submit thread has started.\n");
	//set_user_nice(current, -20);

	use_fake_mm();

	err = -ENOMEM;
	if (unlikely(!current->mm))
		goto cleanup_fd;

	oldfs = get_fs();
	set_fs(get_ds());
	err = sys_io_setup(MARS_MAX_AIO, &output->ctxp);
	set_fs(oldfs);
	if (unlikely(err < 0))
		goto cleanup_mm;
	
	err = aio_start_thread(output, &output->tinfo[1], aio_event_thread, 'e');
	if (unlikely(err < 0))
		goto cleanup_ctxp;

	while (!brick_thread_should_stop() || atomic_read(&output->read_count) + atomic_read(&output->write_count) + atomic_read(&tinfo->queued_sum) > 0) {
		struct aio_mref_aspect *mref_a;
		struct mref_object *mref;
		int sleeptime;
		int status;

		_mapfree_pages(output, false);

		wait_event_interruptible_timeout(
			tinfo->event,
			atomic_read(&tinfo->queued_sum) > 0,
			HZ / 4);

		mref_a = _dequeue(tinfo);
		if (!mref_a) {
			continue;
		}

		mref = mref_a->object;
		status = -EINVAL;
		CHECK_PTR(mref, error);

		if (!output->min_pos || mref->ref_pos < output->min_pos)
			output->min_pos = mref->ref_pos;

		// check for reads exactly at EOF (special case)
		if (mref->ref_pos == mref->ref_total_size &&
		   !mref->ref_rw &&
		   mref->ref_timeout > 0) {
			loff_t total_size = i_size_read(file->f_mapping->host);
			loff_t len = total_size - mref->ref_pos;
			if (len > 0) {
				mref->ref_total_size = total_size;
				mref->ref_len = len;
			} else {
				if (!mref_a->start_jiffies) {
					mref_a->start_jiffies = jiffies;
				}
				if ((long long)jiffies - mref_a->start_jiffies <= mref->ref_timeout) {
					if (atomic_read(&tinfo->queued_sum) <= 0) {
						atomic_inc(&output->total_msleep_count);
						brick_msleep(1000 * 4 / HZ);
					}
					_enqueue(tinfo, mref_a, MARS_PRIO_LOW, true);
					continue;
				}
				MARS_DBG("ENODATA %lld\n", len);
				_complete(output, mref, -ENODATA);
				continue;
			}
		}

		sleeptime = 1;
		for (;;) {
			/* This is just a test. Don't enable it for performance reasons.
			 */
			if (output->brick->wait_during_fdsync && mref->ref_rw != READ) {
				if (output->fdsync_active) {
					long long delay = 60 * HZ;
					atomic_inc(&output->total_fdsync_wait_count);
					__wait_event_interruptible_timeout(
						output->fdsync_event,
						!output->fdsync_active,
						delay);
				}

			}

			/* Now really do the work
			 */
			status = aio_submit(output, mref_a, false);

			if (likely(status != -EAGAIN)) {
				break;
			}
			atomic_inc(&output->total_delay_count);
			brick_msleep(sleeptime);
			if (sleeptime < 100) {
				sleeptime++;
			}
		}
	error:
		if (unlikely(status < 0)) {
			MARS_IO("submit_count = %d status = %d\n", atomic_read(&output->submit_count), status);
			_complete(output, mref, status);
		}
	}

	MARS_INF("submit thread has stopped.\n");

	aio_stop_thread(output, 1, true);

cleanup_ctxp:
	MARS_DBG("destroying ioctx.....\n");
	oldfs = get_fs();
	set_fs(get_ds());
	sys_io_destroy(output->ctxp);
	set_fs(oldfs);
	output->ctxp = 0;

cleanup_mm:
	unuse_fake_mm();

cleanup_fd:
	MARS_DBG("destroying fd %d\n", output->fd);
	fd_uninstall(output->fd);
	put_unused_fd(output->fd);

	err = 0;

done:
	MARS_DBG("status = %d\n", err);
	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	return err;
}

static int aio_get_info(struct aio_output *output, struct mars_info *info)
{
	struct file *file = output->filp;
	if (unlikely(!file || !file->f_mapping || !file->f_mapping->host))
		return -EINVAL;

	info->current_size = i_size_read(file->f_mapping->host);
	MARS_DBG("determined file size = %lld\n", info->current_size);
	info->backing_file = file;
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
		 "total "
		 "reads = %d "
		 "writes = %d "
		 "allocs = %d "
		 "submits = %d "
		 "delays = %d "
		 "msleeps = %d "
		 "fdsyncs = %d "
		 "fdsync_waits = %d "
		 "map_free = %d | "
		 "linear_cache_size = %d "
		 "linear_cache_rounds = %d "
		 "min_pos = %lld | "
		 "flying reads = %d "
		 "writes = %d "
		 "allocs = %d "
		 "submits = %d "
		 "q0 = %d "
		 "q1 = %d "
		 "q2 = %d "
		 "| total "
		 "q0 = %d "
		 "q1 = %d "
		 "q2 = %d "
		 "%s\n",
		 atomic_read(&output->total_read_count),
		 atomic_read(&output->total_write_count),
		 atomic_read(&output->total_alloc_count),
		 atomic_read(&output->total_submit_count),
		 atomic_read(&output->total_delay_count),
		 atomic_read(&output->total_msleep_count),
		 atomic_read(&output->total_fdsync_count),
		 atomic_read(&output->total_fdsync_wait_count),
		 atomic_read(&output->total_mapfree_count),
		 brick->linear_cache_size,
		 brick->linear_cache_rounds,
		 output->min_pos,
		 atomic_read(&output->read_count),
		 atomic_read(&output->write_count),
		 atomic_read(&output->alloc_count),
		 atomic_read(&output->submit_count),
		 atomic_read(&output->tinfo[0].queued_sum),
		 atomic_read(&output->tinfo[1].queued_sum),
		 atomic_read(&output->tinfo[2].queued_sum),
		 atomic_read(&output->tinfo[0].total_enqueue_count),
		 atomic_read(&output->tinfo[1].total_enqueue_count),
		 atomic_read(&output->tinfo[2].total_enqueue_count),
		 sync ? sync : "");
	
	if (sync)
		brick_string_free(sync);

	return res;
}

static noinline
void aio_reset_statistics(struct aio_brick *brick)
{
	struct aio_output *output = brick->outputs[0];
	int i;
	atomic_set(&output->total_read_count, 0);
	atomic_set(&output->total_write_count, 0);
	atomic_set(&output->total_alloc_count, 0);
	atomic_set(&output->total_submit_count, 0);
	atomic_set(&output->total_delay_count, 0);
	atomic_set(&output->total_msleep_count, 0);
	atomic_set(&output->total_fdsync_count, 0);
	atomic_set(&output->total_fdsync_wait_count, 0);
	atomic_set(&output->total_mapfree_count, 0);
	for (i = 0; i < 3; i++) {
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		atomic_set(&tinfo->total_enqueue_count, 0);
	}
}


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
	(void)ini;
}

MARS_MAKE_STATICS(aio);

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
	int flags = O_CREAT | O_RDWR | O_LARGEFILE;
	int prot = 0600;
	mm_segment_t oldfs;
	int err = 0;

	MARS_DBG("power.button = %d\n", brick->power.button);
	if (!brick->power.button)
		goto cleanup;

	if (brick->power.led_on || output->filp)
		goto done;

	mars_power_led_off((void*)brick, false);

	if (brick->o_direct) {
		flags |= O_DIRECT;
		MARS_INF("using O_DIRECT on %s\n", path);
	}

	oldfs = get_fs();
	set_fs(get_ds());
	output->filp = filp_open(path, flags, prot);
	set_fs(oldfs);
	
	MARS_DBG("opened file '%s' flags = %d prot = %d filp = %p\n", path, flags, prot, output->filp);

	if (unlikely(!output->filp || IS_ERR(output->filp))) {
		err = PTR_ERR(output->filp);
		MARS_ERR("can't open file '%s' status=%d\n", path, err);
		output->filp = NULL;
		if (err >= 0)
			err = -ENOENT;
		return err;
	}
#if 1
	{
		struct inode *inode = output->filp->f_mapping->host;
		if (S_ISBLK(inode->i_mode)) {
			MARS_INF("changing readahead from %lu to %d\n", inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages, brick->readahead);
			inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages = brick->readahead;
		}
	}
#endif

	output->index = ++index;
	err = aio_start_thread(output, &output->tinfo[0], aio_submit_thread, 's');
	if (err < 0)
		goto err;

	MARS_INF("opened file '%s'\n", path);
	mars_power_led_on((void*)brick, true);
	MARS_DBG("successfully switched on.\n");
done:
	return 0;

err:
	MARS_ERR("status = %d\n", err);
cleanup:
	if (brick->power.led_off) {
		goto done;
	}

	mars_power_led_on((void*)brick, false);

	aio_stop_thread(output, 0, false);

	mars_power_led_off((void*)brick,
			  (output->tinfo[0].thread == NULL &&
			   output->tinfo[1].thread == NULL &&
			   output->tinfo[2].thread == NULL));

	if (brick->power.led_off) {
		if (output->filp) {
			_mapfree_pages(output, true);
			filp_close(output->filp, NULL);
			output->filp = NULL;
		}
	}
	MARS_DBG("switch off status = %d\n", err);
	return err;
}

static int aio_output_construct(struct aio_output *output)
{
	init_waitqueue_head(&output->fdsync_event);
	return 0;
}

static int aio_output_destruct(struct aio_output *output)
{
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

const struct aio_brick_type aio_brick_type = {
	.type_name = "aio_brick",
	.brick_size = sizeof(struct aio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &aio_brick_ops,
	.aspect_types = aio_aspect_types,
	.default_input_types = aio_input_types,
	.default_output_types = aio_output_types,
	.brick_construct = &aio_brick_construct,
};
EXPORT_SYMBOL_GPL(aio_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_aio(void)
{
	MARS_INF("init_aio()\n");
	_aio_brick_type = (void*)&aio_brick_type;
	return aio_register_brick_type();
}

void __exit exit_mars_aio(void)
{
	MARS_INF("exit_aio()\n");
	aio_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS aio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_aio);
module_exit(exit_mars_aio);
#endif
