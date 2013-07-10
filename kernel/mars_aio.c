// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

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

int aio_sync_mode = 1;
EXPORT_SYMBOL_GPL(aio_sync_mode);

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

////////////////// dirty IOs on the fly  //////////////////

static inline
void insert_dirty(struct aio_output *output, struct aio_mref_aspect *mref_a)
{
	unsigned long flags = 0;

	traced_lock(&output->dirty_lock, flags);
	list_del(&mref_a->dirty_head);
	list_add(&mref_a->dirty_head, &output->dirty_anchor);
	traced_unlock(&output->dirty_lock, flags);
}

static inline
void remove_dirty(struct aio_output *output, struct aio_mref_aspect *mref_a)
{
	if (!list_empty(&mref_a->dirty_head)) {
		unsigned long flags = 0;

		traced_lock(&output->dirty_lock, flags);
		list_del_init(&mref_a->dirty_head);
		traced_unlock(&output->dirty_lock, flags);
	}
}

static inline
void get_dirty(struct aio_output *output, loff_t *min, loff_t *max)
{
	struct list_head *tmp;
	unsigned long flags = 0;

	traced_lock(&output->dirty_lock, flags);
	for (tmp = output->dirty_anchor.next; tmp != &output->dirty_anchor; tmp = tmp->next) {
		struct aio_mref_aspect *mref_a = container_of(tmp, struct aio_mref_aspect, dirty_head);
		struct mref_object *mref = mref_a->object;
		if (mref->ref_pos < *min) {
			*min = mref->ref_pos;
		}
		if (mref->ref_pos + mref->ref_len > *max) {
			*max = mref->ref_pos + mref->ref_len;
		}
	}
	traced_unlock(&output->dirty_lock, flags);
}

////////////////// own brick / input / output operations //////////////////

static int aio_ref_get(struct aio_output *output, struct mref_object *mref)
{
	struct file *file;
	struct inode *inode;
	loff_t total_size;

	if (unlikely(!output->mf)) {
		MARS_ERR("brick is not switched on\n");
		return -EILSEQ;
	}

	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("bad ref_len=%d\n", mref->ref_len);
		return -EILSEQ;
	}

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	file = output->mf->mf_filp;
	if (unlikely(!file)) {
		MARS_ERR("file is not open\n");
		return -EILSEQ;
	}
	if (unlikely(!file->f_mapping)) {
		MARS_ERR("file %p has no mapping\n", file);
		return -EILSEQ;
	}
	inode = file->f_mapping->host;
	if (unlikely(!inode)) {
		MARS_ERR("file %p has no inode\n", file);
		return -EILSEQ;
	}
	
	total_size = i_size_read(inode);
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
	struct file *file;
	struct aio_mref_aspect *mref_a;

	if (!_mref_put(mref)) {
		goto done;
	}

	if (output->mf && (file = output->mf->mf_filp) && file->f_mapping && file->f_mapping->host) {
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
void _complete(struct aio_output *output, struct aio_mref_aspect *mref_a, int err)
{
	struct mref_object *mref;

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

	CHECKED_CALLBACK(mref, err, err_found);

done:
	if (mref->ref_rw) {
		atomic_dec(&output->write_count);
	} else {
		atomic_dec(&output->read_count);
	}

	remove_dirty(output, mref_a);

	aio_ref_put(output, mref);
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

	if (unlikely(!output->mf || !output->mf->mf_filp)) {
		goto done;
	}

	mapfree_set(output->mf, mref->ref_pos, -1);

	MARS_IO("AIO rw=%d pos=%lld len=%d data=%p\n", mref->ref_rw, mref->ref_pos, mref->ref_len, mref->ref_data);

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

	if (unlikely(output->fd < 0)) {
		MARS_ERR("bad fd = %d\n", output->fd);
		res = -EBADF;
		goto done;
	}

	oldfs = get_fs();
	set_fs(get_ds());
	latency = TIME_STATS(&timings[mref->ref_rw & 1], res = sys_io_submit(output->ctxp, 1, &iocbp));
	set_fs(oldfs);

	threshold_check(&aio_submit_threshold, latency);

	atomic_inc(&output->total_submit_count);

	if (likely(res >= 0)) {
		atomic_inc(&output->submit_count);
	} else if (likely(res == -EAGAIN)) {
		atomic_inc(&output->total_again_count);
	} else {
		MARS_ERR("error = %d\n", res);
	}

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
		MARS_DBG("stopping thread %d ...\n", i);
		brick_thread_stop_nowait(tinfo->thread);

		// workaround for waking up the receiver thread. TODO: check whether signal handlong could do better.
		if (do_submit_dummy) {
			MARS_DBG("submitting dummy for wakeup %d...\n", i);
			use_fake_mm();
			aio_submit_dummy(output);
			if (likely(current->mm)) {
				unuse_fake_mm();
			}
		}

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
	atomic_inc(&output->total_fdsync_count);
	
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
	struct aio_threadinfo *other = &output->tinfo[2];
	int err = -ENOMEM;
	
	MARS_DBG("event thread has started.\n");
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

		for (i = 0; i < count; i++) {
			struct aio_mref_aspect *mref_a = (void*)events[i].data;
			struct mref_object *mref;
			int err = events[i].res;

			if (!mref_a) {
				continue; // this was a dummy request
			}
			mref = mref_a->object;

			MARS_IO("AIO done %p pos = %lld len = %d rw = %d\n", mref, mref->ref_pos, mref->ref_len, mref->ref_rw);

			mapfree_set(output->mf, mref->ref_pos, mref->ref_pos + mref->ref_len);

			if (output->brick->o_fdsync
			   && err >= 0 
			   && mref->ref_rw != READ
			   && !mref->ref_skip_sync
			   && !mref_a->resubmit++) {
				// workaround for non-implemented AIO FSYNC operation
				if (output->mf &&
				    output->mf->mf_filp &&
				    output->mf->mf_filp->f_op &&
				    !output->mf->mf_filp->f_op->aio_fsync) {
					mars_trace(mref, "aio_fsync");
					_enqueue(other, mref_a, mref->ref_prio, true);
					continue;
				}
				err = aio_submit(output, mref_a, true);
				if (likely(err >= 0))
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
	MARS_DBG("fd = %d\n", fd);
	if (unlikely(fd < 0)) {
		MARS_ERR("bad fd = %d\n", fd);
		return;
	}
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	rcu_assign_pointer(fdt->fd[fd], NULL);
	spin_unlock(&files->file_lock);
}
EXPORT_SYMBOL(fd_uninstall);
#endif

static
atomic_t ioctx_count = ATOMIC_INIT(0);

static
void _destroy_ioctx(struct aio_output *output)
{
	if (unlikely(!output))
		goto done;

	aio_stop_thread(output, 1, true);

	use_fake_mm();

	if (likely(output->ctxp)) {
		mm_segment_t oldfs;
		int err;

		MARS_DBG("ioctx count = %d destroying %p\n", atomic_read(&ioctx_count), (void*)output->ctxp);
		oldfs = get_fs();
		set_fs(get_ds());
		err = sys_io_destroy(output->ctxp);
		set_fs(oldfs);
		atomic_dec(&ioctx_count);
		MARS_DBG("ioctx count = %d status = %d\n", atomic_read(&ioctx_count), err);
		output->ctxp = 0;
	}

	if (likely(output->fd >= 0)) {
		MARS_DBG("destroying fd %d\n", output->fd);
		fd_uninstall(output->fd);
		put_unused_fd(output->fd);
		output->fd = -1;
	}

 done:
	if (likely(current->mm)) {
		unuse_fake_mm();
	}
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

	/* TODO: this is provisionary. We only need it for sys_io_submit()
	 * which uses userspace concepts like file handles.
	 * This should be accompanied by a future kernelsapce vfs_submit() or
	 * do_submit() which currently does not exist :(
	 */
	err = get_unused_fd();
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

	MARS_DBG("ioctx count = %d old = %p\n", atomic_read(&ioctx_count), (void*)output->ctxp);
	output->ctxp = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	err = sys_io_setup(MARS_MAX_AIO, &output->ctxp);
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

	while (!brick_thread_should_stop() || atomic_read(&output->read_count) + atomic_read(&output->write_count) + atomic_read(&tinfo->queued_sum) > 0) {
		struct aio_mref_aspect *mref_a;
		struct mref_object *mref;
		int sleeptime;
		int status;

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

		mapfree_set(output->mf, mref->ref_pos, -1);

		if (mref->ref_rw) {
			insert_dirty(output, mref_a);
		}

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
				_complete(output, mref_a, -ENODATA);
				continue;
			}
		}

		sleeptime = 1;
		for (;;) {
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
	loff_t min;
	loff_t max;

	if (unlikely(!output ||
		     !output->mf ||
		     !(file = output->mf->mf_filp) ||
		     !file->f_mapping ||
		     !file->f_mapping->host))
		return -EINVAL;

	info->tf_align = 1;
	info->tf_min_size = 1;

	/* Workaround for races in the page cache.
	 *
	 * It appears that concurrent reads and writes seem to
	 * result in inconsistent reads in some very rare cases, due to
	 * races. Sometimes, the inode claims that the file has been already
	 * appended by a write operation, but the data has not actually hit
	 * the page cache, such that a concurrent read gets NULL blocks.
	 */
	min = i_size_read(file->f_mapping->host);
	max = 0;

	if (!output->brick->is_static_device) {
		get_dirty(output, &min, &max);
	}

	info->current_size = min;
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
		 atomic_read(&output->total_again_count),
		 atomic_read(&output->total_delay_count),
		 atomic_read(&output->total_msleep_count),
		 atomic_read(&output->total_fdsync_count),
		 atomic_read(&output->total_fdsync_wait_count),
		 atomic_read(&output->total_mapfree_count),
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
}


//////////////// object / aspect constructors / destructors ///////////////

static int aio_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct aio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	INIT_LIST_HEAD(&ini->dirty_head);
	return 0;
}

static void aio_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct aio_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->dirty_head);
	CHECK_HEAD_EMPTY(&ini->io_head);
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
	int flags = O_RDWR | O_LARGEFILE;
	int status = 0;

	MARS_DBG("power.button = %d\n", brick->power.button);
	if (!brick->power.button)
		goto cleanup;

	if (brick->power.led_on || output->mf)
		goto done;

	mars_power_led_off((void*)brick, false);

	if (brick->o_creat) {
		flags |= O_CREAT;
		MARS_DBG("using O_CREAT on %s\n", path);
	}
	if (brick->o_direct) {
		flags |= O_DIRECT;
		MARS_DBG("using O_DIRECT on %s\n", path);
	}

	output->mf = mapfree_get(path, flags);
	if (unlikely(!output->mf)) {
		MARS_ERR("could not open file = '%s' flags = %d\n", path, flags);
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

	aio_stop_thread(output, 0, false);

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
	INIT_LIST_HEAD(&output->dirty_anchor);
	spin_lock_init(&output->dirty_lock);
	init_waitqueue_head(&output->fdsync_event);
	output->fd = -1;
	return 0;
}

static int aio_output_destruct(struct aio_output *output)
{
	CHECK_HEAD_EMPTY(&output->dirty_anchor);
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
	MARS_DBG("init_aio()\n");
	_aio_brick_type = (void*)&aio_brick_type;
	return aio_register_brick_type();
}

void __exit exit_mars_aio(void)
{
	MARS_DBG("exit_aio()\n");
	aio_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS aio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_aio);
module_exit(exit_mars_aio);
#endif
