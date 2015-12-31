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

#define XIO_DEBUGGING

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

#include "../xio.h"
#include "../../lib/lib_timing.h"
#include "../lib_mapfree.h"

#include "xio_aio_user.h"

/* This brick can only be used when the kernel prepatch is in place.
 */
#ifndef __USE_COMPAT

#define XIO_MAX_AIO			1024
#define XIO_MAX_AIO_READ		32

static struct timing_stats timings[3];

struct threshold aio_submit_threshold = {
	.thr_ban = &xio_global_ban,
	.thr_parent = &global_io_threshold,
	.thr_limit = AIO_SUBMIT_MAX_LATENCY,
	.thr_factor = 10,
	.thr_plus = 10000,
};

struct threshold aio_io_threshold[2] = {
	[0] = {
		.thr_ban = &xio_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = AIO_IO_R_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
	[1] = {
		.thr_ban = &xio_global_ban,
		.thr_parent = &global_io_threshold,
		.thr_limit = AIO_IO_W_MAX_LATENCY,
		.thr_factor = 100,
		.thr_plus = 0,
	},
};

struct threshold aio_sync_threshold = {
	.thr_ban = &xio_global_ban,
	.thr_limit = AIO_SYNC_MAX_LATENCY,
	.thr_factor = 100,
	.thr_plus = 0,
};

int aio_sync_mode = 2;

/************************ mmu faking (provisionary) ***********************/

/* Kludge: our kernel threads will have no mm context, but need one
 * for stuff like ioctx_alloc() / aio_setup_ring() etc
 * which expect userspace resources.
 * We fake one.
 * TODO: factor out the userspace stuff from AIO such that
 * this fake is no longer necessary.
 * Even better: replace do_mmap() in AIO stuff by something
 * more friendly to kernelspace apps.
 */
#include <linux/mmu_context.h>

struct mm_struct *mm_fake;
struct task_struct *mm_fake_task;
atomic_t mm_fake_count = ATOMIC_INIT(0);

static inline void set_fake(void)
{
	mm_fake = current->mm;
	if (mm_fake) {
		XIO_DBG("initialized fake\n");
		mm_fake_task = current;
		get_task_struct(current); /*  paired with put_task_struct() */
		atomic_inc(&mm_fake->mm_count); /*  paired with mmdrop() */
		atomic_inc(&mm_fake->mm_users); /*  paired with mmput() */
	}
}

static inline void put_fake(void)
{
	int count = 0;

	while (mm_fake && mm_fake_task) {
		int remain = atomic_read(&mm_fake_count);

		if (unlikely(remain != 0)) {
			if (count++ < 10) {
				XIO_WRN("cannot cleanup fake, remain = %d\n", remain);
				brick_msleep(1000);
				continue;
			}
			XIO_ERR("cannot cleanup fake, remain = %d\n", remain);
			break;
		} else {
			XIO_DBG("cleaning up fake\n");
			mmput(mm_fake);
			mmdrop(mm_fake);
			mm_fake = NULL;
			put_task_struct(mm_fake_task);
			mm_fake_task = NULL;
		}
	}
}

static inline void use_fake_mm(void)
{
	if (!current->mm && mm_fake) {
		atomic_inc(&mm_fake_count);
		XIO_DBG("using fake, count=%d\n", atomic_read(&mm_fake_count));
		use_mm(mm_fake);
	}
}

/* Cleanup faked mm, otherwise do_exit() will crash
 */
static inline void unuse_fake_mm(void)
{
	if (current->mm == mm_fake && mm_fake) {
		XIO_DBG("unusing fake, count=%d\n", atomic_read(&mm_fake_count));
		atomic_dec(&mm_fake_count);
		unuse_mm(mm_fake);
		current->mm = NULL;
	}
}

/************************ own type definitions ***********************/

/***************** some helpers *****************/

static inline
void _enqueue(struct aio_threadinfo *tinfo, struct aio_aio_aspect *aio_a, int prio, bool at_end)
{
	unsigned long flags;

	prio++;
	if (unlikely(prio < 0))
		prio = 0;
	else if (unlikely(prio >= XIO_PRIO_NR))
		prio = XIO_PRIO_NR - 1;

	aio_a->enqueue_stamp = cpu_clock(raw_smp_processor_id());

	spin_lock_irqsave(&tinfo->lock, flags);

	if (at_end)
		list_add_tail(&aio_a->io_head, &tinfo->aio_list[prio]);
	else
		list_add(&aio_a->io_head, &tinfo->aio_list[prio]);
	tinfo->queued[prio]++;
	atomic_inc(&tinfo->queued_sum);

	spin_unlock_irqrestore(&tinfo->lock, flags);

	atomic_inc(&tinfo->total_enqueue_count);

	wake_up_interruptible_all(&tinfo->event);
}

static inline
struct aio_aio_aspect *_dequeue(struct aio_threadinfo *tinfo)
{
	struct aio_aio_aspect *aio_a = NULL;
	int prio;
	unsigned long flags;

	spin_lock_irqsave(&tinfo->lock, flags);

	for (prio = 0; prio < XIO_PRIO_NR; prio++) {
		struct list_head *start = &tinfo->aio_list[prio];
		struct list_head *tmp = start->next;

		if (tmp != start) {
			list_del_init(tmp);
			tinfo->queued[prio]--;
			atomic_dec(&tinfo->queued_sum);
			aio_a = container_of(tmp, struct aio_aio_aspect, io_head);
			goto done;
		}
	}

done:
	spin_unlock_irqrestore(&tinfo->lock, flags);

	if (likely(aio_a && aio_a->object)) {
		unsigned long long latency;

		latency = cpu_clock(raw_smp_processor_id()) - aio_a->enqueue_stamp;
		threshold_check(&aio_io_threshold[aio_a->object->io_rw & 1], latency);
	}
	return aio_a;
}

/***************** own brick * input * output operations *****************/

static
loff_t get_total_size(struct aio_output *output)
{
	struct file *file;
	struct inode *inode;
	loff_t min;

	file = output->mf->mf_filp;
	if (unlikely(!file)) {
		XIO_ERR("file is not open\n");
		return -EILSEQ;
	}
	if (unlikely(!file->f_mapping)) {
		XIO_ERR("file %p has no mapping\n", file);
		return -EILSEQ;
	}
	inode = file->f_mapping->host;
	if (unlikely(!inode)) {
		XIO_ERR("file %p has no inode\n", file);
		return -EILSEQ;
	}

	min = i_size_read(inode);

	/* Workaround for races in the page cache.
	 * It appears that concurrent reads and writes seem to
	 * result in inconsistent reads in some very rare cases, due to
	 * races. Sometimes, the inode claims that the file has been already
	 * appended by a write operation, but the data has not actually hit
	 * the page cache, such that a concurrent read gets NULL blocks.
	 */
	if (!output->brick->is_static_device) {
		loff_t max = 0;

		mf_get_dirty(output->mf, &min, &max, 0, 99);
	}

	return min;
}

static int aio_io_get(struct aio_output *output, struct aio_object *aio)
{
	loff_t total_size;

	if (unlikely(!output->brick->power.on_led))
		return -EBADFD;

	if (unlikely(!output->mf)) {
		XIO_ERR("brick is not switched on\n");
		return -EILSEQ;
	}

	if (unlikely(aio->io_len <= 0)) {
		XIO_ERR("bad io_len=%d\n", aio->io_len);
		return -EILSEQ;
	}

	total_size = get_total_size(output);
	if (unlikely(total_size < 0))
		return total_size;
	aio->io_total_size = total_size;

	if (aio->obj_initialized) {
		obj_get(aio);
		return aio->io_len;
	}

	/* Buffered IO.
	 */
	if (!aio->io_data) {
		struct aio_aio_aspect *aio_a = aio_aio_get_aspect(output->brick, aio);

		if (unlikely(!aio_a)) {
			XIO_ERR("bad aio_a\n");
			return -EILSEQ;
		}
		if (unlikely(aio->io_len <= 0)) {
			XIO_ERR("bad io_len = %d\n", aio->io_len);
			return -ENOMEM;
		}
		aio->io_data = brick_block_alloc(aio->io_pos, (aio_a->alloc_len = aio->io_len));
		aio_a->do_dealloc = true;
		atomic_inc(&output->total_alloc_count);
		atomic_inc(&output->alloc_count);
	}

	obj_get_first(aio);
	return aio->io_len;
}

static void aio_io_put(struct aio_output *output, struct aio_object *aio)
{
	struct file *file;
	struct aio_aio_aspect *aio_a;

	if (!obj_put(aio))
		goto done;

	if (likely(output->mf)) {
		file = output->mf->mf_filp;
		if (likely(file && file->f_mapping && file->f_mapping->host))
			aio->io_total_size = get_total_size(output);
	}

	aio_a = aio_aio_get_aspect(output->brick, aio);
	if (aio_a && aio_a->do_dealloc) {
		brick_block_free(aio->io_data, aio_a->alloc_len);
		atomic_dec(&output->alloc_count);
	}
	obj_free(aio);
done:;
}

static
void _complete(struct aio_output *output, struct aio_aio_aspect *aio_a, int err)
{
	struct aio_object *aio;

	CHECK_PTR(aio_a, fatal);
	aio = aio_a->object;
	CHECK_PTR(aio, fatal);

	if (err < 0) {
		XIO_ERR("IO error %d at pos=%lld len=%d (aio=%p io_data=%p)\n",
			err,
			aio->io_pos,
			aio->io_len,
			aio,
			aio->io_data);
	} else {
		aio_checksum(aio);
		aio->io_flags |= AIO_UPTODATE;
	}

	CHECKED_CALLBACK(aio, err, err_found);

done:
	if (aio->io_rw)
		atomic_dec(&output->write_count);
	else
		atomic_dec(&output->read_count);
	mf_remove_dirty(output->mf, &aio_a->di);

	aio_io_put(output, aio);
	atomic_dec(&output->work_count);
	atomic_dec(&xio_global_io_flying);
	goto out_return;
err_found:
	XIO_FAT("giving up...\n");
	goto done;

fatal:
	XIO_FAT("bad pointer, giving up...\n");
out_return:;
}

static
void _complete_aio(struct aio_output *output, struct aio_object *aio, int err)
{
	struct aio_aio_aspect *aio_a;

	obj_check(aio);
	aio_a = aio_aio_get_aspect(output->brick, aio);
	CHECK_PTR(aio_a, fatal);
	_complete(output, aio_a, err);
	goto out_return;
fatal:
	XIO_FAT("bad pointer, giving up...\n");
out_return:;
}

static
void _complete_all(struct list_head *tmp_list, struct aio_output *output, int err)
{
	while (!list_empty(tmp_list)) {
		struct list_head *tmp = tmp_list->next;
		struct aio_aio_aspect *aio_a = container_of(tmp, struct aio_aio_aspect, io_head);

		list_del_init(tmp);
		aio_a->di.dirty_stage = 3;
		_complete(output, aio_a, err);
	}
}

static void aio_io_io(struct aio_output *output, struct aio_object *aio)
{
	struct aio_threadinfo *tinfo = &output->tinfo[0];
	struct aio_aio_aspect *aio_a;
	int err = -EINVAL;

	obj_check(aio);

	if (unlikely(!output->brick->power.on_led)) {
		SIMPLE_CALLBACK(aio, -EBADFD);
		goto out_return;
	}

	obj_get(aio);
	atomic_inc(&xio_global_io_flying);
	atomic_inc(&output->work_count);

	/*  statistics */
	if (aio->io_rw) {
		atomic_inc(&output->total_write_count);
		atomic_inc(&output->write_count);
	} else {
		atomic_inc(&output->total_read_count);
		atomic_inc(&output->read_count);
	}

	if (unlikely(!output->mf || !output->mf->mf_filp))
		goto done;

	mapfree_set(output->mf, aio->io_pos, -1);

	aio_a = aio_aio_get_aspect(output->brick, aio);
	if (unlikely(!aio_a))
		goto done;

	_enqueue(tinfo, aio_a, aio->io_prio, true);
	goto out_return;
done:
	_complete_aio(output, aio, err);
out_return:;
}

static int aio_submit(struct aio_output *output, struct aio_aio_aspect *aio_a, bool use_fdsync)
{
	struct aio_object *aio = aio_a->object;

	mm_segment_t oldfs;
	int res;

	struct iocb iocb = {
		.aio_data = (__u64)aio_a,
		.aio_lio_opcode = use_fdsync ? IOCB_CMD_FDSYNC : (aio->io_rw != 0 ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD),
		.aio_fildes = output->fd,
		.aio_buf = (unsigned long)aio->io_data,
		.aio_nbytes = aio->io_len,
		.aio_offset = aio->io_pos,
		/*  .aio_reqprio = something(aio->io_prio) field exists, but not yet implemented in kernelspace :( */
	};
	struct iocb *iocbp = &iocb;
	unsigned long long latency;

	if (unlikely(output->fd < 0)) {
		XIO_ERR("bad fd = %d\n", output->fd);
		res = -EBADF;
		goto done;
	}

	oldfs = get_fs();
	set_fs(get_ds());
	latency = TIME_STATS(&timings[aio->io_rw & 1], res = sys_io_submit(output->ctxp, 1, &iocbp));
	set_fs(oldfs);

	threshold_check(&aio_submit_threshold, latency);

	atomic_inc(&output->total_submit_count);

	if (likely(res >= 0))
		atomic_inc(&output->submit_count);
	else if (likely(res == -EAGAIN))
		atomic_inc(&output->total_again_count);
	else
		XIO_ERR("error = %d\n", res);

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

	if (likely(res >= 0))
		atomic_inc(&output->submit_count);
	return res;
}

static
int aio_start_thread(
	struct aio_output *output,
	struct aio_threadinfo *tinfo,
	int (*fn)(void *),
	char class)
{
	int j;

	for (j = 0; j < XIO_PRIO_NR; j++)
		INIT_LIST_HEAD(&tinfo->aio_list[j]);
	tinfo->output = output;
	spin_lock_init(&tinfo->lock);
	init_waitqueue_head(&tinfo->event);
	init_waitqueue_head(&tinfo->terminate_event);
	tinfo->should_terminate = false;
	tinfo->terminated = false;
	tinfo->thread = brick_thread_create(fn, tinfo, "xio_aio_user_%c%d", class, output->index);
	if (unlikely(!tinfo->thread)) {
		XIO_ERR("cannot create thread\n");
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
		XIO_DBG("stopping thread %d ...\n", i);
		tinfo->should_terminate = true;

/**/
		if (do_submit_dummy) {
			XIO_DBG("submitting dummy for wakeup %d...\n", i);
			use_fake_mm();
			aio_submit_dummy(output);
			if (likely(current->mm))
				unuse_fake_mm();
		}

		/*  wait for termination */
		XIO_DBG("waiting for thread %d ...\n", i);
		wait_event_interruptible_timeout(
			tinfo->terminate_event,
			tinfo->terminated,
			(60 - i * 2) * HZ);
		if (likely(tinfo->terminated))
			brick_thread_stop(tinfo->thread);
		else
			XIO_ERR("thread %d did not terminate - leaving a zombie\n", i);
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
	if (err < 0)
		XIO_ERR("FDSYNC error %d\n", err);

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

	XIO_DBG("sync thread has started on '%s'.\n", output->brick->brick_path);
	/* set_user_nice(current, -20); */

	while (!tinfo->should_terminate || atomic_read(&tinfo->queued_sum) > 0) {
		LIST_HEAD(tmp_list);
		unsigned long flags;
		int i;

		output->fdsync_active = false;
		wake_up_interruptible_all(&output->fdsync_event);

		wait_event_interruptible_timeout(
			tinfo->event,
			atomic_read(&tinfo->queued_sum) > 0,
			HZ / 4);

		spin_lock_irqsave(&tinfo->lock, flags);
		for (i = 0; i < XIO_PRIO_NR; i++) {
			struct list_head *start = &tinfo->aio_list[i];

			if (!list_empty(start)) {
				/*  move over the whole list */
				list_replace_init(start, &tmp_list);
				atomic_sub(tinfo->queued[i], &tinfo->queued_sum);
				tinfo->queued[i] = 0;
				break;
			}
		}
		spin_unlock_irqrestore(&tinfo->lock, flags);

		if (!list_empty(&tmp_list))
			aio_sync_all(output, &tmp_list);
	}

	XIO_DBG("sync thread has stopped.\n");
	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	return 0;
}

static int aio_event_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct aio_threadinfo *other = &output->tinfo[2];
	struct io_event *events;
	int err = -ENOMEM;

	events = brick_mem_alloc(sizeof(struct io_event) * XIO_MAX_AIO_READ);

	XIO_DBG("event thread has started.\n");

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
			.tv_sec = 1,
		};

		if (unlikely(!(void *)output->ctxp)) {
			XIO_ERR("Oops, context vanished. queued_sum = %d\n", atomic_read(&tinfo->queued_sum));
			break;
		}

		oldfs = get_fs();
		set_fs(get_ds());
		/* TODO: don't timeout upon termination.
		 * Probably we should submit a dummy request.
		 */
		count = sys_io_getevents(output->ctxp, 1, XIO_MAX_AIO_READ, events, &timeout);
		set_fs(oldfs);

		if (likely(count > 0))
			atomic_sub(count, &output->submit_count);

		for (i = 0; i < count; i++) {
			struct aio_aio_aspect *aio_a = (void *)events[i].data;
			struct aio_object *aio;
			int err = events[i].res;

			if (!aio_a)
				continue; /*  this was a dummy request */

			aio_a->di.dirty_stage = 2;
			aio = aio_a->object;

			mapfree_set(output->mf, aio->io_pos, aio->io_pos + aio->io_len);

			if (output->brick->o_fdsync
			   && err >= 0
			   && aio->io_rw != READ
			   && !aio->io_skip_sync
			   && !aio_a->resubmit++) {
				/*  workaround for non-implemented AIO FSYNC operation */
				if (output->mf &&
				    output->mf->mf_filp &&
				    output->mf->mf_filp->f_op &&
				    !output->mf->mf_filp->f_op->aio_fsync) {
					_enqueue(other, aio_a, aio->io_prio, true);
					continue;
				}
				err = aio_submit(output, aio_a, true);
				if (likely(err >= 0))
					continue;
			}

			aio_a->di.dirty_stage = 3;
			_complete(output, aio_a, err);

		}
	}
	err = 0;

err:
	XIO_DBG("event thread has stopped, err = %d\n", err);

	aio_stop_thread(output, 2, false);

	unuse_fake_mm();

	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	brick_mem_free(events);
	return err;
}

#if 1
/* Workaround
 */
#include <linux/fdtable.h>
void fd_uninstall(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	unsigned long flags;

	XIO_DBG("fd = %d\n", fd);
	if (unlikely(fd < 0)) {
		XIO_ERR("bad fd = %d\n", fd);
		goto out_return;
	}
	spin_lock_irqsave(&files->file_lock, flags);
	fdt = files_fdtable(files);
	rcu_assign_pointer(fdt->fd[fd], NULL);
	spin_unlock_irqrestore(&files->file_lock, flags);
out_return:;
}
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

		XIO_DBG("ioctx count = %d destroying %p\n", atomic_read(&ioctx_count), (void *)output->ctxp);
		oldfs = get_fs();
		set_fs(get_ds());
		err = sys_io_destroy(output->ctxp);
		set_fs(oldfs);
		atomic_dec(&ioctx_count);
		XIO_DBG("ioctx count = %d status = %d\n", atomic_read(&ioctx_count), err);
		output->ctxp = 0;
	}

	if (likely(output->fd >= 0)) {
		XIO_DBG("destroying fd %d\n", output->fd);
		fd_uninstall(output->fd);
		put_unused_fd(output->fd);
		output->fd = -1;
	}

done:
	if (likely(current->mm))
		unuse_fake_mm();
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
#ifdef get_unused_fd /*  see f938612dd97d481b8b5bf960c992ae577f081c17 */
	err = get_unused_fd();
#else
	err = get_unused_fd_flags(0);
#endif
	XIO_DBG("file %p '%s' new fd = %d\n", file, output->mf->mf_name, err);
	if (unlikely(err < 0)) {
		XIO_ERR("cannot get fd, err=%d\n", err);
		goto done;
	}
	output->fd = err;
	fd_install(err, file);

	use_fake_mm();

	err = -ENOMEM;
	if (unlikely(!current->mm)) {
		XIO_ERR("cannot fake mm\n");
		goto done;
	}

	XIO_DBG("ioctx count = %d old = %p\n", atomic_read(&ioctx_count), (void *)output->ctxp);
	output->ctxp = 0;

	oldfs = get_fs();
	set_fs(get_ds());
	err = sys_io_setup(XIO_MAX_AIO, &output->ctxp);
	set_fs(oldfs);
	if (likely(output->ctxp))
		atomic_inc(&ioctx_count);
	XIO_DBG("ioctx count = %d new = %p status = %d\n", atomic_read(&ioctx_count), (void *)output->ctxp, err);
	if (unlikely(err < 0)) {
		XIO_ERR("io_setup failed, err=%d\n", err);
		goto done;
	}

	err = aio_start_thread(output, &output->tinfo[1], aio_event_thread, 'e');
	if (unlikely(err < 0)) {
		XIO_ERR("could not start event thread\n");
		goto done;
	}

done:
	if (likely(current->mm))
		unuse_fake_mm();
	return err;
}

static int aio_submit_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct file *file;
	int err = -EINVAL;

	XIO_DBG("submit thread has started.\n");

	file = output->mf->mf_filp;

	use_fake_mm();

	while (!tinfo->should_terminate || atomic_read(&output->read_count) + atomic_read(&output->write_count) + atomic_read(&tinfo->queued_sum) > 0) {
		struct aio_aio_aspect *aio_a;
		struct aio_object *aio;
		int sleeptime;
		int status;

		wait_event_interruptible_timeout(
			tinfo->event,
			atomic_read(&tinfo->queued_sum) > 0,
			HZ / 4);

		aio_a = _dequeue(tinfo);
		if (!aio_a)
			continue;

		aio = aio_a->object;
		status = -EINVAL;
		CHECK_PTR(aio, error);

		mapfree_set(output->mf, aio->io_pos, -1);

		aio_a->di.dirty_stage = 0;
		if (aio->io_rw)
			mf_insert_dirty(output->mf, &aio_a->di);

		aio->io_total_size = get_total_size(output);

		/*  check for reads crossing the EOF boundary (special case) */
		if (aio->io_timeout > 0 &&
		    !aio->io_rw &&
		    aio->io_pos + aio->io_len > aio->io_total_size) {
			loff_t len = aio->io_total_size - aio->io_pos;

			if (len > 0) {
				if (aio->io_len > len)
					aio->io_len = len;
			} else {
				if (!aio_a->start_jiffies)
					aio_a->start_jiffies = jiffies;
				if ((long long)jiffies - aio_a->start_jiffies <= aio->io_timeout) {
					if (atomic_read(&tinfo->queued_sum) <= 0) {
						atomic_inc(&output->total_msleep_count);
						brick_msleep(1000 * 4 / HZ);
					}
					_enqueue(tinfo, aio_a, XIO_PRIO_LOW, true);
					continue;
				}
				XIO_DBG("ENODATA %lld\n", len);
				_complete(output, aio_a, -ENODATA);
				continue;
			}
		}

		sleeptime = 1;
		for (;;) {
			aio_a->di.dirty_stage = 1;
			status = aio_submit(output, aio_a, false);

			if (likely(status != -EAGAIN))
				break;
			aio_a->di.dirty_stage = 0;
			atomic_inc(&output->total_delay_count);
			brick_msleep(sleeptime);
			if (sleeptime < 100)
				sleeptime++;
		}

error:
		if (unlikely(status < 0))
			_complete_aio(output, aio, status);
	}

	XIO_DBG("submit thread has stopped, status = %d.\n", err);

	if (likely(current->mm))
		unuse_fake_mm();

	tinfo->terminated = true;
	wake_up_interruptible_all(&tinfo->terminate_event);
	return err;
}

static int aio_get_info(struct aio_output *output, struct xio_info *info)
{
	struct file *file;

	if (unlikely(!output || !output->mf))
		return -EINVAL;
	file = output->mf->mf_filp;
	if (unlikely(!file || !file->f_mapping || !file->f_mapping->host))
		return -EINVAL;

	info->tf_align = 1;
	info->tf_min_size = 1;
	info->current_size = get_total_size(output);

	XIO_DBG("determined file size = %lld\n", info->current_size);

	return 0;
}

/*************** informational * statistics **************/

static noinline
char *aio_statistics(struct aio_brick *brick, int verbose)
{
	struct aio_output *output = brick->outputs[0];
	char *res = brick_string_alloc(4096);
	char *sync = NULL;
	int pos = 0;

	pos += report_timing(&timings[0], res + pos, 4096 - pos);
	pos += report_timing(&timings[1], res + pos, 4096 - pos);
	pos += report_timing(&timings[2], res + pos, 4096 - pos);

	snprintf(res + pos, 4096 - pos,
		 "total reads = %d writes = %d allocs = %d submits = %d again = %d delays = %d msleeps = %d fdsyncs = %d fdsync_waits = %d map_free = %d | flying reads = %d writes = %d allocs = %d submits = %d q0 = %d q1 = %d q2 = %d | total q0 = %d q1 = %d q2 = %d %s\n",
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

/*************** object * aspect constructors * destructors **************/

static int aio_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct aio_aio_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->io_head);
	INIT_LIST_HEAD(&ini->di.dirty_head);
	ini->di.dirty_aio = ini->object;
	return 0;
}

static void aio_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct aio_aio_aspect *ini = (void *)_ini;

	CHECK_HEAD_EMPTY(&ini->di.dirty_head);
	CHECK_HEAD_EMPTY(&ini->io_head);
}

XIO_MAKE_STATICS(aio);

/********************* brick constructors * destructors *******************/

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

	XIO_DBG("power.button = %d\n", brick->power.button);
	if (!brick->power.button)
		goto cleanup;

	if (brick->power.on_led || output->mf)
		goto done;

	xio_set_power_off_led((void *)brick, false);

	if (brick->o_creat) {
		flags |= O_CREAT;
		XIO_DBG("using O_CREAT on %s\n", path);
	}
	if (brick->o_direct) {
		flags |= O_DIRECT;
		XIO_DBG("using O_DIRECT on %s\n", path);
	}

	output->mf = mapfree_get(path, flags);
	if (unlikely(!output->mf)) {
		XIO_ERR("could not open file = '%s' flags = %d\n", path, flags);
		status = -ENOENT;
		goto err;
	}

	output->index = ++index;

	status = _create_ioctx(output);
	if (unlikely(status < 0)) {
		XIO_ERR("could not create ioctx, status = %d\n", status);
		goto err;
	}

	status = aio_start_thread(output, &output->tinfo[0], aio_submit_thread, 's');
	if (unlikely(status < 0)) {
		XIO_ERR("could not start theads, status = %d\n", status);
		goto err;
	}

	XIO_DBG("opened file '%s'\n", path);
	brick->mode_ptr = &output->mf->mf_mode;
	xio_set_power_on_led((void *)brick, true);

done:
	return 0;

err:
	XIO_ERR("status = %d\n", status);
cleanup:
	if (brick->power.off_led)
		goto done;

	xio_set_power_on_led((void *)brick, false);

	for (;;) {
		int count = atomic_read(&output->work_count);

		if (count <= 0)
			break;
		XIO_DBG("working on %d requests\n", count);
		brick_msleep(1000);
	}

	aio_stop_thread(output, 0, false);

	brick->mode_ptr = NULL;

	_destroy_ioctx(output);

	xio_set_power_off_led((void *)brick,
			  (output->tinfo[0].thread == NULL &&
			   output->tinfo[1].thread == NULL &&
			   output->tinfo[2].thread == NULL));

	XIO_DBG("switch off off_led = %d status = %d\n", brick->power.off_led, status);
	if (brick->power.off_led) {
		if (output->mf) {
			XIO_DBG("closing file = '%s'\n", output->mf->mf_name);
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
	if (unlikely(output->fd >= 0))
		XIO_ERR("active fd = %d detected\n", output->fd);
	return 0;
}

/************************ static structs ***********************/

static struct aio_brick_ops aio_brick_ops = {
	.brick_switch = aio_switch,
	.brick_statistics = aio_statistics,
	.reset_statistics = aio_reset_statistics,
};

static struct aio_output_ops aio_output_ops = {
	.aio_get = aio_io_get,
	.aio_put = aio_io_put,
	.aio_io = aio_io_io,
	.xio_get_info = aio_get_info,
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

/***************** module init stuff ************************/

int __init init_xio_aio(void)
{
	XIO_DBG("init_aio()\n");
	_aio_brick_type = (void *)&aio_brick_type;
	set_fake();
	return aio_register_brick_type();
}

void exit_xio_aio(void)
{
	XIO_DBG("exit_aio()\n");
	put_fake();
	aio_unregister_brick_type();
}

#endif
