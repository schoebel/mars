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
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#define USE_VFS_READ
#define USE_VFS_WRITE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/splice.h>

#include "brick_wait.h"
#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_sio.h"

////////////////// own brick / input / output operations //////////////////

static int sio_ref_get(struct sio_output *output, struct mref_object *mref)
{
	struct file *file;

	if (unlikely(!output->brick->power.led_on))
		return -EBADFD;

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	file = output->mf->mf_filp;
	if (file) {
		loff_t total_size = i_size_read(file->f_mapping->host);
		mref->ref_total_size = total_size;
		/* Only check reads.
		 * Writes behind EOF are always allowed (sparse files)
		 */
		if (!(mref->ref_flags & MREF_MAY_WRITE)) {
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
		struct sio_mref_aspect *mref_a = sio_mref_get_aspect(output->brick, mref);
		if (unlikely(!mref_a))
			return -EILSEQ;
		if (unlikely(mref->ref_len <= 0)) {
			MARS_ERR("bad ref_len = %d\n", mref->ref_len);
			return -EBADR;
		}
		mref_a->alloc_len = mref->ref_len;
		mref->ref_data = brick_block_alloc(mref->ref_pos, mref->ref_len);
		mref_a->do_dealloc = true;
		//atomic_inc(&output->total_alloc_count);
		//atomic_inc(&output->alloc_count);
	}

	_mref_get_first(mref);
	return mref->ref_len;
}

static void sio_ref_put(struct sio_output *output, struct mref_object *mref)
{
	struct file *file;
	struct sio_mref_aspect *mref_a;

	if (!_mref_put(mref))
		return;

	file = output->mf->mf_filp;
	mref->ref_total_size = i_size_read(file->f_mapping->host);

	mref_a = sio_mref_get_aspect(output->brick, mref);
	if (mref_a && mref_a->do_dealloc) {
		brick_block_free(mref->ref_data, mref_a->alloc_len);
		//atomic_dec(&output->alloc_count);
	}

	sio_free_mref(mref);
}

#ifndef MARS_HAS_KERNEL_READ
// some code borrowed from the loopback driver

static int transfer_none(int cmd,
			 struct page *raw_page, unsigned raw_off,
			 void *loop_buf,
			 int size)
{
	void *raw_buf;

	if (unlikely(!raw_page || !loop_buf)) {
		MARS_ERR("transfer NULL: %p %p\n", raw_buf, loop_buf);
		return -EFAULT;
	}

	raw_buf = page_address(raw_page) + raw_off;

	if (cmd == READ)
		memcpy(loop_buf, raw_buf, size);
	else
		memcpy(raw_buf, loop_buf, size);

	brick_yield();
	return 0;
}
#endif

static
int write_aops(struct sio_output *output, struct mref_object *mref)
{
	struct file *file = output->mf->mf_filp;
	loff_t pos = mref->ref_pos;
	void *data = mref->ref_data;
	int  len = mref->ref_len;
	int ret = 0;

#ifdef MARS_HAS_KERNEL_READ
	ret = kernel_write(file,
			   data,
			   len,
			   &pos);
#else
#ifdef USE_VFS_WRITE
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_write(file, data, len, &pos);
	set_fs(oldfs);
#else
	unsigned offset;
	struct address_space *mapping;

	if (unlikely(!file)) {
		MARS_FAT("No FILE\n");
		return -ENXIO;
	}
	mapping = file->f_mapping;

	mutex_lock(&mapping->host->i_mutex);
		
	offset = pos & ((pgoff_t)PAGE_CACHE_SIZE - 1);
	
	while (len > 0) {
		int transfer_result;
		unsigned size, copied;
		struct page *page = NULL;
		void *fsdata;

		size = PAGE_CACHE_SIZE - offset;
		if (size > len)
			size = len;

		ret = pagecache_write_begin(file, mapping, pos, size, 0,
					    &page, &fsdata);
		if (ret) {
			MARS_ERR("cannot start pagecache_write_begin() error=%d\n", ret);
			if (ret >= 0)
				ret = -EINVAL;
			goto fail;
		}

		//file_update_time(file);

		transfer_result = transfer_none(WRITE, page, offset, data, size);

		copied = size;
		if (transfer_result) {
			MARS_ERR("transfer error %d\n", transfer_result);
			copied = 0;
		}

		ret = pagecache_write_end(file, mapping, pos, size, copied,
					  page, fsdata);
		if (ret < 0 || ret != copied || transfer_result) {
			MARS_ERR("write error %d\n", ret);
			if (ret >= 0)
				ret = -EINVAL;
			goto fail;
		}
		
		len -= copied;
		offset = 0;
		pos += copied;
		data += copied;
	}
	ret = 0;
	
fail:
	mutex_unlock(&mapping->host->i_mutex);

#if 1
	blk_run_address_space(mapping);
#endif
#endif
#endif
	return ret;
}

struct cookie_data {
	struct sio_output *output;
	struct mref_object *mref;
};

#ifndef MARS_HAS_KERNEL_READ
static int
sio_splice_actor(struct pipe_inode_info *pipe,
			struct pipe_buffer *buf,
			struct splice_desc *sd)
{
	struct cookie_data *cookie = sd->u.data;
	struct mref_object *mref = cookie->mref;
	struct page *page = buf->page;
	void *data;
	int size, ret;

	ret = buf->ops->confirm(pipe, buf);
	if (unlikely(ret))
		return ret;

	size = sd->len;
	if (size > mref->ref_len)
		size = mref->ref_len;

	data = mref->ref_data;
	if (transfer_none(READ, page, buf->offset, data, size)) {
		MARS_ERR("transfer error\n");
		size = -EINVAL;
	}

	//flush_dcache_page(p->bvec->bv_page);

	return size;
}

static int
sio_direct_splice_actor(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	return __splice_from_pipe(pipe, sd, sio_splice_actor);
}
#endif

static 
int read_aops(struct sio_output *output, struct mref_object *mref)
{
	loff_t pos = mref->ref_pos;
	int len = mref->ref_len;
	int ret;

#ifdef MARS_HAS_KERNEL_READ
	ret = kernel_read(output->mf->mf_filp,
			  mref->ref_data,
			  len,
			  &pos);
#else
#ifdef USE_VFS_READ
	mm_segment_t oldfs;
	(void) sio_direct_splice_actor; // shut up gcc

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_read(output->mf->mf_filp, mref->ref_data, len, &pos);
	set_fs(oldfs);
#else
	struct cookie_data cookie = {
		.output = output,
		.mref = mref,
	};
	struct splice_desc sd = {
		.len = 0,
		.total_len = len,
		.flags = 0,
		.pos = pos,
		.u.data = &cookie,
	};

	ret = splice_direct_to_actor(output->mf->mf_filp, &sd, sio_direct_splice_actor);
#endif
#endif

	if (unlikely(ret < 0)) {
		MARS_ERR("%p %p status=%d\n", output, mref, ret);
	}
	return ret;
}

static void sync_file(struct sio_output *output)
{
	struct file *file = output->mf->mf_filp;
	int ret;
#if defined(S_BIAS) || (defined(RHEL_MAJOR) && (RHEL_MAJOR < 7))
	ret = vfs_fsync(file, file->f_path.dentry, 1);
#else
	ret = vfs_fsync(file, 1);
#endif
	if (unlikely(ret)) {
		MARS_ERR("syncing pages failed: %d\n", ret);
	}
	return;
}

static
void _complete(struct sio_output *output, struct mref_object *mref, int err)
{
	_mref_check(mref);

	mars_trace(mref, "sio_endio");

	if (err < 0) {
		MARS_ERR("IO error %d at pos=%lld len=%d (mref=%p ref_data=%p)\n", err, mref->ref_pos, mref->ref_len, mref, mref->ref_data);
	} else {
		mref_checksum(mref);
		mref->ref_flags |= MREF_UPTODATE;
	}

#ifdef CONFIG_MARS_DEBUG
	while (mars_hang_mode & 1)
		brick_msleep(100);
#endif

	CHECKED_CALLBACK(mref, err, err_found);

done:
#if 0
	if (mref->ref_flags & MREF_WRITE) {
		atomic_dec(&output->write_count);
	} else {
		atomic_dec(&output->read_count);
	}
#endif
	sio_ref_put(output, mref);

	atomic_dec(&output->work_count);
	atomic_dec(&mars_global_io_flying);
	return;

err_found:
	MARS_FAT("giving up...\n");
	goto done;
}

/* This is called by the threads
 */
static
void _sio_ref_io(struct sio_threadinfo *tinfo, struct mref_object *mref)
{
	struct sio_output *output = tinfo->output;
	bool barrier = false;
	int status;

	_mref_check(mref);

	atomic_inc(&tinfo->fly_count);

	if (unlikely(!output->mf || !output->mf->mf_filp)) {
		status = -EINVAL;
		goto done;
	}

	if (barrier) {
		MARS_INF("got barrier request\n");
		sync_file(output);
	}

	if (!(mref->ref_flags & MREF_WRITE)) {
		status = read_aops(output, mref);
	} else {
		mf_dirty_append(output->mf, DIRTY_SUBMITTED,
				mref->ref_pos + mref->ref_len);
		status = write_aops(output, mref);
		if (status >= 0) {
			if (barrier || output->brick->o_fdsync)
				sync_file(output);
			mf_dirty_append(output->mf, DIRTY_COMPLETING,
					mref->ref_pos + mref->ref_len);
		}
	}

	mapfree_set(output->mf, mref->ref_pos, mref->ref_pos + mref->ref_len);

done:
	if ((mref->ref_flags & MREF_WRITE) && status >= 0)
		mf_dirty_append(output->mf,
				DIRTY_FINISHED,
				mref->ref_pos + mref->ref_len);

	_complete(output, mref, status);

	atomic_dec(&tinfo->fly_count);
}

/* This is called from outside
 */
static
void sio_ref_io(struct sio_output *output, struct mref_object *mref)
{
	int index;
	struct sio_threadinfo *tinfo;
	struct sio_mref_aspect *mref_a;
	unsigned long flags;

	_mref_check(mref);

	mref_a = sio_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		SIMPLE_CALLBACK(mref, -EINVAL);
		return;
	}

	if (unlikely(!output->brick->power.led_on)) {
		SIMPLE_CALLBACK(mref, -EBADFD);
		return;
	}

	atomic_inc(&mars_global_io_flying);
	atomic_inc(&output->work_count);
	_mref_get(mref);

	mapfree_set(output->mf, mref->ref_pos, -1);

	index = 0;
	if (!(mref->ref_flags & MREF_WRITE)) {
		traced_lock(&output->g_lock, flags);
		index = output->index++;
		traced_unlock(&output->g_lock, flags);
		index = (index % WITH_THREAD) + 1;
	}

	tinfo = &output->tinfo[index];
	MARS_IO("queueing %p on %d\n", mref, index);

	atomic_inc(&tinfo->total_count);
	atomic_inc(&tinfo->queue_count);

	traced_lock(&tinfo->lock, flags);
	list_add_tail(&mref_a->io_head, &tinfo->mref_list);
	traced_unlock(&tinfo->lock, flags);

	brick_wake_smp(&tinfo->event);
}

static int sio_thread(void *data)
{
	struct sio_threadinfo *tinfo = data;
	
	MARS_INF("sio thread has started.\n");
	//set_user_nice(current, -20);

	while (!brick_thread_should_stop()) {
		struct list_head *tmp = NULL;
		struct mref_object *mref;
		struct sio_mref_aspect *mref_a;
		unsigned long flags;

		brick_wait_smp(
			tinfo->event,
			!list_empty(&tinfo->mref_list) || brick_thread_should_stop(),
			HZ);

		tinfo->last_jiffies = jiffies;

		traced_lock(&tinfo->lock, flags);
		
		if (!list_empty(&tinfo->mref_list)) {
			tmp = tinfo->mref_list.next;
			list_del_init(tmp);
			atomic_dec(&tinfo->queue_count);
		}

		traced_unlock(&tinfo->lock, flags);

		if (!tmp)
			continue;

		mref_a = container_of(tmp, struct sio_mref_aspect, io_head);
		mref = mref_a->object;
		MARS_IO("got %p %p\n", mref_a, mref);
		_sio_ref_io(tinfo, mref);
	}

	MARS_INF("sio thread has stopped.\n");
	return 0;
}

static int sio_get_info(struct sio_output *output, struct mars_info *info)
{
	struct file *file = output->mf->mf_filp;
	if (unlikely(!file || !file->f_mapping || !file->f_mapping->host))
		return -EINVAL;

	info->tf_align = 1;
	info->tf_min_size = 1;
	info->current_size = i_size_read(file->f_mapping->host);
	MARS_DBG("determined file size = %lld\n", info->current_size);
	return 0;
}

//////////////// informational / statistics ///////////////

static noinline
char *sio_statistics(struct sio_brick *brick, int verbose)
{
	struct sio_output *output = brick->outputs[0];
	char *res = brick_string_alloc(1024);
	int queue_sum = 0;
	int fly_sum   = 0;
	int total_sum = 0;
	int i;
	if (!res)
		return NULL;

	for (i = 1; i <= WITH_THREAD; i++) {
		struct sio_threadinfo *tinfo = &output->tinfo[i];
		queue_sum += atomic_read(&tinfo->queue_count);
		fly_sum   += atomic_read(&tinfo->fly_count);
		total_sum += atomic_read(&tinfo->total_count);
	}

	snprintf(res, 1024,
		 "queued read = %d write = %d "
		 "flying read = %d write = %d "
		 "total  read = %d write = %d "
		 "\n",
		 queue_sum, atomic_read(&output->tinfo[0].queue_count),
		 fly_sum,   atomic_read(&output->tinfo[0].fly_count),
		 total_sum, atomic_read(&output->tinfo[0].total_count)
		);
	return res;
}

static noinline
void sio_reset_statistics(struct sio_brick *brick)
{
	struct sio_output *output = brick->outputs[0];
	int i;
	for (i = 0; i <= WITH_THREAD; i++) {
		struct sio_threadinfo *tinfo = &output->tinfo[i];
		atomic_set(&tinfo->total_count, 0);
	}
}


//////////////// object / aspect constructors / destructors ///////////////

static int sio_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct sio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void sio_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct sio_mref_aspect *ini = (void*)_ini;
	(void)ini;
#if 1
	CHECK_HEAD_EMPTY(&ini->io_head);
#endif
}

MARS_MAKE_STATICS(sio);

////////////////////// brick constructors / destructors ////////////////////

static int sio_brick_construct(struct sio_brick *brick)
{
	return 0;
}

static int sio_switch(struct sio_brick *brick)
{
	static int sio_nr = 0;
	struct sio_output *output = brick->outputs[0];
	const char *path = output->brick->brick_path;
	int status = 0;

	if (brick->power.button) {
		int flags = O_CREAT | O_NOFOLLOW | O_RDWR | O_LARGEFILE;
		int index;

		if (brick->power.led_on)
			goto done;

		if (brick->o_direct) {
			flags |= O_DIRECT;
			MARS_INF("using O_DIRECT on %s\n", path);
		}

		mars_power_led_off((void*)brick, false);

		output->error = 0;
		output->mf = mapfree_get(path, flags, &output->error);
		if (unlikely(!output->mf || IS_ERR(output->mf))) {
			status = output->error;
			if (!status)
				status = -ENOENT;
			output->mf = NULL;
			MARS_ERR("open '%s' flags=%d status=%d\n",
				 path,
				 flags,
				 status);
			goto done;
		}

		output->index = 0;
		for (index = 0; index <= WITH_THREAD; index++) {
			struct sio_threadinfo *tinfo = &output->tinfo[index];
			
			tinfo->last_jiffies = jiffies;
			tinfo->thread = brick_thread_create(sio_thread, tinfo, "mars_sio%d", sio_nr++);
			if (unlikely(!tinfo->thread)) {
				MARS_ERR("cannot create thread\n");
				status = -ENOENT;
				goto done;
			}
		}
		mars_power_led_on((void*)brick, true);
	}
done:
	if (unlikely(status < 0) || !brick->power.button) {
		int index;
		int count;

		mars_power_led_on((void*)brick, false);
		for (;;) {
			count = atomic_read(&output->work_count);
			if (count <= 0)
				break;
			MARS_DBG("working on %d requests\n", count);
			brick_msleep(1000);
		}
		for (index = 0; index <= WITH_THREAD; index++) {
			struct sio_threadinfo *tinfo = &output->tinfo[index];
			if (!tinfo->thread)
				continue;
			MARS_DBG("stopping thread %d\n", index);
			brick_thread_stop(tinfo->thread);
			tinfo->thread = NULL;
		}
		if (output->mf) {
			MARS_DBG("closing file\n");
			mapfree_put(output->mf);
			output->mf = NULL;
		}
		mars_power_led_off((void*)brick, true);
	}
	return status;
}

static int sio_output_construct(struct sio_output *output)
{
	int index;

	spin_lock_init(&output->g_lock);
	for (index = 0; index <= WITH_THREAD; index++) {
		struct sio_threadinfo *tinfo = &output->tinfo[index];
		tinfo->output = output;
		spin_lock_init(&tinfo->lock);
		init_waitqueue_head(&tinfo->event);
		INIT_LIST_HEAD(&tinfo->mref_list);
	}

	return 0;
}

static int sio_output_destruct(struct sio_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct sio_brick_ops sio_brick_ops = {
	.brick_switch = sio_switch,
	.brick_statistics = sio_statistics,
	.reset_statistics = sio_reset_statistics,
};

static struct sio_output_ops sio_output_ops = {
	.mref_get = sio_ref_get,
	.mref_put = sio_ref_put,
	.mref_io = sio_ref_io,
	.mars_get_info = sio_get_info,
};

const struct sio_input_type sio_input_type = {
	.type_name = "sio_input",
	.input_size = sizeof(struct sio_input),
};

static const struct sio_input_type *sio_input_types[] = {
	&sio_input_type,
};

const struct sio_output_type sio_output_type = {
	.type_name = "sio_output",
	.output_size = sizeof(struct sio_output),
	.master_ops = &sio_output_ops,
	.output_construct = &sio_output_construct,
	.output_destruct = &sio_output_destruct,
};

static const struct sio_output_type *sio_output_types[] = {
	&sio_output_type,
};

const struct sio_brick_type sio_brick_type = {
	.type_name = "sio_brick",
	.brick_size = sizeof(struct sio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &sio_brick_ops,
	.aspect_types = sio_aspect_types,
	.default_input_types = sio_input_types,
	.default_output_types = sio_output_types,
	.brick_construct = &sio_brick_construct,
};
EXPORT_SYMBOL_GPL(sio_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_sio(void)
{
	MARS_INF("init_sio()\n");
	_sio_brick_type = (void*)&sio_brick_type;
	return sio_register_brick_type();
}

void exit_mars_sio(void)
{
	MARS_INF("exit_sio()\n");
	sio_unregister_brick_type();
}
