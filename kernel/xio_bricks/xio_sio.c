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

#include "xio.h"

/************************ own type definitions ***********************/

#include "xio_sio.h"

/***************** own brick * input * output operations *****************/

static int sio_io_get(struct sio_output *output, struct aio_object *aio)
{
	struct file *file;

	if (unlikely(!output->brick->power.on_led))
		return -EBADFD;

	if (aio->obj_initialized) {
		obj_get(aio);
		return aio->io_len;
	}

	file = output->mf->mf_filp;
	if (file) {
		loff_t total_size = i_size_read(file->f_mapping->host);

		aio->io_total_size = total_size;
		/* Only check reads.
		 * Writes behind EOF are always allowed (sparse files)
		 */
		if (!aio->io_may_write) {
			loff_t len = total_size - aio->io_pos;

			if (unlikely(len <= 0)) {
				/* Special case: allow reads starting _exactly_ at EOF when a timeout is specified.
				 */
				if (len < 0 || aio->io_timeout <= 0) {
					XIO_DBG("ENODATA %lld\n", len);
					return -ENODATA;
				}
			}
			/*  Shorten below EOF, but allow special case */
			if (aio->io_len > len && len > 0)
				aio->io_len = len;
		}
	}

	/* Buffered IO.
	 */
	if (!aio->io_data) {
		struct sio_aio_aspect *aio_a = sio_aio_get_aspect(output->brick, aio);

		if (unlikely(!aio_a))
			return -EILSEQ;
		if (unlikely(aio->io_len <= 0)) {
			XIO_ERR("bad io_len = %d\n", aio->io_len);
			return -ENOMEM;
		}
		aio->io_data = brick_block_alloc(aio->io_pos, (aio_a->alloc_len = aio->io_len));
		aio_a->do_dealloc = true;
		/* atomic_inc(&output->total_alloc_count); */
		/* atomic_inc(&output->alloc_count); */
	}

	obj_get_first(aio);
	return aio->io_len;
}

static void sio_io_put(struct sio_output *output, struct aio_object *aio)
{
	struct file *file;
	struct sio_aio_aspect *aio_a;

	if (!obj_put(aio))
		goto out_return;
	file = output->mf->mf_filp;
	aio->io_total_size = i_size_read(file->f_mapping->host);

	aio_a = sio_aio_get_aspect(output->brick, aio);
	if (aio_a && aio_a->do_dealloc) {
		brick_block_free(aio->io_data, aio_a->alloc_len);
		/* atomic_dec(&output->alloc_count); */
	}

	obj_free(aio);
out_return:;
}

static
int write_aops(struct sio_output *output, struct aio_object *aio)
{
	struct file *file = output->mf->mf_filp;
	loff_t pos = aio->io_pos;
	void *data = aio->io_data;
	int  len = aio->io_len;
	int ret = 0;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	ret = vfs_write(file, data, len, &pos);
	set_fs(oldfs);
	return ret;
}

static
int read_aops(struct sio_output *output, struct aio_object *aio)
{
	loff_t pos = aio->io_pos;
	int len = aio->io_len;
	int ret;

	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	ret = vfs_read(output->mf->mf_filp, aio->io_data, len, &pos);
	set_fs(oldfs);

	if (unlikely(ret < 0))
		XIO_ERR("%p %p status=%d\n", output, aio, ret);
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
	if (unlikely(ret))
		XIO_ERR("syncing pages failed: %d\n", ret);
	goto out_return;
out_return:;
}

static
void _complete(struct sio_output *output, struct aio_object *aio, int err)
{
	obj_check(aio);

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
	sio_io_put(output, aio);

	atomic_dec(&output->work_count);
	atomic_dec(&xio_global_io_flying);
	goto out_return;
err_found:
	XIO_FAT("giving up...\n");
	goto done;
out_return:;
}

/* This is called by the threads
 */
static
void _sio_io_io(struct sio_threadinfo *tinfo, struct aio_object *aio)
{
	struct sio_output *output = tinfo->output;
	bool barrier = false;
	int status;

	obj_check(aio);

	atomic_inc(&tinfo->fly_count);

	if (unlikely(!output->mf || !output->mf->mf_filp)) {
		status = -EINVAL;
		goto done;
	}

	if (barrier) {
		XIO_INF("got barrier request\n");
		sync_file(output);
	}

	if (aio->io_rw == READ) {
		status = read_aops(output, aio);
	} else {
		status = write_aops(output, aio);
		if (barrier || output->brick->o_fdsync)
			sync_file(output);
	}

	mapfree_set(output->mf, aio->io_pos, aio->io_pos + aio->io_len);

done:
	_complete(output, aio, status);

	atomic_dec(&tinfo->fly_count);
}

/* This is called from outside
 */
static
void sio_io_io(struct sio_output *output, struct aio_object *aio)
{
	int index;
	struct sio_threadinfo *tinfo;
	struct sio_aio_aspect *aio_a;
	unsigned long flags;

	obj_check(aio);

	aio_a = sio_aio_get_aspect(output->brick, aio);
	if (unlikely(!aio_a)) {
		XIO_FAT("cannot get aspect\n");
		SIMPLE_CALLBACK(aio, -EINVAL);
		goto out_return;
	}

	if (unlikely(!output->brick->power.on_led)) {
		SIMPLE_CALLBACK(aio, -EBADFD);
		goto out_return;
	}

	atomic_inc(&xio_global_io_flying);
	atomic_inc(&output->work_count);
	obj_get(aio);

	mapfree_set(output->mf, aio->io_pos, -1);

	index = 0;
	if (aio->io_rw == READ) {
		spin_lock_irqsave(&output->g_lock, flags);
		index = output->index++;
		spin_unlock_irqrestore(&output->g_lock, flags);
		index = (index % WITH_THREAD) + 1;
	}

	tinfo = &output->tinfo[index];

	atomic_inc(&tinfo->total_count);
	atomic_inc(&tinfo->queue_count);

	spin_lock_irqsave(&tinfo->lock, flags);
	list_add_tail(&aio_a->io_head, &tinfo->aio_list);
	spin_unlock_irqrestore(&tinfo->lock, flags);

	wake_up_interruptible(&tinfo->event);
out_return:;
}

static int sio_thread(void *data)
{
	struct sio_threadinfo *tinfo = data;

	XIO_INF("sio thread has started.\n");
	/* set_user_nice(current, -20); */

	while (!brick_thread_should_stop()) {
		struct list_head *tmp = NULL;
		struct aio_object *aio;
		struct sio_aio_aspect *aio_a;
		unsigned long flags;

		wait_event_interruptible_timeout(
			tinfo->event,
			!list_empty(&tinfo->aio_list) || brick_thread_should_stop(),
			HZ);

		tinfo->last_jiffies = jiffies;

		spin_lock_irqsave(&tinfo->lock, flags);

		if (!list_empty(&tinfo->aio_list)) {
			tmp = tinfo->aio_list.next;
			list_del_init(tmp);
			atomic_dec(&tinfo->queue_count);
		}

		spin_unlock_irqrestore(&tinfo->lock, flags);

		if (!tmp)
			continue;

		aio_a = container_of(tmp, struct sio_aio_aspect, io_head);
		aio = aio_a->object;
		_sio_io_io(tinfo, aio);
	}

	XIO_INF("sio thread has stopped.\n");
	return 0;
}

static int sio_get_info(struct sio_output *output, struct xio_info *info)
{
	struct file *file = output->mf->mf_filp;

	if (unlikely(!file || !file->f_mapping || !file->f_mapping->host))
		return -EINVAL;

	info->tf_align = 1;
	info->tf_min_size = 1;
	info->current_size = i_size_read(file->f_mapping->host);
	XIO_DBG("determined file size = %lld\n", info->current_size);
	return 0;
}

/*************** informational * statistics **************/

static noinline
char *sio_statistics(struct sio_brick *brick, int verbose)
{
	struct sio_output *output = brick->outputs[0];
	char *res = brick_string_alloc(1024);
	int queue_sum = 0;
	int fly_sum = 0;
	int total_sum = 0;
	int i;

	for (i = 1; i <= WITH_THREAD; i++) {
		struct sio_threadinfo *tinfo = &output->tinfo[i];

		queue_sum += atomic_read(&tinfo->queue_count);
		fly_sum += atomic_read(&tinfo->fly_count);
		total_sum += atomic_read(&tinfo->total_count);
	}

	snprintf(res, 1024,
		 "queued read = %d write = %d "
		 "flying read = %d write = %d "
		 "total  read = %d write = %d\n",
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

/*************** object * aspect constructors * destructors **************/

static int sio_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct sio_aio_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void sio_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct sio_aio_aspect *ini = (void *)_ini;

	(void)ini;
	CHECK_HEAD_EMPTY(&ini->io_head);
}

XIO_MAKE_STATICS(sio);

/********************* brick constructors * destructors *******************/

static int sio_brick_construct(struct sio_brick *brick)
{
	return 0;
}

static int sio_switch(struct sio_brick *brick)
{
	static int sio_nr;
	struct sio_output *output = brick->outputs[0];
	const char *path = output->brick->brick_path;
	int status = 0;

	if (brick->power.button) {
		int flags = O_CREAT | O_RDWR | O_LARGEFILE;
		int index;

		if (brick->power.on_led)
			goto done;

		if (brick->o_direct) {
			flags |= O_DIRECT;
			XIO_INF("using O_DIRECT on %s\n", path);
		}

		xio_set_power_off_led((void *)brick, false);

		output->mf = mapfree_get(path, flags);
		if (unlikely(IS_ERR(output->mf))) {
			XIO_ERR("could not open file = '%s' flags = %d\n", path, flags);
			status = -ENOENT;
			goto done;
		}

		output->index = 0;
		for (index = 0; index <= WITH_THREAD; index++) {
			struct sio_threadinfo *tinfo = &output->tinfo[index];

			tinfo->last_jiffies = jiffies;
			tinfo->thread = brick_thread_create(sio_thread, tinfo, "xio_sio%d", sio_nr++);
			if (unlikely(!tinfo->thread)) {
				XIO_ERR("cannot create thread\n");
				status = -ENOENT;
				goto done;
			}
		}
		xio_set_power_on_led((void *)brick, true);
	}
done:
	if (unlikely(status < 0) || !brick->power.button) {
		int index;
		int count;

		xio_set_power_on_led((void *)brick, false);
		for (;;) {
			count = atomic_read(&output->work_count);
			if (count <= 0)
				break;
			XIO_DBG("working on %d requests\n", count);
			brick_msleep(1000);
		}
		for (index = 0; index <= WITH_THREAD; index++) {
			struct sio_threadinfo *tinfo = &output->tinfo[index];

			if (!tinfo->thread)
				continue;
			XIO_DBG("stopping thread %d\n", index);
			brick_thread_stop(tinfo->thread);
			tinfo->thread = NULL;
		}
		if (output->mf) {
			XIO_DBG("closing file\n");
			mapfree_put(output->mf);
			output->mf = NULL;
		}
		xio_set_power_off_led((void *)brick, true);
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
		INIT_LIST_HEAD(&tinfo->aio_list);
	}

	return 0;
}

static int sio_output_destruct(struct sio_output *output)
{
	return 0;
}

/************************ static structs ***********************/

static struct sio_brick_ops sio_brick_ops = {
	.brick_switch = sio_switch,
	.brick_statistics = sio_statistics,
	.reset_statistics = sio_reset_statistics,
};

static struct sio_output_ops sio_output_ops = {
	.aio_get = sio_io_get,
	.aio_put = sio_io_put,
	.aio_io = sio_io_io,
	.xio_get_info = sio_get_info,
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

/***************** module init stuff ************************/

int __init init_xio_sio(void)
{
	XIO_INF("init_sio()\n");
	_sio_brick_type = (void *)&sio_brick_type;
	return sio_register_brick_type();
}

void exit_xio_sio(void)
{
	XIO_INF("exit_sio()\n");
	sio_unregister_brick_type();
}
