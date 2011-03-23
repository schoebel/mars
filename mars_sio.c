// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/splice.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_sio.h"

////////////////// own brick / input / output operations //////////////////

static int sio_ref_get(struct sio_output *output, struct mref_object *mref)
{
	_CHECK_ATOMIC(&mref->ref_count, !=,  0);
	/* Buffered IO is not implemented.
	 * Use an intermediate buf instance if you need it.
	 */
	if (!mref->ref_data)
		return -ENOSYS;

	atomic_inc(&mref->ref_count);
	return 0;
}

static void sio_ref_put(struct sio_output *output, struct mref_object *mref)
{
	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count))
		return;
	sio_free_mref(mref);
}

// some code borrowed from the loopback driver

static int transfer_none(int cmd,
			 struct page *raw_page, unsigned raw_off,
			 //struct page *loop_page, unsigned loop_off,
			 void *loop_buf,
			 int size)
{
#if 1
	void *raw_buf = kmap_atomic(raw_page, KM_USER0) + raw_off;
	//void *loop_buf = kmap_atomic(loop_page, KM_USER1) + loop_off;

	if (unlikely(!raw_buf || !loop_buf)) {
		MARS_ERR("transfer NULL: %p %p\n", raw_buf, loop_buf);
		return -EFAULT;
	}

	if (cmd == READ)
		memcpy(loop_buf, raw_buf, size);
	else
		memcpy(raw_buf, loop_buf, size);

	kunmap_atomic(raw_buf, KM_USER0);
	//kunmap_atomic(loop_buf, KM_USER1);
	cond_resched();
#endif
	return 0;
}

static void write_aops(struct sio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;
	loff_t pos = mref->ref_pos;
	void *data = mref->ref_data;
	unsigned offset;
	int len;
	struct address_space *mapping;
	int ret = 0;

	if (unlikely(!file)) {
		MARS_FAT("No FILE\n");
		return;
	}
	mapping = file->f_mapping;

	mutex_lock(&mapping->host->i_mutex);
		
	offset = pos & ((pgoff_t)PAGE_CACHE_SIZE - 1);
	len = mref->ref_len;
	
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
				ret = -EIO;
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
				ret = -EIO;
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

	mref->ref_cb->cb_error = ret;

#if 1
	blk_run_address_space(mapping);
#endif
}

struct cookie_data {
	struct sio_output *output;
	struct mref_object *mref;
	void *data;
	int len;
};

static int
sio_splice_actor(struct pipe_inode_info *pipe,
			struct pipe_buffer *buf,
			struct splice_desc *sd)
{
	struct cookie_data *p = sd->u.data;
	struct page *page = buf->page;
	sector_t IV;
	int size, ret;

	ret = buf->ops->confirm(pipe, buf);
	if (unlikely(ret))
		return ret;

	IV = ((sector_t) page->index << (PAGE_CACHE_SHIFT - 9)) +
		(buf->offset >> 9);
	size = sd->len;
	if (size > p->len)
		size = p->len;

	if (transfer_none(READ, page, buf->offset, p->data, size)) {
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

static void read_aops(struct sio_output *output, struct mref_object *mref)
{
	loff_t pos = mref->ref_pos;
	int ret = -EIO;

	struct cookie_data cookie = {
		.output = output,
		.mref = mref,
		.data = mref->ref_data,
		.len = mref->ref_len,
	};
	struct splice_desc sd = {
		.len = 0,
		.total_len = mref->ref_len,
		.flags = 0,
		.pos = pos,
		.u.data = &cookie,
	};

	ret = splice_direct_to_actor(output->filp, &sd, sio_direct_splice_actor);
	if (unlikely(ret < 0)) {
		MARS_ERR("splice %p %p status=%d\n", output, mref, ret);
	}
	mref->ref_cb->cb_error = ret;
}

static void sync_file(struct sio_output *output)
{
	struct file *file = output->filp;
	int ret;
#if 1
	ret = vfs_fsync(file, file->f_path.dentry, 1);
	if (unlikely(ret)) {
		MARS_ERR("syncing pages failed: %d\n", ret);
	}
	return;
#endif
}

static void sio_ref_io(struct sio_output *output, struct mref_object *mref)
{
	struct generic_callback *cb = mref->ref_cb;
	bool barrier = false;
	int test;

	if (unlikely(!output->filp)) {
		cb->cb_error = -EINVAL;
		goto done;
	}

	if (barrier) {
		MARS_INF("got barrier request\n");
		sync_file(output);
	}

	if (mref->ref_rw == READ) {
		read_aops(output, mref);
	} else {
		write_aops(output, mref);
		if (barrier || output->o_fdsync)
			sync_file(output);
	}

done:
#if 1
	if (cb->cb_error < 0)
		MARS_ERR("IO error %d\n", cb->cb_error);
#endif

	cb->cb_fn(cb);

	test = atomic_read(&mref->ref_count);
	if (test <= 0) {
		MARS_ERR("ref_count UNDERRUN %d\n", test);
		atomic_set(&mref->ref_count, 1);
	}
	if (!atomic_dec_and_test(&mref->ref_count))
		return;

	sio_free_mref(mref);
}

static void sio_mars_queue(struct sio_output *output, struct mref_object *mref)
{
	int index = 0;
	struct sio_threadinfo *tinfo;
	struct sio_mref_aspect *mref_a;
	struct generic_callback *cb = mref->ref_cb;
	unsigned long flags;

	if (mref->ref_rw == READ) {
		traced_lock(&output->g_lock, flags);
		index = output->index++;
		traced_unlock(&output->g_lock, flags);
		index = (index % WITH_THREAD) + 1;
	}
	mref_a = sio_mref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		cb->cb_error = -EINVAL;
		cb->cb_fn(cb);
		return;
	}

	atomic_inc(&mref->ref_count);

	tinfo = &output->tinfo[index];
	MARS_DBG("queueing %p on %d\n", mref, index);

	traced_lock(&tinfo->lock, flags);
	list_add_tail(&mref_a->io_head, &tinfo->mref_list);
	traced_unlock(&tinfo->lock, flags);

	wake_up_interruptible(&tinfo->event);
}

static int sio_thread(void *data)
{
	struct sio_threadinfo *tinfo = data;
	struct sio_output *output = tinfo->output;
	
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		struct list_head *tmp = NULL;
		struct mref_object *mref;
		struct sio_mref_aspect *mref_a;
		unsigned long flags;

		wait_event_interruptible_timeout(
			tinfo->event,
			!list_empty(&tinfo->mref_list) || kthread_should_stop(),
			HZ);

		tinfo->last_jiffies = jiffies;

		traced_lock(&tinfo->lock, flags);
		
		if (!list_empty(&tinfo->mref_list)) {
			tmp = tinfo->mref_list.next;
			list_del_init(tmp);
		}

		traced_unlock(&tinfo->lock, flags);

		if (!tmp)
			continue;

		mref_a = container_of(tmp, struct sio_mref_aspect, io_head);
		mref = mref_a->object;
		MARS_DBG("got %p %p\n", mref_a, mref);
		sio_ref_io(output, mref);
	}

	MARS_INF("kthread has stopped.\n");
	return 0;
}

static int sio_watchdog(void *data)
{
	struct sio_output *output = data;
	MARS_INF("watchdog has started.\n");
	while (!kthread_should_stop()) {
		int i;

		msleep_interruptible(5000);

		for (i = 0; i <= WITH_THREAD; i++) {
			struct sio_threadinfo *tinfo = &output->tinfo[i];
			unsigned long now = jiffies;
			unsigned long elapsed = now - tinfo->last_jiffies;
			if (elapsed > 10 * HZ) {
				tinfo->last_jiffies = now;
				MARS_ERR("thread %d is dead for more than 10 seconds.\n", i);
			}
		}
	}
	return 0;
}

static int sio_get_info(struct sio_output *output, struct mars_info *info)
{
	struct file *file = output->filp;
	info->current_size = i_size_read(file->f_mapping->host);
	info->backing_file = file;
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int sio_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct sio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void sio_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
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
	struct sio_output *output = brick->outputs[0];
	const char *path = output->output_name;
	int flags = O_CREAT | O_RDWR | O_LARGEFILE;
	int prot = 0600;
	mm_segment_t oldfs;

	if (output->o_direct) {
		flags |= O_DIRECT;
		MARS_INF("using O_DIRECT on %s\n", path);
	}
	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		oldfs = get_fs();
		set_fs(get_ds());
		output->filp = filp_open(path, flags, prot);
		set_fs(oldfs);
		
		if (IS_ERR(output->filp)) {
			int err = PTR_ERR(output->filp);
			MARS_ERR("can't open file '%s' status=%d\n", path, err);
			output->filp = NULL;
			return err;
		}
#if 0
		{
			struct address_space *mapping = output->filp->f_mapping;
			int old_gfp_mask = mapping_gfp_mask(mapping);
			mapping_set_gfp_mask(mapping, old_gfp_mask & ~(__GFP_IO|__GFP_FS));
		}
#endif
		MARS_INF("opened file '%s'\n", path);
		mars_power_led_on((void*)brick, true);
	} else {
		mars_power_led_on((void*)brick, false);
		// TODO: close etc...
		mars_power_led_off((void*)brick, true);
	}
	return 0;
}

static int sio_output_construct(struct sio_output *output)
{
	struct task_struct *watchdog;
	int index;

	spin_lock_init(&output->g_lock);
	output->index = 0;
	for (index = 0; index <= WITH_THREAD; index++) {
		struct sio_threadinfo *tinfo = &output->tinfo[index];
		tinfo->output = output;
		spin_lock_init(&tinfo->lock);
		init_waitqueue_head(&tinfo->event);
		INIT_LIST_HEAD(&tinfo->mref_list);
		tinfo->last_jiffies = jiffies;
		tinfo->thread = kthread_create(sio_thread, tinfo, "mars_sio%d", index);
		if (IS_ERR(tinfo->thread)) {
			int error = PTR_ERR(tinfo->thread);
			MARS_ERR("cannot create thread, status=%d\n", error);
			filp_close(output->filp, NULL);
			return error;
		}
		wake_up_process(tinfo->thread);
	}

	watchdog = kthread_create(sio_watchdog, output, "mars_watchdog%d", 0);
	if (!IS_ERR(watchdog)) {
		wake_up_process(watchdog);
	}
	return 0;
}

static int sio_output_destruct(struct sio_output *output)
{
	int index;
	for (index = 0; index <= WITH_THREAD; index++) {
		kthread_stop(output->tinfo[index].thread);
		output->tinfo[index].thread = NULL;
	}

	if (output->filp) {
		filp_close(output->filp, NULL);
		output->filp = NULL;
	}

	return 0;
}

///////////////////////// static structs ////////////////////////

static struct sio_brick_ops sio_brick_ops = {
	.brick_switch = sio_switch,
};

static struct sio_output_ops sio_output_ops = {
	.make_object_layout = sio_make_object_layout,
	.mref_get = sio_ref_get,
	.mref_put = sio_ref_put,
	.mref_io = sio_mars_queue,
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
	.aspect_types = sio_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_NONE,
	}
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
	.default_input_types = sio_input_types,
	.default_output_types = sio_output_types,
	.brick_construct = &sio_brick_construct,
};
EXPORT_SYMBOL_GPL(sio_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_sio(void)
{
	MARS_INF("init_sio()\n");
	return sio_register_brick_type();
}

static void __exit exit_sio(void)
{
	MARS_INF("exit_sio()\n");
	sio_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS sio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_sio);
module_exit(exit_sio);
