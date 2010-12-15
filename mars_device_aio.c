// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define LOG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/mmu_context.h>
#include <linux/file.h>

#include "mars.h"

#define MARS_MAX_AIO      1024
#define MARS_MAX_AIO_READ 32

///////////////////////// own type definitions ////////////////////////

#include "mars_device_aio.h"

////////////////// own brick / input / output operations //////////////////

static int device_aio_ref_get(struct device_aio_output *output, struct mars_ref_object *mref)
{
	_CHECK_ATOMIC(&mref->ref_count, !=,  0);
	/* Buffered IO is implemented, but should not be used
	 * except for testing.
	 * Always precede this with a buf brick -- otherwise you
	 * can get bad performance!
	 */
	if (!mref->ref_data) {
		struct device_aio_mars_ref_aspect *mref_a = device_aio_mars_ref_get_aspect(output, mref);
		if (!mref_a)
			return -EILSEQ;
		mref->ref_data = kmalloc(mref->ref_len, GFP_MARS);
		if (!mref->ref_data)
			return -ENOMEM;
		mref->ref_flags = 0;
		mref_a->do_dealloc = true;
#if 1 // litter flags for testing
		if (mref->ref_rw) {
			static int random = 0;
			if (!(random++ % 2))
				mref->ref_flags |= MARS_REF_UPTODATE;
		}
#endif
	}

	atomic_inc(&mref->ref_count);
	return 0;
}

static void device_aio_ref_put(struct device_aio_output *output, struct mars_ref_object *mref)
{
	struct device_aio_mars_ref_aspect *mref_a;
	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count))
		return;
	mref_a = device_aio_mars_ref_get_aspect(output, mref);
	if (mref_a && mref_a->do_dealloc) {
		kfree(mref->ref_data);
	}
	device_aio_free_mars_ref(mref);
}

static void device_aio_ref_io(struct device_aio_output *output, struct mars_ref_object *mref)
{
	struct aio_threadinfo *tinfo = &output->tinfo[0];
	struct generic_callback *cb = mref->ref_cb;
	struct device_aio_mars_ref_aspect *mref_a;
	unsigned long flags;

	atomic_inc(&mref->ref_count);

	if (unlikely(!output->filp)) {
		cb->cb_error = -EINVAL;
		goto done;
	}

#ifdef LOG
	MARS_INF("AIO rw=%d pos=%lld len=%d data=%p\n", mref->ref_rw, mref->ref_pos, mref->ref_len, mref->ref_data);
#endif

	mref_a = device_aio_mars_ref_get_aspect(output, mref);
	traced_lock(&tinfo->lock, flags);
	list_add_tail(&mref_a->io_head, &tinfo->mref_list);
	traced_unlock(&tinfo->lock, flags);

	wake_up(&tinfo->event);
	return;

done:
	if (cb->cb_error < 0)
		MARS_ERR("IO error %d\n", cb->cb_error);

	cb->cb_fn(cb);
	device_aio_ref_put(output, mref);
}

static int device_aio_submit(struct device_aio_output *output, struct device_aio_mars_ref_aspect *mref_a, bool use_fdsync)
{
	struct mars_ref_object *mref = mref_a->object;
	mm_segment_t oldfs;
	int res;
	struct iocb iocb = {
		.aio_data = (__u64)mref_a,
		.aio_lio_opcode = use_fdsync ? IOCB_CMD_FDSYNC : (mref->ref_rw != 0 ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD),
		.aio_fildes = output->fd,
		.aio_buf = (unsigned long)mref->ref_data,
		.aio_nbytes = mref->ref_len,
		.aio_offset = mref->ref_pos,
	};
	struct iocb *iocbp = &iocb;

	oldfs = get_fs();
	set_fs(get_ds());
	res = sys_io_submit(output->ctxp, 1, &iocbp);
	set_fs(oldfs);

	if (res < 0 && res != -EAGAIN)
		MARS_ERR("error = %d\n", res);
	return res;
}

static int device_aio_submit_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct device_aio_output *output = tinfo->output;
	int err;
	
	/* TODO: this is provisionary. We only need it for sys_io_submit().
	 * The latter should be accompanied by a future vfs_submit() or
	 * do_sumbmit() which currently does not exist :(
	 * FIXME: corresponding cleanup NYI
	 */
	err = get_unused_fd();
	MARS_INF("fd = %d\n", err);
	if (unlikely(err < 0))
		return err;
	output->fd = err;
	fd_install(err, output->filp);

	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	MARS_INF("old mm = %p\n", current->mm);
	use_mm(tinfo->mm);
	MARS_INF("new mm = %p\n", current->mm);
	if (!current->mm)
		return 0;

	while (!kthread_should_stop()) {
		struct list_head *tmp = NULL;
		struct device_aio_mars_ref_aspect *mref_a;
		unsigned long flags;
		int err;

		wait_event_interruptible_timeout(
			tinfo->event,
			!list_empty(&tinfo->mref_list) || kthread_should_stop(),
			HZ);

		traced_lock(&tinfo->lock, flags);
		
		if (!list_empty(&tinfo->mref_list)) {
			tmp = tinfo->mref_list.next;
			list_del_init(tmp);
		}

		traced_unlock(&tinfo->lock, flags);

		if (!tmp)
			continue;

		mref_a = container_of(tmp, struct device_aio_mars_ref_aspect, io_head);

		err = device_aio_submit(output, mref_a, false);

		if (err == -EAGAIN) {
			traced_lock(&tinfo->lock, flags);
			list_add(&mref_a->io_head, &tinfo->mref_list);
			traced_unlock(&tinfo->lock, flags);
			msleep(10); // PROVISIONARY
			continue;
		}
#if 0
		if (false) {
			struct generic_callback *cb = mref_a->object->ref_cb;
			cb->cb_error = err;
			if (err < 0)
				MARS_ERR("IO error %d\n", err);
			cb->cb_fn(cb);
			device_aio_ref_put(output, mref_a->object);
		}
#endif
	}

	unuse_mm(tinfo->mm);

	MARS_INF("kthread has stopped.\n");
	return 0;
}

static int device_aio_event_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct device_aio_output *output = tinfo->output;
	struct aio_threadinfo *other = &output->tinfo[2];
	
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	MARS_INF("old mm = %p\n", current->mm);
	use_mm(tinfo->mm);
	MARS_INF("new mm = %p\n", current->mm);
	if (!current->mm)
		return 0;

	while (!kthread_should_stop()) {
		mm_segment_t oldfs;
		int count;
		int bounced;
		int i;
		struct timespec timeout = {
			.tv_sec = 30,
		};
		struct io_event events[MARS_MAX_AIO_READ];

		oldfs = get_fs();
		set_fs(get_ds());
		count = sys_io_getevents(output->ctxp, 1, MARS_MAX_AIO_READ, events, &timeout);
		set_fs(oldfs);

		//MARS_INF("count = %d\n", count);
		bounced = 0;
		for (i = 0; i < count; i++) {
			struct device_aio_mars_ref_aspect *mref_a = (void*)events[i].data;
			struct mars_ref_object *mref = mref_a->object;
			struct generic_callback *cb = mref->ref_cb;
			int err = events[i].res;

#ifdef LOG
			MARS_INF("AIO done %p pos = %lld len = %d rw = %d\n", mref, mref->ref_pos, mref->ref_len, mref->ref_rw);
#endif

			if (output->o_fdsync
			   && err >= 0 
			   && mref->ref_rw != 0
			   && !mref_a->resubmit++) {
				if (!output->filp->f_op->aio_fsync) {
					unsigned long flags;
					traced_lock(&other->lock, flags);
					list_add(&mref_a->io_head, &other->mref_list);
					traced_unlock(&other->lock, flags);
					bounced++;
					continue;
				}
				err = device_aio_submit(output, mref_a, true);
				if (likely(err >= 0))
					continue;
			}

			cb->cb_error = err;
			if (err < 0) {
				MARS_ERR("IO error %d\n", err);
			} else {
				mref->ref_flags |= MARS_REF_UPTODATE;
			}
			cb->cb_fn(cb);
			device_aio_ref_put(output, mref);
		}
		if (bounced)
			wake_up(&other->event);
	}

	unuse_mm(tinfo->mm);

	MARS_INF("kthread has stopped.\n");
	return 0;
}

/* Workaround for non-implemented aio_fsync()
 */
static int device_aio_sync_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct device_aio_output *output = tinfo->output;
	struct file *file = output->filp;
	
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		LIST_HEAD(tmp_list);
		unsigned long flags;
		int err;

		wait_event_interruptible_timeout(
			tinfo->event,
			!list_empty(&tinfo->mref_list) || kthread_should_stop(),
			HZ);

		traced_lock(&tinfo->lock, flags);
		if (!list_empty(&tinfo->mref_list)) {
			// move over the whole list
			list_replace_init(&tinfo->mref_list, &tmp_list);
		}
		traced_unlock(&tinfo->lock, flags);

		if (list_empty(&tmp_list))
			continue;

		err = vfs_fsync(file, file->f_path.dentry, 1);
		if (err < 0)
			MARS_ERR("FDSYNC error %d\n", err);

		/* Signal completion for the whole list.
		 * No locking needed, it's on the stack.
		 */
		while (!list_empty(&tmp_list)) {
			struct list_head *tmp = tmp_list.next;
			struct device_aio_mars_ref_aspect *mref_a = container_of(tmp, struct device_aio_mars_ref_aspect, io_head);
			struct generic_callback *cb = mref_a->object->ref_cb;
			list_del_init(tmp);
			cb->cb_error = err;
			if (err >= 0) {
				mref_a->object->ref_flags |= MARS_REF_UPTODATE;
			}
			cb->cb_fn(cb);
			device_aio_ref_put(output, mref_a->object);
		}
	}

	MARS_INF("kthread has stopped.\n");
	return 0;
}

static int device_aio_get_info(struct device_aio_output *output, struct mars_info *info)
{
	struct file *file = output->filp;
	info->current_size = i_size_read(file->f_mapping->host);
	info->backing_file = file;
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int device_aio_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct device_aio_mars_ref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void device_aio_mars_ref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct device_aio_mars_ref_aspect *ini = (void*)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(device_aio);

////////////////////// brick constructors / destructors ////////////////////

static int device_aio_brick_construct(struct device_aio_brick *brick)
{
	return 0;
}

static int device_aio_switch(struct device_aio_brick *brick, bool state)
{
	static int index = 0;
	struct device_aio_output *output = brick->outputs[0];
	char *path = output->output_name;
	int flags = O_CREAT | O_RDWR | O_LARGEFILE;
	int prot = 0600;
	mm_segment_t oldfs;
	int i;
	int err = 0;

	if (output->o_direct) {
		flags |= O_DIRECT;
		MARS_INF("using O_DIRECT on %s\n", path);
	}
	if (!state)
		goto cleanup;

	oldfs = get_fs();
	set_fs(get_ds());
	output->filp = filp_open(path, flags, prot);
	set_fs(oldfs);
	
	if (unlikely(IS_ERR(output->filp))) {
		err = PTR_ERR(output->filp);
		MARS_ERR("can't open file '%s' status=%d\n", path, err);
		output->filp = NULL;
		return err;
	}

	if (!output->ctxp) {
		MARS_INF("mm = %p\n", current->mm);
		oldfs = get_fs();
		set_fs(get_ds());
		err = sys_io_setup(MARS_MAX_AIO, &output->ctxp);
		set_fs(oldfs);
		if (unlikely(err))
			goto err;
	}

	for (i = 0; i < 3; i++) {
		static int (*fn[])(void*) = {
			device_aio_submit_thread,
			device_aio_event_thread,
			device_aio_sync_thread,
		};
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		INIT_LIST_HEAD(&tinfo->mref_list);
		tinfo->output = output;
		tinfo->mm = current->mm;
		spin_lock_init(&tinfo->lock);
		init_waitqueue_head(&tinfo->event);
		tinfo->thread = kthread_create(fn[i], tinfo, "mars_aio%d", index++);
		if (IS_ERR(tinfo->thread)) {
			err = PTR_ERR(tinfo->thread);
			MARS_ERR("cannot create thread\n");
			tinfo->thread = NULL;
			goto err;
		}
		wake_up_process(tinfo->thread);
	}

	MARS_INF("opened file '%s'\n", path);
	return 0;

err:
	MARS_ERR("status = %d\n", err);
cleanup:
	for (i = 0; i < 2; i++) {
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		if (tinfo->thread) {
			kthread_stop(tinfo->thread);
			// FIXME: wait for termination
			tinfo->thread = NULL;
		}
	}
	if (output->ctxp) {
		//...
	}
	if (output->filp) {
		filp_close(output->filp, NULL);
		output->filp = NULL;
	}
	return err;
}

static int device_aio_output_construct(struct device_aio_output *output)
{
	return 0;
}

static int device_aio_output_destruct(struct device_aio_output *output)
{
	return device_aio_switch(output->brick, false);
}

///////////////////////// static structs ////////////////////////

static struct device_aio_brick_ops device_aio_brick_ops = {
	.brick_switch = device_aio_switch,
};

static struct device_aio_output_ops device_aio_output_ops = {
	.make_object_layout = device_aio_make_object_layout,
	.mars_ref_get = device_aio_ref_get,
	.mars_ref_put = device_aio_ref_put,
	.mars_ref_io = device_aio_ref_io,
	.mars_get_info = device_aio_get_info,
};

const struct device_aio_output_type device_aio_output_type = {
	.type_name = "device_aio_output",
	.output_size = sizeof(struct device_aio_output),
	.master_ops = &device_aio_output_ops,
	.output_construct = &device_aio_output_construct,
	.output_destruct = &device_aio_output_destruct,
	.aspect_types = device_aio_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_NONE,
	}
};

static const struct device_aio_output_type *device_aio_output_types[] = {
	&device_aio_output_type,
};

const struct device_aio_brick_type device_aio_brick_type = {
	.type_name = "device_aio_brick",
	.brick_size = sizeof(struct device_aio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &device_aio_brick_ops,
	.default_output_types = device_aio_output_types,
	.brick_construct = &device_aio_brick_construct,
};
EXPORT_SYMBOL_GPL(device_aio_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_device_aio(void)
{
	MARS_INF("init_device_aio()\n");
	return device_aio_register_brick_type();
}

static void __exit exit_device_aio(void)
{
	MARS_INF("exit_device_aio()\n");
	device_aio_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS device_aio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_device_aio);
module_exit(exit_device_aio);
