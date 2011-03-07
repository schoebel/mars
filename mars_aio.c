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
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "mars.h"

#define MARS_MAX_AIO      1024
#define MARS_MAX_AIO_READ 32

#define STRONG_MM

///////////////////////// own type definitions ////////////////////////

#include "mars_aio.h"

////////////////// some helpers //////////////////

static
void _queue(struct aio_threadinfo *tinfo, struct aio_mref_aspect *mref_a)
{
	unsigned long flags;

	traced_lock(&tinfo->lock, flags);

	list_add_tail(&mref_a->io_head, &tinfo->mref_list);

	traced_unlock(&tinfo->lock, flags);
}

static
void _delay(struct aio_threadinfo *tinfo, struct aio_mref_aspect *mref_a, int delta_jiffies)
{
	long long timeout = (long long)jiffies + delta_jiffies;
	unsigned long flags;

	mref_a->timeout = timeout;

	traced_lock(&tinfo->lock, flags);

	list_add_tail(&mref_a->io_head, &tinfo->delay_list);

	traced_unlock(&tinfo->lock, flags);
}

static
struct aio_mref_aspect *_get_delayed(struct aio_threadinfo *tinfo, bool remove)
{
	struct list_head *tmp;
	struct aio_mref_aspect *mref_a;
	unsigned long flags;

	if (list_empty(&tinfo->delay_list))
		return NULL;

	traced_lock(&tinfo->lock, flags);

	tmp = tinfo->delay_list.next;
	mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
	if (mref_a->timeout < (long long)jiffies) {
		mref_a = NULL;
	} else if (remove) {
		list_del_init(tmp);
	}

	traced_unlock(&tinfo->lock, flags);

	return mref_a;
}


////////////////// own brick / input / output operations //////////////////

static int aio_ref_get(struct aio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;

	_CHECK_ATOMIC(&mref->ref_count, !=,  0);
	
	if (file) {
		mref->ref_total_size = i_size_read(file->f_mapping->host);
	}

	/* Buffered IO is implemented, but should not be used
	 * except for testing.
	 * Always precede this with a buf brick -- otherwise you
	 * can get bad performance!
	 */
	if (!mref->ref_data) {
		struct aio_mref_aspect *mref_a = aio_mref_get_aspect(output, mref);
		if (!mref_a)
			return -EILSEQ;
		mref->ref_data = kmalloc(mref->ref_len, GFP_MARS);
		if (!mref->ref_data)
			return -ENOMEM;
		mref->ref_flags = 0;
		mref_a->do_dealloc = true;
#if 0 // litter flags for testing
		if (mref->ref_rw) {
			static int random = 0;
			if (!(random++ % 2))
				mref->ref_flags |= MREF_UPTODATE;
		}
#endif
	}

	atomic_inc(&mref->ref_count);
	return 0;
}

static void aio_ref_put(struct aio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;
	struct aio_mref_aspect *mref_a;

	CHECK_ATOMIC(&mref->ref_count, 1);
	if (file) {
		mref->ref_total_size = i_size_read(file->f_mapping->host);
	}
	if (!atomic_dec_and_test(&mref->ref_count)) {
		goto done;
	}
	mref_a = aio_mref_get_aspect(output, mref);
	if (mref_a && mref_a->do_dealloc) {
		kfree(mref->ref_data);
	}
	aio_free_mref(mref);
 done:;
}

static
void _complete(struct aio_output *output, struct mref_object *mref, int err)
{
	struct generic_callback *cb;
	cb = mref->ref_cb;
	cb->cb_error = err;
	if (err < 0) {
		MARS_ERR("IO error %d\n", err);
	} else {
		mref->ref_flags |= MREF_UPTODATE;
	}
	cb->cb_fn(cb);
	aio_ref_put(output, mref);
}

static void aio_ref_io(struct aio_output *output, struct mref_object *mref)
{
	struct aio_threadinfo *tinfo = &output->tinfo[0];
	struct aio_mref_aspect *mref_a;
	int err = -EINVAL;

	atomic_inc(&mref->ref_count);

	if (unlikely(!output->filp)) {
		goto done;
	}

	MARS_IO("AIO rw=%d pos=%lld len=%d data=%p\n", mref->ref_rw, mref->ref_pos, mref->ref_len, mref->ref_data);

	mref_a = aio_mref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		goto done;
	}

	_queue(tinfo, mref_a);

	wake_up_interruptible(&tinfo->event);
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

static int aio_submit_dummy(struct aio_output *output)
{
	mm_segment_t oldfs;
	int res;
	struct iocb iocb = {
	};
	struct iocb *iocbp = &iocb;

	oldfs = get_fs();
	set_fs(get_ds());
	res = sys_io_submit(output->ctxp, 1, &iocbp);
	set_fs(oldfs);

	return res;
}

static int aio_submit_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct file *file = output->filp;
	struct mm_struct *old_mm;
	int err;
	
	/* TODO: this is provisionary. We only need it for sys_io_submit().
	 * The latter should be accompanied by a future vfs_submit() or
	 * do_submit() which currently does not exist :(
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

	old_mm = fake_mm();

	if (!current->mm)
		return -ENOMEM;

	while (!kthread_should_stop()) {
		struct list_head *tmp = NULL;
		struct aio_mref_aspect *mref_a;
		struct mref_object *mref;
		unsigned long flags;
		int err;

		wait_event_interruptible_timeout(
			tinfo->event,
			!list_empty(&tinfo->mref_list) ||
			_get_delayed(tinfo, false) ||
			kthread_should_stop(),
			HZ);

		traced_lock(&tinfo->lock, flags);
		
		if (!list_empty(&tinfo->mref_list)) {
			tmp = tinfo->mref_list.next;
			list_del_init(tmp);
			mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
		} else {
			mref_a = _get_delayed(tinfo, true);
		}

		traced_unlock(&tinfo->lock, flags);

		if (!mref_a)
			continue;

		// check for reads behind EOF
		mref = mref_a->object;
		if (!mref->ref_rw && mref->ref_pos + mref->ref_len > i_size_read(file->f_mapping->host)) {
			if (!mref->ref_timeout || mref->ref_timeout < (long long)jiffies) {
				_complete(output, mref, -ENODATA);
				continue;
			}
			_delay(tinfo, mref_a, HZ/2);
			continue;
		}

		err = aio_submit(output, mref_a, false);

		if (err == -EAGAIN) {
			_delay(tinfo, mref_a, (HZ/100)+1);
			continue;
		}
		if (unlikely(err < 0)) {
			_complete(output, mref, err);
		}
	}

	MARS_INF("kthread has stopped.\n");
	tinfo->terminated = true;

	cleanup_mm(old_mm);

	return 0;
}

static int aio_event_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct aio_threadinfo *other = &output->tinfo[2];
	struct mm_struct *old_mm;
	int err = -ENOMEM;
	
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	old_mm = fake_mm();
	if (!current->mm)
		goto err;

#if 1
	if (!output->ctxp) {
	mm_segment_t oldfs;
		if (!current->mm) {
			MARS_ERR("mm = %p\n", current->mm);
			err = -EINVAL;
			goto err;
		}
		oldfs = get_fs();
		set_fs(get_ds());
		err = sys_io_setup(MARS_MAX_AIO, &output->ctxp);
		set_fs(oldfs);
		if (unlikely(err))
			goto err;
	}
#endif

	while (!kthread_should_stop()) {
		mm_segment_t oldfs;
		int count;
		int bounced;
		int i;
		struct timespec timeout = {
			.tv_sec = 10,
		};
		struct io_event events[MARS_MAX_AIO_READ];

		oldfs = get_fs();
		set_fs(get_ds());
		/* TODO: don't timeout upon termination.
		 * Probably we should submit a dummy request.
		 */
		count = sys_io_getevents(output->ctxp, 1, MARS_MAX_AIO_READ, events, &timeout);
		set_fs(oldfs);

		//MARS_INF("count = %d\n", count);
		bounced = 0;
		for (i = 0; i < count; i++) {
			struct aio_mref_aspect *mref_a = (void*)events[i].data;
			struct mref_object *mref;
			int err = events[i].res;

			if (!mref_a) {
				continue; // this was a dummy request
			}
			mref = mref_a->object;

			MARS_IO("AIO done %p pos = %lld len = %d rw = %d\n", mref, mref->ref_pos, mref->ref_len, mref->ref_rw);

			if (output->o_fdsync
			   && err >= 0 
			   && mref->ref_rw != 0
			   && !mref_a->resubmit++) {
				if (!output->filp->f_op->aio_fsync) {
					_queue(other, mref_a);
					bounced++;
					continue;
				}
				err = aio_submit(output, mref_a, true);
				if (likely(err >= 0))
					continue;
			}

			_complete(output, mref, err);

		}
		if (bounced)
			wake_up_interruptible(&other->event);
	}
	err = 0;

 err:
	MARS_INF("kthread has stopped, err = %d\n", err);
	tinfo->terminated = true;

	cleanup_mm(old_mm);

	return err;
}

/* Workaround for non-implemented aio_fsync()
 */
static int aio_sync_thread(void *data)
{
	struct aio_threadinfo *tinfo = data;
	struct aio_output *output = tinfo->output;
	struct file *file = output->filp;
	
	MARS_INF("kthread has started on '%s'.\n", output->brick->brick_name);
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
			struct aio_mref_aspect *mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
			list_del_init(tmp);
			_complete(output, mref_a->object, err);
		}
	}

	MARS_INF("kthread has stopped.\n");
	tinfo->terminated = true;
	return 0;
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

//////////////// object / aspect constructors / destructors ///////////////

static int aio_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct aio_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void aio_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
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
	static int index = 0;
	struct aio_output *output = brick->outputs[0];
	const char *path = output->brick->brick_name;
	int flags = O_CREAT | O_RDWR | O_LARGEFILE;
	int prot = 0600;
	mm_segment_t oldfs;
	int i;
	int err = 0;

	MARS_DBG("power.button = %d\n", brick->power.button);
	if (!brick->power.button)
		goto cleanup;

	if (brick->power.led_on)
		goto done;

	mars_power_led_off((void*)brick, false);

	if (output->o_direct) {
		flags |= O_DIRECT;
		MARS_INF("using O_DIRECT on %s\n", path);
	}

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
	MARS_DBG("opened file '%s'\n", path);

#if 0 // not here
	if (!output->ctxp) {
		if (!current->mm) {
			MARS_ERR("mm = %p\n", current->mm);
			err = -EINVAL;
			goto err;
		}
		oldfs = get_fs();
		set_fs(get_ds());
		err = sys_io_setup(MARS_MAX_AIO, &output->ctxp);
		set_fs(oldfs);
		if (unlikely(err))
			goto err;
	}
#endif

	for (i = 0; i < 3; i++) {
		static int (*fn[])(void*) = {
			aio_submit_thread,
			aio_event_thread,
			aio_sync_thread,
		};
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		INIT_LIST_HEAD(&tinfo->mref_list);
		INIT_LIST_HEAD(&tinfo->delay_list);
		tinfo->output = output;
		spin_lock_init(&tinfo->lock);
		init_waitqueue_head(&tinfo->event);
		tinfo->terminated = false;
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
	for (i = 0; i < 3; i++) {
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		if (tinfo->thread) {
			kthread_stop(tinfo->thread);
			tinfo->thread = NULL;
		}
	}
	aio_submit_dummy(output);
	for (i = 0; i < 3; i++) {
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		if (tinfo->thread) {
			// wait for termination
			wait_event_interruptible_timeout(
				tinfo->event,
				tinfo->terminated, 30 * HZ);
			if (tinfo->terminated)
				tinfo->thread = NULL;
		}
	}
	mars_power_led_off((void*)brick,
			  (output->tinfo[0].thread == NULL &&
			   output->tinfo[1].thread == NULL &&
			   output->tinfo[2].thread == NULL));
	if (brick->power.led_off) {
		if (output->filp) {
			filp_close(output->filp, NULL);
			output->filp = NULL;
		}
		if (output->ctxp) {
#if 0 // FIXME this crashes
			sys_io_destroy(output->ctxp);
#endif
			output->ctxp = 0;
		}
	}
	MARS_DBG("switch off status = %d\n", err);
	return err;
}

static int aio_output_construct(struct aio_output *output)
{
	return 0;
}

static int aio_output_destruct(struct aio_output *output)
{
	return mars_power_button((void*)output->brick, false);
}

///////////////////////// static structs ////////////////////////

static struct aio_brick_ops aio_brick_ops = {
	.brick_switch = aio_switch,
};

static struct aio_output_ops aio_output_ops = {
	.make_object_layout = aio_make_object_layout,
	.mref_get = aio_ref_get,
	.mref_put = aio_ref_put,
	.mref_io = aio_ref_io,
	.mars_get_info = aio_get_info,
};

const struct aio_output_type aio_output_type = {
	.type_name = "aio_output",
	.output_size = sizeof(struct aio_output),
	.master_ops = &aio_output_ops,
	.output_construct = &aio_output_construct,
	.output_destruct = &aio_output_destruct,
	.aspect_types = aio_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_NONE,
	}
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
	.default_output_types = aio_output_types,
	.brick_construct = &aio_brick_construct,
};
EXPORT_SYMBOL_GPL(aio_brick_type);

////////////////// module init stuff /////////////////////////

static int __init _init_aio(void)
{
	MARS_INF("init_aio()\n");
	_aio_brick_type = (void*)&aio_brick_type;
	return aio_register_brick_type();
}

static void __exit _exit_aio(void)
{
	MARS_INF("exit_aio()\n");
	aio_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS aio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(_init_aio);
module_exit(_exit_aio);
