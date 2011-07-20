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
#define MEMLEAK // FIXME: remove this
#define MEASURE_SYNC 8

///////////////////////// own type definitions ////////////////////////

#include "mars_aio.h"

#ifdef MEASURE_SYNC
static int sync_ticks[MEASURE_SYNC] = {};

static void measure_sync(int ticks)
{
	int order = ticks;
	if (ticks > 1) {
		order = MEASURE_SYNC - 1;
		while (order > 0 && (1 << (order-1)) >= ticks) {
			order--;
		}
		order++;
	}
	sync_ticks[order]++;
}

static char *show_sync(void)
{
	char *res = kmalloc(512, GFP_MARS);
	int i;
	int pos = 0;
	for (i = 0; i < MEASURE_SYNC; i++) {
		pos += snprintf(res + pos, 256, "%d: %d ", i, sync_ticks[i]);
	}
	return res;
}

#endif

////////////////// some helpers //////////////////

static inline
void _enqueue(struct aio_threadinfo *tinfo, struct aio_mref_aspect *mref_a, int prio, bool at_end)
{
	unsigned long flags;
#if 1
	prio++;
	if (prio < 0) {
		prio = 0;
	} else if (prio > MARS_PRIO_NR) {
		prio = MARS_PRIO_NR;
	}
#else
	prio = 0;
#endif

	traced_lock(&tinfo->lock, flags);

	if (at_end) {
		list_add_tail(&mref_a->io_head, &tinfo->mref_list[prio]);
	} else {
		list_add(&mref_a->io_head, &tinfo->mref_list[prio]);
	}

	traced_unlock(&tinfo->lock, flags);

	atomic_inc(&tinfo->total_enqueue_count);
}

static inline
struct aio_mref_aspect *_dequeue(struct aio_threadinfo *tinfo, bool do_remove)
{
	struct aio_mref_aspect *mref_a = NULL;
	int prio;
	unsigned long flags = 0;

	if (do_remove)
		traced_lock(&tinfo->lock, flags);

	for (prio = 0; prio < MARS_PRIO_NR; prio++) {
		struct list_head *start = &tinfo->mref_list[prio];
		struct list_head *tmp = start->next;
		if (tmp != start) {
			if (do_remove) {
				list_del_init(tmp);
				atomic_inc(&tinfo->total_dequeue_count);
			}
			mref_a = container_of(tmp, struct aio_mref_aspect, io_head);
			goto done;
		}
	}

done:
	if (do_remove)
		traced_unlock(&tinfo->lock, flags);
	return mref_a;
}

////////////////// own brick / input / output operations //////////////////

static int aio_ref_get(struct aio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;

	if (atomic_read(&mref->ref_count) > 0) {
		atomic_inc(&mref->ref_count);
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
		struct aio_mref_aspect *mref_a = aio_mref_get_aspect(output, mref);
		if (!mref_a)
			return -EILSEQ;
		mref->ref_data = mars_alloc(mref->ref_pos, (mref_a->alloc_len = mref->ref_len));
		if (!mref->ref_data) {
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

	atomic_inc(&mref->ref_count);
	return mref->ref_len;
}

static void aio_ref_put(struct aio_output *output, struct mref_object *mref)
{
	struct file *file = output->filp;
	struct aio_mref_aspect *mref_a;

	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count)) {
		goto done;
	}

	if (file) {
		mref->ref_total_size = i_size_read(file->f_mapping->host);
	}

	mref_a = aio_mref_get_aspect(output, mref);
	if (mref_a && mref_a->do_dealloc) {
		mars_free(mref->ref_data, mref_a->alloc_len);
		atomic_dec(&output->alloc_count);
	}
	aio_free_mref(mref);
 done:;
}

static
void _complete(struct aio_output *output, struct mref_object *mref, int err)
{
	struct generic_callback *cb;

	mars_trace(mref, "aio_endio");

	cb = mref->ref_cb;
	CHECK_PTR(cb, err_found);

	cb->cb_error = err;
	if (err < 0) {
		MARS_ERR("IO error %d at pos=%lld len=%d (mref=%p ref_data=%p)\n", err, mref->ref_pos, mref->ref_len, mref, mref->ref_data);
	} else {
		mref->ref_flags |= MREF_UPTODATE;
	}

	cb->cb_fn(cb);

done:
	if (mref->ref_rw) {
		atomic_dec(&output->write_count);
	} else {
		atomic_dec(&output->read_count);
	}

	aio_ref_put(output, mref);
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

	atomic_inc(&mref->ref_count);

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

	mref_a = aio_mref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		goto done;
	}

	_enqueue(tinfo, mref_a, mref->ref_prio, true);

	wake_up_interruptible_all(&tinfo->event);
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

	mars_trace(mref, "aio_submit");

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
		struct aio_mref_aspect *mref_a;
		struct mref_object *mref;
		int sleeptime;
		int err;

		wait_event_interruptible_timeout(
			tinfo->event,
			kthread_should_stop() ||
			_dequeue(tinfo, false),
			HZ);

		mref_a = _dequeue(tinfo, true);
		if (!mref_a) {
			continue;
		}

		// check for reads exactly at EOF (special case)
		mref = mref_a->object;
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
					if (!_dequeue(tinfo, false)) {
						atomic_inc(&output->total_msleep_count);
						msleep(1000 * 4 / HZ);
					}
					_enqueue(tinfo, mref_a, MARS_PRIO_LOW, true);
					continue;
				}
				MARS_DBG("ENODATA %lld\n", len);
				_complete(output, mref, -ENODATA);
				continue;
			}
		}

		sleeptime = 1000 / HZ;
		for (;;) {
			/* This is just a test. Don't use it for performance reasons.
			 */
			if (output->brick->wait_during_fdsync && mref->ref_rw != READ) {
				if (output->fdsync_active) {
					long long delay = 60 * HZ;
					atomic_inc(&output->total_fdsync_wait_count);
					__wait_event_interruptible_timeout(
						output->fdsync_event,
						!output->fdsync_active || kthread_should_stop(),
						delay);
				}

			}

			/* Now really do the work
			 */
			err = aio_submit(output, mref_a, false);

			if (likely(err != -EAGAIN)) {
				break;
			}
			atomic_inc(&output->total_delay_count);
			msleep(sleeptime);
			if (sleeptime < 100) {
				sleeptime += 1000 / HZ;
			}
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

			if (output->brick->o_fdsync
			   && err >= 0 
			   && mref->ref_rw != READ
			   && !mref->ref_skip_sync
			   && !mref_a->resubmit++) {
				// workaround for non-implemented AIO FSYNC operation
				if (!output->filp->f_op->aio_fsync) {
					mars_trace(mref, "aio_fsync");
					_enqueue(other, mref_a, mref->ref_prio, true);
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
			wake_up_interruptible_all(&other->event);
	}
	err = 0;

 err:
	MARS_INF("kthread has stopped, err = %d\n", err);
	tinfo->terminated = true;

	cleanup_mm(old_mm);

	return err;
}

static
int aio_sync(struct file *file)
{
	int err;
#ifdef MEASURE_SYNC
	long long old_jiffies = jiffies;
#endif

	err = do_sync_mapping_range(file->f_mapping, 0, LLONG_MAX, SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER);


#ifdef MEASURE_SYNC
	measure_sync(jiffies - old_jiffies);
#endif
	return err;
}

static
void aio_sync_all(struct aio_output *output, struct list_head *tmp_list)
{
	int err;

	output->fdsync_active = true;
	atomic_inc(&output->total_fdsync_count);
	
	err = aio_sync(output->filp);
	
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
	
	MARS_INF("kthread has started on '%s'.\n", output->brick->brick_name);
	//set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		LIST_HEAD(tmp_list);
		unsigned long flags;
		int i;

		output->fdsync_active = false;
		wake_up_interruptible_all(&output->fdsync_event);

		wait_event_interruptible_timeout(
			tinfo->event,
			kthread_should_stop() ||
			_dequeue(tinfo, false),
			60 * HZ);

		traced_lock(&tinfo->lock, flags);
		for (i = 0; i < MARS_PRIO_NR; i++) {
			struct list_head *start = &tinfo->mref_list[i];
			if (!list_empty(start)) {
				// move over the whole list
				list_replace_init(start, &tmp_list);
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

//////////////// informational / statistics ///////////////

static noinline
char *aio_statistics(struct aio_brick *brick, int verbose)
{
	struct aio_output *output = brick->outputs[0];
	char *res = kmalloc(1024, GFP_MARS);
	char *sync = NULL;
	if (!res)
		return NULL;

#ifdef MEASURE_SYNC
	sync = show_sync();
#endif

	// FIXME: check for allocation overflows

	snprintf(res, 1024, "total reads = %d writes = %d allocs = %d delays = %d msleeps = %d fdsyncs = %d fdsync_waits = %d | flying reads = %d writes = %d allocs = %d q0 = %d/%d q1 = %d/%d q2 = %d/%d | %s\n",
		atomic_read(&output->total_read_count), atomic_read(&output->total_write_count), atomic_read(&output->total_alloc_count), atomic_read(&output->total_delay_count), atomic_read(&output->total_msleep_count), atomic_read(&output->total_fdsync_count), atomic_read(&output->total_fdsync_wait_count),
		atomic_read(&output->read_count), atomic_read(&output->write_count), atomic_read(&output->alloc_count),
		atomic_read(&output->tinfo[0].total_enqueue_count), atomic_read(&output->tinfo[0].total_dequeue_count),
		atomic_read(&output->tinfo[1].total_enqueue_count), atomic_read(&output->tinfo[2].total_dequeue_count),
		atomic_read(&output->tinfo[2].total_enqueue_count), atomic_read(&output->tinfo[2].total_dequeue_count),
		sync ? sync : "");
	
	if (sync)
		kfree(sync);

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
	atomic_set(&output->total_delay_count, 0);
	atomic_set(&output->total_msleep_count, 0);
	atomic_set(&output->total_fdsync_count, 0);
	atomic_set(&output->total_fdsync_wait_count, 0);
	for (i = 0; i < 3; i++) {
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		atomic_set(&tinfo->total_enqueue_count, 0);
		atomic_set(&tinfo->total_dequeue_count, 0);
	}
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

	if (brick->o_direct) {
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
#if 1
	{
		struct inode *inode = output->filp->f_mapping->host;
		if (S_ISBLK(inode->i_mode)) {
			MARS_INF("changing readahead from %lu to %d\n", inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages, brick->readahead);
			inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages = brick->readahead;
		}
	}
#endif

	for (i = 0; i < 3; i++) {
		static int (*fn[])(void*) = {
			aio_submit_thread,
			aio_event_thread,
			aio_sync_thread,
		};
		struct aio_threadinfo *tinfo = &output->tinfo[i];
		int j;
		for (j = 0; j < MARS_PRIO_NR; j++) {
			INIT_LIST_HEAD(&tinfo->mref_list[j]);
		}
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
#ifndef MEMLEAK // FIXME this crashes
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
	.make_object_layout = aio_make_object_layout,
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
	.default_input_types = aio_input_types,
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
