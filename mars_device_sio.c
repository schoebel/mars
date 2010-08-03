// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

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

#include "mars_device_sio.h"

////////////////// own brick / input / output operations //////////////////

// some code borrowed from the loopback driver

static int transfer_none(int cmd,
			 struct page *raw_page, unsigned raw_off,
			 struct page *loop_page, unsigned loop_off,
			 int size)
{
	char *raw_buf = kmap_atomic(raw_page, KM_USER0) + raw_off;
	char *loop_buf = kmap_atomic(loop_page, KM_USER1) + loop_off;

	if (unlikely(!raw_buf || !loop_buf)) {
		MARS_ERR("transfer NULL: %p %p\n", raw_buf, loop_buf);
		return -EFAULT;
	}

	if (cmd == READ)
		memcpy(loop_buf, raw_buf, size);
	else
		memcpy(raw_buf, loop_buf, size);

	kunmap_atomic(raw_buf, KM_USER0);
	kunmap_atomic(loop_buf, KM_USER1);
	cond_resched();
	return 0;
}

static int write_aops(struct device_sio_output *output, struct mars_io_object *mio)
{
	struct bio *bio = mio->orig_bio;
	loff_t pos = ((loff_t)bio->bi_sector << 9);
	struct file *file = output->filp;
	struct address_space *mapping = file->f_mapping;
	struct bio_vec *bvec;
	int i;
	int ret = 0;

	MARS_DBG("write_aops pos=%llu len=%d\n", pos, bio->bi_size);

	mutex_lock(&mapping->host->i_mutex);
		
	bio_for_each_segment(bvec, bio, i) {
		//pgoff_t index;
		unsigned offset, bv_offs;
		int len;

		//index = pos >> PAGE_CACHE_SHIFT;
		offset = pos & ((pgoff_t)PAGE_CACHE_SIZE - 1);
		bv_offs = bvec->bv_offset;
		len = bvec->bv_len;

		while (len > 0) {
			int transfer_result;
			unsigned size, copied;
			struct page *page;
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

			transfer_result = transfer_none(WRITE, page, offset, bvec->bv_page, bv_offs, size);

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
			
			bv_offs += copied;
			len -= copied;
			offset = 0;
			//index++;
			pos += copied;
		}
		ret = 0;
	}
	
fail:
	mutex_unlock(&mapping->host->i_mutex);

	if (!ret)
		bio->bi_size = 0;

	mio->mars_endio(mio, ret);

#if 1
	blk_run_address_space(mapping);
#endif

	return ret;
}

struct cookie_data {
	struct device_sio_output *output;
	struct mars_io_object *mio;
	struct bio_vec *bvec;
	unsigned int offset;
};

static int
device_sio_splice_actor(struct pipe_inode_info *pipe,
			struct pipe_buffer *buf,
			struct splice_desc *sd)
{
	struct cookie_data *p = sd->u.data;
	//struct device_sio_output *output = p->output;
	//struct mars_io_object *mio = p->mio;
	struct page *page = buf->page;
	sector_t IV;
	int size, ret;

	//MARS_DBG("now splice %p %p %p\n", mio, mio->orig_bio, p->bvec);

	ret = buf->ops->confirm(pipe, buf);
	if (unlikely(ret))
		return ret;

	IV = ((sector_t) page->index << (PAGE_CACHE_SHIFT - 9)) +
		(buf->offset >> 9);
	size = sd->len;
	if (size > p->bvec->bv_len)
		size = p->bvec->bv_len;

	if (transfer_none(READ, page, buf->offset, p->bvec->bv_page, p->offset, size)) {
		MARS_ERR("transfer error block %ld\n",  p->bvec->bv_page->index);
		size = -EINVAL;
	}

	flush_dcache_page(p->bvec->bv_page);

	if (size > 0)
		p->offset += size;

	return size;
}

static int
device_sio_direct_splice_actor(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	return __splice_from_pipe(pipe, sd, device_sio_splice_actor);
}

static int read_aops(struct device_sio_output *output, struct mars_io_object *mio)
{
	struct bio *bio = mio->orig_bio;
	loff_t pos = ((loff_t)bio->bi_sector << 9); // TODO: make dynamic
	struct bio_vec *bvec;
	int i;
	int ret = -EIO;

	bio_for_each_segment(bvec, bio, i) {
		struct cookie_data cookie = {
			.output = output,
			.mio = mio,
			.bvec = bvec,
			.offset = bvec->bv_offset,
		};
		struct splice_desc sd = {
			.len = 0,
			.total_len = bvec->bv_len,
			.flags = 0,
			.pos = pos,
			.u.data = &cookie,
		};

		MARS_DBG("start splice %p %p %p %p\n", output, mio, bio, bvec);
		ret = 0;
		ret = splice_direct_to_actor(output->filp, &sd, device_sio_direct_splice_actor);
		if (unlikely(ret < 0)) {
			MARS_ERR("splice %p %p %p %p status=%d\n", output, mio, bio, bvec, ret);
			break;
		}
		pos += bvec->bv_len;
		bio->bi_size -= bvec->bv_len;

	}

	if (unlikely(bio->bi_size)) {
		MARS_ERR("unhandled rest size %d on bio %p\n", bio->bi_size, bio);
	}

	mio->mars_endio(mio, ret);
	return ret;
}

static void sync_file(struct device_sio_output *output)
{
	struct file *file = output->filp;
	int ret;
#if 1
	ret = vfs_fsync(file, file->f_path.dentry, 0);
	if (unlikely(ret)) {
		MARS_ERR("syncing pages failed: %d\n", ret);
	}
	return;
#endif
}

static int device_sio_mars_io(struct device_sio_output *output, struct mars_io_object *mio)
{
	struct bio *bio = mio->orig_bio;
	int direction = bio->bi_rw & 1;
	bool barrier = (direction != READ && bio_rw_flagged(bio, BIO_RW_BARRIER));
	int ret = -EIO;
	
	if (barrier) {
		MARS_INF("got barrier request\n");
		sync_file(output);
	}

	if (!output->filp)
		goto done;

	if (direction == READ) {
		return read_aops(output, mio);
	} else {
		ret = write_aops(output, mio);
		if (barrier)
			sync_file(output);
		return ret;
	}

done:
	mio->mars_endio(mio, ret);
	return ret;
}

static int device_sio_mars_queue(struct device_sio_output *output, struct mars_io_object *mio)
{
	int index = 0;
	struct sio_threadinfo *tinfo;
	struct device_sio_mars_io_aspect *aspect;
	int direction = mio->orig_bio->bi_rw & 1;
	unsigned long flags;

	if (direction == READ) {
		traced_lock(&output->g_lock, flags);
		index = output->index++;
		traced_unlock(&output->g_lock, flags);
		index = (index % WITH_THREAD) + 1;
	}
	aspect = device_sio_mars_io_get_aspect(output, mio);
	tinfo = &output->tinfo[index];
	MARS_DBG("queueing %p on %d\n", mio, index);
	traced_lock(&tinfo->lock, flags);
	list_add_tail(&aspect->io_head, &tinfo->mio_list);
	traced_unlock(&tinfo->lock, flags);

	wake_up(&tinfo->event);

	return 0;
}

static int device_sio_thread(void *data)
{
	struct sio_threadinfo *tinfo = data;
	struct device_sio_output *output = tinfo->output;
	
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		struct list_head *tmp = NULL;
		struct device_sio_mars_io_aspect *aspect;
		struct mars_io_object *mio;
		unsigned long flags;

		wait_event_interruptible_timeout(
			tinfo->event,
			!list_empty(&tinfo->mio_list) || kthread_should_stop(),
			HZ);

		tinfo->last_jiffies = jiffies;

		traced_lock(&tinfo->lock, flags);

		if (!list_empty(&tinfo->mio_list)) {
			tmp = tinfo->mio_list.next;
			list_del_init(tmp);
		}

		traced_unlock(&tinfo->lock, flags);

		if (!tmp)
			continue;

		aspect = container_of(tmp, struct device_sio_mars_io_aspect, io_head);
		mio = aspect->object;
		MARS_DBG("got %p %p\n", aspect, mio);
		device_sio_mars_io(output, mio);
	}

	MARS_INF("kthread has stopped.\n");
	return 0;
}

static int device_sio_watchdog(void *data)
{
	struct device_sio_output *output = data;
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

static int device_sio_get_info(struct device_sio_output *output, struct mars_info *info)
{
	struct file *file = output->filp;
	info->current_size = i_size_read(file->f_mapping->host);
	info->backing_file = file;
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int device_sio_mars_io_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct device_sio_mars_io_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static int device_sio_mars_buf_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct device_sio_mars_buf_aspect *ini = (void*)_ini;
	(void)ini;
	return 0;
}

MARS_MAKE_STATICS(device_sio);

////////////////////// brick constructors / destructors ////////////////////

static int device_sio_brick_construct(struct device_sio_brick *brick)
{
	return 0;
}

static int device_sio_output_construct(struct device_sio_output *output)
{
	mm_segment_t oldfs;
	int flags = O_CREAT | O_RDWR | O_LARGEFILE;
	int prot = 0600;
	char *path = "/tmp/testfile.img";
	struct task_struct *watchdog;
	int index;

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

	spin_lock_init(&output->g_lock);
	output->index = 0;
	for (index = 0; index <= WITH_THREAD; index++) {
		struct sio_threadinfo *tinfo = &output->tinfo[index];
		tinfo->output = output;
		spin_lock_init(&tinfo->lock);
		init_waitqueue_head(&tinfo->event);
		INIT_LIST_HEAD(&tinfo->mio_list);
		tinfo->last_jiffies = jiffies;
		tinfo->thread = kthread_create(device_sio_thread, tinfo, "mars_sio%d", index);
		if (IS_ERR(tinfo->thread)) {
			int error = PTR_ERR(tinfo->thread);
			MARS_ERR("cannot create thread, status=%d\n", error);
			filp_close(output->filp, NULL);
			return error;
		}
		wake_up_process(tinfo->thread);
	}

	watchdog = kthread_create(device_sio_watchdog, output, "mars_watchdog%d", 0);
	if (!IS_ERR(watchdog)) {
		wake_up_process(watchdog);
	}
	return 0;
}

static int device_sio_output_destruct(struct device_sio_output *output)
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

static struct device_sio_brick_ops device_sio_brick_ops = {
};

static struct device_sio_output_ops device_sio_output_ops = {
	.make_object_layout = device_sio_make_object_layout,
	.mars_io = device_sio_mars_queue,
	.mars_get_info = device_sio_get_info,
};

static const struct device_sio_output_type device_sio_output_type = {
	.type_name = "device_sio_output",
	.output_size = sizeof(struct device_sio_output),
	.master_ops = &device_sio_output_ops,
	.output_construct = &device_sio_output_construct,
	.output_destruct = &device_sio_output_destruct,
	.aspect_types = device_sio_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_IO] = LAYOUT_NONE,
		[BRICK_OBJ_MARS_BUF] = LAYOUT_NONE,
	}
};

static const struct device_sio_output_type *device_sio_output_types[] = {
	&device_sio_output_type,
};

const struct device_sio_brick_type device_sio_brick_type = {
	.type_name = "device_sio_brick",
	.brick_size = sizeof(struct device_sio_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &device_sio_brick_ops,
	.default_output_types = device_sio_output_types,
	.brick_construct = &device_sio_brick_construct,
};
EXPORT_SYMBOL_GPL(device_sio_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_device_sio(void)
{
	MARS_INF("init_device_sio()\n");
	return device_sio_register_brick_type();
}

static void __exit exit_device_sio(void)
{
	MARS_INF("exit_device_sio()\n");
	device_sio_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS device_sio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_device_sio);
module_exit(exit_device_sio);
