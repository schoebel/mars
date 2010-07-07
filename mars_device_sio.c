// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

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
	int ret = -EIO;

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
			if (ret)
				goto fail;

			//file_update_time(file);

			transfer_result = transfer_none(WRITE, page, offset, bvec->bv_page, bv_offs, size);

			copied = size;
			if (transfer_result)
				copied = 0;

			ret = pagecache_write_end(file, mapping, pos, size, copied,
						  page, fsdata);
			if (ret < 0 || ret != copied)
				goto fail;
			
			if (unlikely(transfer_result))
				goto fail;
			
			bv_offs += copied;
			len -= copied;
			offset = 0;
			//index++;
			pos += copied;
		}
		ret = 0;
		continue;
	fail:
		ret = -EIO;
	}
	
	mutex_unlock(&mapping->host->i_mutex);

	if (!ret)
		bio->bi_size = 0;

	mio->mars_endio(mio);

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

	MARS_DBG("now splice %p %p %p %p\n", output, mio, mio->orig_bio, p->bvec);

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
	loff_t pos = ((loff_t)bio->bi_sector << 9);
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
		if (ret < 0) {
			MARS_ERR("splice %p %p %p %p status=%d\n", output, mio, bio, bvec, ret);
			break;
		}
		pos += bvec->bv_len;
		bio->bi_size -= bvec->bv_len;

	}

	mio->mars_endio(mio);
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
#if 0
	unsigned long sector = bio->bi_sector;
	loff_t pos = sector << 9; //TODO: allow different sector sizes
	struct bio_vec *bvec;
	int i;
#endif
	int ret = -EIO;
	
	if (barrier) {
		MARS_INF("got barrier request\n");
		sync_file(output);
	}

	if (!output->filp)
		goto done;
#if 1
	if (direction == READ) {
		return read_aops(output, mio);
	} else {
		ret = write_aops(output, mio);
		if (barrier)
			sync_file(output);
		return ret;
	}
#else // toter code, war ein erster versuch
	bio_for_each_segment(bvec, bio, i) {
		mm_segment_t oldfs;
		unsigned long long ppos = pos;
		void *addr = kmap(bvec->bv_page) + bvec->bv_offset;
		unsigned int len = bvec->bv_len;

		MARS_DBG("IO dir=%d sector=%lu size=%d | pos=%llu len=%u addr=%p\n", direction, sector, bio->bi_size, pos, len, addr);

		oldfs = get_fs();
		set_fs(get_ds());
		
		if (direction == READ) {
			ret = do_sync_read(output->filp, addr, len, &ppos);
		} else {
			ret = do_sync_write(output->filp, addr, len, &ppos);
		}
		
		set_fs(oldfs);
		kunmap(bvec->bv_page);

		if (!ret) { // EOF
			MARS_DBG("EOF\n");
			addr = kmap(bvec->bv_page) + bvec->bv_offset;
			memset(addr, 0, len);
			kunmap(bvec->bv_page);
		} else if (ret != len) {
			MARS_ERR("IO error pos=%llu, len=%u, status=%d\n", pos, len, ret);
			goto done;
		}

		pos += len;

		ret = 0;
	}
#endif

done:
	if (!ret) {
		bio->bi_size = 0;
		if (direction == WRITE && barrier) {
			sync_file(output);
		}
	}
	mio->mars_endio(mio);
	return ret;
}

#ifdef WITH_THREAD
static int device_sio_mars_queue(struct device_sio_output *output, struct mars_io_object *mio)
{
	int index = 0;
	struct sio_threadinfo *tinfo;
	struct device_sio_mars_io_aspect *aspect;
	int direction = mio->orig_bio->bi_rw & 1;
	if (direction == READ) {
		spin_lock_irq(&output->g_lock);
		index = output->index++;
		spin_unlock_irq(&output->g_lock);
		index = (index % WITH_THREAD) + 1;
	}
	aspect = mars_io_get_aspect(mio, output->aspect_slot);
	tinfo = &output->tinfo[index];
	MARS_DBG("queueing %p on %d\n", mio, index);
	spin_lock_irq(&tinfo->lock);
	list_add_tail(&aspect->io_head, &tinfo->mio_list);
	spin_unlock_irq(&tinfo->lock);

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
		struct list_head *tmp;
		struct device_sio_mars_io_aspect *aspect;
		struct mars_io_object *mio;

		wait_event_interruptible(tinfo->event,
					 !list_empty(&tinfo->mio_list) ||
					 kthread_should_stop());

		if (list_empty(&tinfo->mio_list))
			continue;

		spin_lock_irq(&tinfo->lock);
		tmp = tinfo->mio_list.next;
		list_del_init(tmp);
		spin_unlock_irq(&tinfo->lock);

		aspect = container_of(tmp, struct device_sio_mars_io_aspect, io_head);
		mio = aspect->object;
		MARS_DBG("got %p %p\n", aspect, mio);
		device_sio_mars_io(output, mio);
	}

	MARS_INF("kthread has stopped.\n");
	return 0;
}
#endif

static int device_sio_get_info(struct device_sio_output *output, struct mars_info *info)
{
	struct file *file = output->filp;
	info->current_size = i_size_read(file->f_mapping->host);
	info->backing_file = file;
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int device_sio_aspect_init_fn(struct mars_io_aspect *_ini, void *_init_data)
{
	struct device_sio_mars_io_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static int device_sio_make_object_layout(struct device_sio_output *output, struct generic_object_layout *object_layout)
{
	const struct generic_object_type *object_type = object_layout->type;
	int slot;
	if (object_type != &mars_io_type)
		return 0;

	slot = mars_io_add_aspect(object_layout, sizeof(struct device_sio_mars_io_aspect), device_sio_aspect_init_fn, output);
	if (slot < 0)
		return slot;

	output->aspect_slot = slot;
	return sizeof(struct device_sio_mars_io_aspect);
}

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

#ifdef WITH_THREAD
	spin_lock_init(&output->g_lock);
	output->index = 0;
	for (index = 0; index <= WITH_THREAD; index++) {
		struct sio_threadinfo *tinfo = &output->tinfo[index];
		tinfo->output = output;
		spin_lock_init(&tinfo->lock);
		init_waitqueue_head(&tinfo->event);
		INIT_LIST_HEAD(&tinfo->mio_list);
		tinfo->thread = kthread_create(device_sio_thread, tinfo, "mars_sio%d", index);
		if (IS_ERR(tinfo->thread)) {
			int error = PTR_ERR(tinfo->thread);
			MARS_ERR("cannot create thread, status=%d\n", error);
			filp_close(output->filp, NULL);
			return error;
		}
		wake_up_process(tinfo->thread);
	}
#endif

	return 0;
}

static int device_sio_output_destruct(struct device_sio_output *output)
{
#ifdef WITH_THREAD
	int index;
	for (index = 0; index <= WITH_THREAD; index++) {
		kthread_stop(output->tinfo[index].thread);
		output->tinfo[index].thread = NULL;
	}
#endif
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
#ifdef WITH_THREAD
	.mars_io = device_sio_mars_queue,
#else
	.mars_io = device_sio_mars_io,
#endif
	.mars_get_info = device_sio_get_info,
};

static struct device_sio_output_type device_sio_output_type = {
	.type_name = "device_sio_output",
	.output_size = sizeof(struct device_sio_output),
	.master_ops = &device_sio_output_ops,
	.output_construct = &device_sio_output_construct,
	.output_destruct = &device_sio_output_destruct,
};

static struct device_sio_output_type *device_sio_output_types[] = {
	&device_sio_output_type,
};

struct device_sio_brick_type device_sio_brick_type = {
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
