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

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_device_sio.h"

////////////////// own brick / input / output operations //////////////////

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

static int device_sio_write_aops(struct device_sio_output *output, struct mars_io *mio)
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

	blk_run_address_space(mapping);

	return ret;
}

static int device_sio_mars_io(struct device_sio_output *output, struct mars_io *mio)
{
	struct bio *bio = mio->orig_bio;
	int direction = bio->bi_rw & 1;
	unsigned long sector = bio->bi_sector;
	unsigned long long pos = sector << 9; //TODO: allow different sector sizes
	bool barrier = (direction != READ && bio_rw_flagged(bio, BIO_RW_BARRIER));
	struct bio_vec *bvec;
	int i;
	int ret = -EIO;
	
	if (barrier) {
		MARS_INF("got barrier request\n");
	}

	if (!output->filp)
		goto done;
#if 1
	if (direction == WRITE) {
		return device_sio_write_aops(output, mio);
	}
#endif

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

#if 0
		if (direction == WRITE) {
			struct inode *inode = output->filp->f_dentry->d_inode;
			struct address_space *mapping = inode->i_mapping;
			int res;

			res = sync_page_range(inode, mapping, pos, len);
			if (res) {
				MARS_ERR("syncing pages failed: %d\n", res);
			}
		}

#endif		
		pos += len;
		bio->bi_size -= len;
		ret = 0;
	}

done:
	mio->mars_endio(mio);
	return ret;
}

#ifdef WITH_THREAD
static int device_sio_mars_queue(struct device_sio_output *output, struct mars_io *mio)
{
	MARS_DBG("queue %p\n", mio);
	spin_lock_irq(&output->lock);
	list_add_tail(&mio->io_head, &output->mio_list);
	spin_unlock_irq(&output->lock);

	wake_up(&output->event);

	return 0;
}

static int device_sio_thread(void *data)
{
	struct device_sio_output *output = data;
	
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		struct mars_io *mio;

		wait_event_interruptible(output->event,
					 !list_empty(&output->mio_list) ||
					 kthread_should_stop());

		if (list_empty(&output->mio_list))
			continue;

		spin_lock_irq(&output->lock);
		mio = container_of(output->mio_list.next, struct mars_io, io_head);
		spin_unlock_irq(&output->lock);

		MARS_DBG("got %p\n", mio);
		device_sio_mars_io(output, mio);
	}

	MARS_INF("kthread has stopped.\n");
	return 0;
}
#endif

//////////////////////// constructors / destructors //////////////////////

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
	spin_lock_init(&output->lock);
	init_waitqueue_head(&output->event);
	INIT_LIST_HEAD(&output->mio_list);
	output->thread = kthread_create(device_sio_thread, output, "mars_sio%d", 0);
	if (IS_ERR(output->thread)) {
		int error = PTR_ERR(output->thread);
		MARS_ERR("cannot create thread, status=%d\n", error);
		filp_close(output->filp, NULL);
		return error;
	}
	wake_up_process(output->thread);
#endif

	return 0;
}

static int device_sio_output_destruct(struct device_sio_output *output)
{
#ifdef WITH_THREAD
	kthread_stop(output->thread);
	output->thread = NULL;
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
#ifdef WITH_THREAD
	.mars_io = device_sio_mars_queue,
#else
	.mars_io = device_sio_mars_io,
#endif
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
	printk(MARS_INFO "init_device_sio()\n");
	return device_sio_register_brick_type();
}

static void __exit exit_device_sio(void)
{
	printk(MARS_INFO "exit_device_sio()\n");
	device_sio_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS device_sio brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_device_sio);
module_exit(exit_device_sio);
