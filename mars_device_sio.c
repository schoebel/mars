// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_device_sio.h"

////////////////// own brick / input / output operations //////////////////

static int device_sio_mars_io(struct device_sio_output *output, struct mars_io *mio)
{
	struct bio *bio = mio->orig_bio;
	int direction = bio->bi_rw & 1;
	//unsigned int nr_sectors = bio_sectors(bio);
	unsigned long sector = bio->bi_sector;
	unsigned long long pos = sector << 9; //TODO: allow different sector sizes
	struct bio_vec *bvec;
	int i;
	int ret = -EIO;
	
	if (!output->filp)
		goto done;

	bio_for_each_segment(bvec, bio, i) {
		mm_segment_t oldfs;
		unsigned long long ppos = pos;
		void *addr = kmap(bvec->bv_page) + bvec->bv_offset;
		unsigned int len = bvec->bv_len;

		MARS_DBG("IO dir=%d sector=%lu size=%d | pos=%llu len=%u addr=%p\n", direction, sector, bio->bi_size, pos, len, addr);

		oldfs = get_fs();
		set_fs(get_ds());
		
		if (direction == READ)
			ret = do_sync_read(output->filp, addr, len, &ppos);
		else
			ret = do_sync_write(output->filp, addr, len, &ppos);
		
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
		bio->bi_size -= len;
		ret = 0;
	}

done:
	mio->mars_endio(mio);
	return ret;
}

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

	return 0;
}

static int device_sio_output_destruct(struct device_sio_output *output)
{
	if (output->filp) {
		filp_close(output->filp, NULL);
	}

	return 0;
}

///////////////////////// static structs ////////////////////////

static struct device_sio_brick_ops device_sio_brick_ops = {
};

static struct device_sio_output_ops device_sio_output_ops = {
	.mars_io = device_sio_mars_io,
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
