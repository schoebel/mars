// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Interface to a Linux device.
 * 1 Input, 0 Outputs.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_if_device.h"

///////////////////////// own static definitions ////////////////////////

static int device_minor = 0;

//////////////// object / aspect constructors / destructors ///////////////

static struct mars_io_object_layout *if_device_init_object_layout(struct if_device_output *output)
{
	const int layout_size = 1024;
	const int max_aspects = 16;
	struct mars_io_object_layout *res;
	int status;
	void *data = kzalloc(layout_size, GFP_KERNEL);
	if (!data) {
		MARS_ERR("emergency, cannot allocate object_layout!\n");
		return NULL;
	}
	res = mars_io_init_object_layout(data, layout_size, max_aspects, &mars_io_type);
	if (unlikely(!res)) {
		MARS_ERR("emergency, cannot init object_layout!\n");
		goto err_free;
	}
	
	status = output->ops->make_object_layout(output, (struct generic_object_layout*)res);
	if (unlikely(status < 0)) {
		MARS_ERR("emergency, cannot add aspects to object_layout!\n");
		goto err_free;
	}
	MARS_INF("OK, object_layout init succeeded.\n");
	return res;

err_free:
	kfree(res);
	return NULL;
}

///////////////////////// linux operations ////////////////////////

/* callback
 */
static int if_device_endio(struct mars_io_object *mio)
{
	struct bio *bio = mio->orig_bio;
	if (bio) {
		mio->orig_bio = NULL;
		if (!bio->bi_size) {
			bio_endio(bio, 0);
		} else {
			MARS_ERR("NYI: RETRY LOGIC %u\n", bio->bi_size);
			bio_endio(bio, -EIO);
		}
	} // else lower layers have already signalled the orig_bio

	kfree(mio);
	return 0;
}

/* accept a linux bio, wrap it into struct mars_io_object and call mars_io() on it.
 */
static int if_device_make_request(struct request_queue *q, struct bio *bio)
{
	struct if_device_input *input = q->queuedata;
	struct if_device_output *output;
	struct mars_io_object *mio = NULL;
	void *data;
	int error = -ENOSYS;

	MARS_DBG("make_request(%d)\n", bio->bi_size);

	if (!input || !input->connect)
		goto err;

	output = input->connect;
	if (!output->ops || !output->ops->mars_io)
		goto err;

	error = -ENOMEM;
	if (unlikely(!input->mio_layout)) {
		input->mio_layout = if_device_init_object_layout(output);
		if (!input->mio_layout)
			goto err;
	}

	data = kzalloc(input->mio_layout->object_size, GFP_KERNEL);
	if (!data)
		goto err;

	mio = mars_io_construct(data, input->mio_layout);
	if (!mio)
		goto err_free;

	mio->orig_bio = bio;
	mio->mars_endio = if_device_endio;

	error = output->ops->mars_io(output, mio);
	if (error)
		goto err_free;

	return 0;

err_free:
	kfree(data);
err:
	MARS_ERR("cannot submit request, status=%d\n", error);
	if (!mio)
		bio_endio(bio, error);
	//else mars_endio() callback must have been called, which is responsible for cleanup
	return 0;
}

static int if_device_open(struct block_device *bdev, fmode_t mode)
{
	struct if_device_input *input = bdev->bd_disk->private_data;
	(void)input;
	MARS_DBG("if_device_open()\n");
	return 0;
}

static int if_device_release(struct gendisk *gd, fmode_t mode)
{
	MARS_DBG("if_device_close()\n");
	return 0;
}

static const struct block_device_operations if_device_blkdev_ops = {
	.owner =   THIS_MODULE,
	.open =    if_device_open,
	.release = if_device_release,

};

////////////////// own brick / input / output operations //////////////////

static void if_device_unplug(struct request_queue *q)
{
	//struct if_device_input *input = q->queuedata;
	MARS_DBG("UNPLUG\n");
	queue_flag_clear_unlocked(QUEUE_FLAG_PLUGGED, q);
	//blk_run_address_space(lo->lo_backing_file->f_mapping);
}


//////////////// object / aspect constructors / destructors ///////////////

static int if_device_mars_io_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	return 0;
}

static int if_device_mars_buf_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	return 0;
}

static int if_device_mars_buf_callback_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	return 0;
}

MARS_MAKE_STATICS(if_device);

//////////////////////// contructors / destructors ////////////////////////

static int if_device_brick_construct(struct if_device_brick *brick)
{
	return 0;
}

static int if_device_brick_destruct(struct if_device_brick *brick)
{
	return 0;
}

static int if_device_input_construct(struct if_device_input *input)
{
	struct request_queue *q;
	struct gendisk *disk;
	int minor;
	int capacity = 2 * 1024 * 1024 * 4; //TODO: make this dynamic

	MARS_DBG("1\n");
	q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		MARS_ERR("cannot allocate device request queue\n");
		return -ENOMEM;
	}
	q->queuedata = input;
	input->q = q;

	MARS_DBG("2\n");
	disk = alloc_disk(1);
	if (!disk) {
		MARS_ERR("cannot allocate gendisk\n");
		return -ENOMEM;
	}

	MARS_DBG("3\n");
	minor = device_minor++; //TODO: protect against races (e.g. atomic_t)
	disk->queue = q;
	disk->major = MARS_MAJOR; //TODO: make this dynamic for >256 devices
	disk->first_minor = minor;
	disk->fops = &if_device_blkdev_ops;
	sprintf(disk->disk_name, "mars%d", minor);
	MARS_DBG("created device name %s\n", disk->disk_name);
	disk->private_data = input;
	set_capacity(disk, capacity);

	blk_queue_make_request(q, if_device_make_request);
	blk_queue_max_segment_size(q, MARS_MAX_SEGMENT_SIZE);
	blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
	q->unplug_fn = if_device_unplug;
	spin_lock_init(&input->req_lock);
	q->queue_lock = &input->req_lock; // needed!
	//blk_queue_ordered(q, QUEUE_ORDERED_DRAIN, NULL);//???

	MARS_DBG("4\n");
	input->bdev = bdget(MKDEV(disk->major, minor));
	/* we have no partitions. we contain only ourselves. */
	input->bdev->bd_contains = input->bdev;

#if 0 // ???
	q->backing_dev_info.congested_fn = mars_congested;
	q->backing_dev_info.congested_data = input;
#endif

#if 0 // ???
	blk_queue_merge_bvec(q, mars_merge_bvec);
#endif

	// point of no return
	MARS_DBG("99999\n");
	add_disk(disk);
	input->disk = disk;
	//set_device_ro(input->bdev, 0); // TODO: implement modes
	return 0;
}

static int if_device_input_destruct(struct if_device_input *input)
{
	if (input->bdev)
		bdput(input->bdev);
	if (input->disk) {
		del_gendisk(input->disk);
		//put_disk(input->disk);
	}
	if (input->q)
		blk_cleanup_queue(input->q);
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct if_device_brick_ops if_device_brick_ops = {
};

static const struct if_device_input_type if_device_input_type = {
	.type_name = "if_device_input",
	.input_size = sizeof(struct if_device_input),
	.input_construct = &if_device_input_construct,
	.input_destruct = &if_device_input_destruct,
};

static const struct if_device_input_type *if_device_input_types[] = {
	&if_device_input_type,
};

const struct if_device_brick_type if_device_brick_type = {
	.type_name = "if_device_brick",
	.brick_size = sizeof(struct if_device_brick),
	.max_inputs = 1,
	.max_outputs = 0,
	.master_ops = &if_device_brick_ops,
	.default_input_types = if_device_input_types,
	.brick_construct = &if_device_brick_construct,
	.brick_destruct = &if_device_brick_destruct,
};
EXPORT_SYMBOL_GPL(if_device_brick_type);

////////////////// module init stuff /////////////////////////

static void __exit exit_if_device(void)
{
	int status;
	printk(MARS_INFO "exit_if_device()\n");
	status = if_device_unregister_brick_type();
	unregister_blkdev(DRBD_MAJOR, "mars");
}

static int __init init_if_device(void)
{
	int status;
	printk(MARS_INFO "init_if_device()\n");
	status = register_blkdev(DRBD_MAJOR, "mars");
	if (status)
		return status;
	status = if_device_register_brick_type();
	if (status)
		goto err_device;
	return status;
err_device:
	MARS_ERR("init_if_device() status=%d\n", status);
	exit_if_device();
	return status;
}

MODULE_DESCRIPTION("MARS if_device");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_if_device);
module_exit(exit_if_device);
