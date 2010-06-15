// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_device_sio.h"

////////////////// own brick / input / output operations //////////////////

static int device_sio_mars_io(struct device_sio_output *output, struct mars_io *mio)
{
	struct bio *bio = mio->orig_bio;
	mio->mars_endio(mio);
	return 0;
}

///////////////////////// contructors / destructors ////////////////////////

static int device_sio_brick_construct(struct device_sio_brick *brick)
{
	return 0;
}

static int device_sio_output_construct(struct device_sio_output *output)
{
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
