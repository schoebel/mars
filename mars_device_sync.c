// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_device_sync.h"

////////////////// own brick / input / output operations //////////////////

static int device_sync_mars_io(struct device_sync_output *output, struct mars_io *mio)
{
	struct bio *bio = mio->orig_bio;
	mio->mars_endio(mio);
	return 0;
}

///////////////////////// contructors / destructors ////////////////////////

static int device_sync_brick_construct(struct device_sync_brick *brick)
{
	return 0;
}

static int device_sync_output_construct(struct device_sync_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct device_sync_brick_ops device_sync_brick_ops = {
};

static struct device_sync_output_ops device_sync_output_ops = {
	.mars_io = device_sync_mars_io,
};

static struct device_sync_output_type device_sync_output_type = {
	.type_name = "device_sync_output",
	.output_size = sizeof(struct device_sync_output),
	.master_ops = &device_sync_output_ops,
	.output_construct = &device_sync_output_construct,
};

static struct device_sync_output_type *device_sync_output_types[] = {
	&device_sync_output_type,
};

struct device_sync_brick_type device_sync_brick_type = {
	.type_name = "device_sync_brick",
	.brick_size = sizeof(struct device_sync_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &device_sync_brick_ops,
	.default_output_types = device_sync_output_types,
	.brick_construct = &device_sync_brick_construct,
};
EXPORT_SYMBOL_GPL(device_sync_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_device_sync(void)
{
	printk(MARS_INFO "init_device_sync()\n");
	return device_sync_register_brick_type();
}

static void __exit exit_device_sync(void)
{
	printk(MARS_INFO "exit_device_sync()\n");
	device_sync_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS device_sync brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_device_sync);
module_exit(exit_device_sync);
