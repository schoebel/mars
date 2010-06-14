// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#define _STRATEGY
#include "mars.h"

#include "mars_if_device.h"
#include "mars_device_sync.h"

GENERIC_MAKE_CONNECT(if_device, device_sync);

static struct if_device_brick *if_brick = NULL;
static struct device_sync_brick *device_brick = NULL;

void make_test_instance(void)
{
	static char *names[] = { "brick" };
	int size = 1024;
	int status;
	void *mem = kzalloc(size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	MARS_DBG("starting....\n");

	status = device_sync_brick_init_full(mem, size, &device_sync_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (!status)
		device_brick = mem;

	mem = kzalloc(size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	status = if_device_brick_init_full(mem, size, &if_device_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (!status)
		if_brick = mem;

	status = if_device_device_sync_connect(if_brick->inputs[0], device_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);

}

void destroy_test_instance(void)
{
	if (if_brick) {
		if_device_device_sync_disconnect(if_brick->inputs[0]);
		if_device_brick_exit_full(if_brick);
		kfree(if_brick);
		if_brick = NULL;
	}
	if (device_brick) {
		device_sync_brick_exit_full(device_brick);
		kfree(device_brick);
		device_brick = NULL;
	}
}

static void __exit exit_test(void)
{
	MARS_DBG("destroy_test_instance()\n");
	destroy_test_instance();
}

static int __init init_test(void)
{
	MARS_DBG("make_test_instance()\n");
	make_test_instance();
	return 0;
}

MODULE_DESCRIPTION("MARS TEST");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_test);
module_exit(exit_test);
