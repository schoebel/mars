// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#define _STRATEGY
#include "mars.h"

#include "mars_if_device.h"
#include "mars_dummy.h"
#include "mars_device_sio.h"
#include "mars_buf.h"
#include "mars_usebuf.h"

GENERIC_MAKE_CONNECT(if_device, device_sio);
GENERIC_MAKE_CONNECT(if_device, buf);
GENERIC_MAKE_CONNECT(if_device, dummy);
GENERIC_MAKE_CONNECT(if_device, usebuf);
GENERIC_MAKE_CONNECT(usebuf, dummy);
GENERIC_MAKE_CONNECT(buf, device_sio);
GENERIC_MAKE_CONNECT(dummy, buf);

static struct if_device_brick *if_brick = NULL;
static struct usebuf_brick *usebuf_brick = NULL;
static struct dummy_brick *dummy_brick = NULL;
static struct buf_brick *buf_brick = NULL;
static struct device_sio_brick *device_brick = NULL;

static int test_endio(struct mars_buf_object *mbuf)
{
	MARS_DBG("test_endio() called! error=%d\n", mbuf->cb_error);
	return 0;
}

void make_test_instance(void)
{
	static char *names[] = { "brick" };
	int size = 4096;
	int buf_size = 4096 * 8;
	int status;
	void *mem;

	mem = kzalloc(size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	MARS_DBG("starting....\n");

	status = device_sio_brick_init_full(mem, size, &device_sio_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (status) {
		MARS_ERR("cannot init brick device_sio\n");
		return;
	}
	device_brick = mem;

	mem = kzalloc(size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	status = if_device_brick_init_full(mem, size, &if_device_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (status) {
		MARS_ERR("cannot init brick if_device\n");
		return;
	}
	if_brick = mem;

	mem = kzalloc(size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	status = dummy_brick_init_full(mem, size, &dummy_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (status) {
		MARS_ERR("cannot init brick dummy\n");
		return;
	}
	dummy_brick = mem;

#if 1 // usebuf zwischenschalten
	mem = kzalloc(size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	status = usebuf_brick_init_full(mem, size, &usebuf_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (status) {
		MARS_ERR("cannot init brick usebuf\n");
		return;
	}
	usebuf_brick = mem;

	status = if_device_usebuf_connect(if_brick->inputs[0], usebuf_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);
	status = usebuf_dummy_connect(usebuf_brick->inputs[0], dummy_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);
#else
	(void)usebuf_brick;
	status = if_device_dummy_connect(if_brick->inputs[0], dummy_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);
#endif

#if 1 // buf zwischenschalten
	mem = kzalloc(buf_size, GFP_KERNEL);
	if (!mem) {
		MARS_ERR("cannot grab test memory\n");
		return;
	}

	status = buf_brick_init_full(mem, buf_size, &buf_brick_type, NULL, NULL, names);
	MARS_DBG("done (status=%d)\n", status);
	if (status) {
		MARS_ERR("cannot init brick buf\n");
		return;
	}
	buf_brick = mem;
	buf_brick->backing_order = 0;
	buf_brick->backing_size = PAGE_SIZE << buf_brick->backing_order;
	buf_brick->max_count = 512;

	status = buf_device_sio_connect(buf_brick->inputs[0], device_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);

	status = dummy_buf_connect(dummy_brick->inputs[0], buf_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);

	if (true) {
		struct buf_output *output = buf_brick->outputs[0];
		struct mars_buf_object *mbuf = NULL;
		struct mars_alloc_helper h = {};

		//mars_init_helper(&h);

		status = GENERIC_OUTPUT_CALL(output, mars_buf_get, &mbuf, &h, 0, PAGE_SIZE);
		MARS_DBG("buf_get (status=%d)\n", status);

		if (mbuf) {
			if (true) {
				mbuf->cb_rw = READ;
				mbuf->cb_buf_endio = test_endio;

				status = GENERIC_OUTPUT_CALL(output, mars_buf_io, mbuf);
				MARS_DBG("buf_io (status=%d)\n", status);
			}
			status = GENERIC_OUTPUT_CALL(output, mars_buf_put, mbuf);
			MARS_DBG("buf_put (status=%d)\n", status);
		}
	}
#else

	status = dummy_device_sio_connect(dummy_brick->inputs[0], device_brick->outputs[0]);
	MARS_DBG("connect (status=%d)\n", status);
#endif

}

void destroy_test_instance(void)
{
	if (if_brick) {
		if_device_device_sio_disconnect(if_brick->inputs[0]);
		if_device_brick_exit_full(if_brick);
		kfree(if_brick);
		if_brick = NULL;
	}
	if (buf_brick) {
		buf_device_sio_disconnect(buf_brick->inputs[0]);
		buf_brick_exit_full(buf_brick);
		kfree(buf_brick);
		buf_brick = NULL;
	}
	if (device_brick) {
		device_sio_brick_exit_full(device_brick);
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
