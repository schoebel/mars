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
#include "mars_check.h"
#include "mars_device_sio.h"
#include "mars_buf.h"
#include "mars_usebuf.h"

GENERIC_ASPECT_FUNCTIONS(generic,mars_buf);

static struct generic_brick *if_brick = NULL;
static struct generic_brick *usebuf_brick = NULL;
static struct generic_brick *buf_brick = NULL;
static struct buf_brick *_buf_brick = NULL;
static struct generic_brick *device_brick = NULL;

static void test_endio(struct mars_buf_object *mbuf)
{
	MARS_DBG("test_endio() called! error=%d\n", mbuf->cb_error);
}

void make_test_instance(void)
{
	static char *names[] = { "brick" };
	struct generic_input *last = NULL;

	void *brick(const void *_brick_type)
	{
		const struct generic_brick_type *brick_type = _brick_type;
		void *mem = kzalloc(brick_type->brick_size, GFP_MARS);
		int status;
		if (!mem) {
			MARS_ERR("cannot grab test memory\n");
			return NULL;
		}
		status = generic_brick_init_full(mem, brick_type->brick_size, brick_type, NULL, NULL, names);
		MARS_DBG("done (status=%d)\n", status);
		if (status) {
			MARS_ERR("cannot init brick device_sio\n");
			return NULL;
		}
		return mem;
	}

	void connect(struct generic_input *a, struct generic_output *b)
	{
		int status = generic_connect(a, b);
		MARS_DBG("connect (status=%d)\n", status);
	}


	MARS_DBG("starting....\n");

	device_brick = brick(&device_sio_brick_type);

	if_brick = brick(&if_device_brick_type);

#if 1 // usebuf zwischenschalten
	usebuf_brick = brick(&usebuf_brick_type);

	connect(if_brick->inputs[0], usebuf_brick->outputs[0]);

	last = usebuf_brick->inputs[0];
#else
	(void)usebuf_brick;
	last = if_brick->inputs[0];
#endif

#if 1 // buf zwischenschalten
	buf_brick = brick(&buf_brick_type);
	_buf_brick = (void*)buf_brick;
	//_buf_brick->backing_order = 4;
	_buf_brick->backing_order = 0;
	_buf_brick->backing_size = PAGE_SIZE << _buf_brick->backing_order;
	_buf_brick->max_count = 512;

	connect(last, buf_brick->outputs[0]);

	connect(buf_brick->inputs[0], device_brick->outputs[0]);

	if (true) {
		struct buf_output *output = _buf_brick->outputs[0];
		struct mars_buf_object *mbuf = NULL;
		struct generic_object_layout ol = {};

		mbuf = generic_alloc_mars_buf((struct generic_output*)output, &ol);

		if (mbuf) {
			int status;
			mbuf->buf_pos = 0;
			mbuf->buf_len = PAGE_SIZE;
			mbuf->buf_may_write = READ;

			status = GENERIC_OUTPUT_CALL(output, mars_buf_get, mbuf);
			MARS_DBG("buf_get (status=%d)\n", status);
			if (true) {
				mbuf->cb_buf_endio = test_endio;

				GENERIC_OUTPUT_CALL(output, mars_buf_io, mbuf, READ);
				status = mbuf->cb_error;
				MARS_DBG("buf_io (status=%d)\n", status);
			}
			GENERIC_OUTPUT_CALL(output, mars_buf_put, mbuf);
		}
	}
#else
	(void)test_endio;
	connect(last, device_brick->outputs[0]);
#endif
}

void destroy_test_instance(void)
{
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
