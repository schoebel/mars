// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#define DEFAULT_ORDER    0
//#define DEFAULT_BUFFERS (32768 / 2)
//#define DEFAULT_MEM     (1024 / 4 * 1024)
#define DEFAULT_MEM     (1024 / 4 * 1024 / 4)

#define TRANS_ORDER    4
#define TRANS_BUFFERS (32)
#define TRANS_MEM     (1024 / 4)

//#define CONF_TEST // use intermediate mars_check bricks

#define CONF_AIO // use aio instead of sio
//#define CONF_BUF
#define CONF_BUF_AHEAD // readahead optimization
//#define CONF_USEBUF
//#define CONF_TRANS
#define CONF_TRANS_LOG_READS false
//#define CONF_TRANS_LOG_READS true
#define CONF_TRANS_FLYING 32
#define CONF_TRANS_MAX_QUEUE 1000
#define CONF_TRANS_MAX_JIFFIES (5 * HZ)
#define CONF_TRANS_SORT
//#define CONF_TBUF

//#define CONF_DIRECT // use O_DIRECT
#define CONF_FDSYNC // use additional aio_fdsync

#define DIRECT

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/debug_locks.h>

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#define _STRATEGY
#include "mars.h"

#include "mars_if.h"
#include "mars_check.h"
#include "mars_sio.h"
#include "mars_aio.h"
#include "mars_buf.h"
#include "mars_usebuf.h"
#include "mars_trans_logger.h"

GENERIC_ASPECT_FUNCTIONS(generic,mref);

#ifdef CONF_AIO
#define sio_brick aio_brick
#define sio_brick_type aio_brick_type
#endif

static struct generic_brick *if_brick = NULL;
static struct if_brick *_if_brick = NULL;
static struct generic_brick *usebuf_brick = NULL;

static struct generic_brick *trans_brick = NULL;
static struct trans_logger_brick *_trans_brick = NULL;
static struct generic_brick *tbuf_brick = NULL;
static struct buf_brick *_tbuf_brick = NULL;
static struct generic_brick *tdevice_brick = NULL;
static struct sio_brick *_tdevice_brick = NULL;

static struct generic_brick *buf_brick = NULL;
static struct buf_brick *_buf_brick = NULL;
static struct generic_brick *device_brick = NULL;
static struct sio_brick *_device_brick = NULL;

void make_test_instance(void)
{
	static const char *names[] = { "brick" };
	struct generic_output *first = NULL;
	struct generic_output *inter = NULL;
	struct generic_input *last = NULL;

	void *brick(const void *_brick_type)
	{
		const struct generic_brick_type *brick_type = _brick_type;
		const struct generic_input_type **input_types;
		const struct generic_output_type **output_types;
		void *mem;
		int size;
		int i;
		int status;

		size = brick_type->brick_size +
			(brick_type->max_inputs + brick_type->max_outputs) * sizeof(void*);
		input_types = brick_type->default_input_types;
		for (i = 0; i < brick_type->max_inputs; i++) {
			const struct generic_input_type *type = *input_types++;
			size += type->input_size;
		}
		output_types = brick_type->default_output_types;
		for (i = 0; i < brick_type->max_outputs; i++) {
			const struct generic_output_type *type = *output_types++;
			size += type->output_size;
		}

		mem = kzalloc(size, GFP_MARS);
		if (!mem) {
			MARS_ERR("cannot grab test memory for %s\n", brick_type->type_name);
			msleep(60000);
			return NULL;
		}
		status = generic_brick_init_full(mem, size, brick_type, NULL, NULL, names);
		MARS_INF("init '%s' (status=%d)\n", brick_type->type_name, status);
		if (status) {
			MARS_ERR("cannot init brick %s\n", brick_type->type_name);
			msleep(60000);
			return NULL;
		}
		return mem;
	}

	void connect(struct generic_input *a, struct generic_output *b)
	{
		int status;
#ifdef CONF_TEST
		struct generic_brick *tmp = brick(&check_brick_type);
		
		status = generic_connect(a, tmp->outputs[0]);
		MARS_DBG("connect (status=%d)\n", status);
		if (status < 0)
			msleep(60000);

		status = generic_connect(tmp->inputs[0], b);
#else
		status = generic_connect(a, b);
#endif
		MARS_DBG("connect (status=%d)\n", status);
		if (status < 0)
			msleep(60000);
	}


	MARS_DBG("starting....\n");

	// first
	device_brick = brick(&sio_brick_type);
	_device_brick = (void*)device_brick;
	device_brick->outputs[0]->output_name = "/tmp/testfile.img";
#ifdef CONF_DIRECT
	_device_brick->o_direct = true;
#endif
#ifdef CONF_FDSYNC
	_device_brick->o_fdsync = true;
#endif
	mars_power_button((void*)device_brick, true);
	first = device_brick->outputs[0];

	// last
	if_brick = brick(&if_brick_type);
	last = if_brick->inputs[0];

#ifdef CONF_USEBUF // usebuf zwischenschalten
	usebuf_brick = brick(&usebuf_brick_type);
	connect(last, usebuf_brick->outputs[0]);
	last = usebuf_brick->inputs[0];
#else
	(void)usebuf_brick;
#endif

#ifdef CONF_BUF // Standard-buf zwischenschalten
	buf_brick = brick(&buf_brick_type);
	_buf_brick = (void*)buf_brick;
	_buf_brick->outputs[0]->output_name = "/tmp/testfile.img";
	_buf_brick->backing_order = DEFAULT_ORDER;
	_buf_brick->backing_size = PAGE_SIZE << _buf_brick->backing_order;
#ifdef DEFAULT_BUFFERS
	_buf_brick->max_count = DEFAULT_BUFFERS;
#else
	_buf_brick->max_count = DEFAULT_MEM >> _buf_brick->backing_order;
#endif
#ifdef CONF_BUF_AHEAD
	_buf_brick->optimize_chains = true;
#endif

	connect(buf_brick->inputs[0], first);
	first = buf_brick->outputs[0];

#else // CONF_BUF
	(void)buf_brick;
	(void)_buf_brick;
#endif // CONF_BUF


#ifdef CONF_TRANS // trans_logger plus Infrastruktur zwischenschalten

	tdevice_brick = brick(&sio_brick_type);
	_tdevice_brick = (void*)tdevice_brick;
	tdevice_brick->outputs[0]->output_name = "/tmp/testfile.log";
#ifdef CONF_DIRECT
	_tdevice_brick->o_direct = true;
#endif
#ifdef CONF_FDSYNC
	_tdevice_brick->o_fdsync = true;
#endif
	tdevice_brick->ops->brick_switch(tdevice_brick, true);
	inter = tdevice_brick->outputs[0];

#ifdef CONF_TBUF
	tbuf_brick = brick(&buf_brick_type);
	_tbuf_brick = (void*)tbuf_brick;
	_tbuf_brick->outputs[0]->output_name = "/tmp/testfile.log";
	_tbuf_brick->backing_order = TRANS_ORDER;
	_tbuf_brick->backing_size = PAGE_SIZE << _tbuf_brick->backing_order;
#ifdef TRANS_BUFFERS
	_tbuf_brick->max_count = TRANS_BUFFERS;
#else
	_tbuf_brick->max_count = TRANS_MEM >> _tbuf_brick->backing_order;
#endif

	connect(tbuf_brick->inputs[0], inter);
	inter = tbuf_brick->outputs[0];
#else
	(void)tbuf_brick;
	(void)_tbuf_brick;
#endif // CONF_TBUF

	trans_brick = brick(&trans_logger_brick_type);
	_trans_brick = (void*)trans_brick;
	_trans_brick->log_reads = CONF_TRANS_LOG_READS;
	_trans_brick->outputs[0]->q_phase2.q_max_queued = CONF_TRANS_MAX_QUEUE;
	_trans_brick->outputs[0]->q_phase4.q_max_queued = CONF_TRANS_MAX_QUEUE;
	_trans_brick->outputs[0]->q_phase2.q_max_jiffies = CONF_TRANS_MAX_JIFFIES;
	_trans_brick->outputs[0]->q_phase4.q_max_jiffies = CONF_TRANS_MAX_JIFFIES;
	_trans_brick->outputs[0]->q_phase2.q_max_flying = CONF_TRANS_FLYING;
	_trans_brick->outputs[0]->q_phase4.q_max_flying = CONF_TRANS_FLYING;
#ifdef CONF_TRANS_SORT
	_trans_brick->outputs[0]->q_phase2.q_ordering = true;
	_trans_brick->outputs[0]->q_phase4.q_ordering = true;
#endif

	connect(trans_brick->inputs[0], first);
	connect(trans_brick->inputs[1], inter);
	first = trans_brick->outputs[0];

#else // CONF_TRANS
	(void)trans_brick;
	(void)_trans_brick;
	(void)tdevice_brick;
	(void)_tdevice_brick;
	(void)inter;
	(void)tbuf_brick;
	(void)_tbuf_brick;
#endif // CONF_TRANS

	connect(last, first);

	msleep(200);

	MARS_INF("------------- END INIT --------------\n");

	_if_brick = (void*)if_brick;
	{
		struct mars_info info = {};
		int status = GENERIC_INPUT_CALL(_if_brick->inputs[0], mars_get_info, &info);
		MARS_INF("INFO status=%d size=%lld transfer_order=%d transfer_size=%d %p\n", status, info.current_size, info.transfer_order, info.transfer_size, info.backing_file);
	}

	MARS_INF("------------- START GATE --------------\n");

	mars_power_button((void*)if_brick, true);
	//_if_brick->is_active = true;

	msleep(2000);
	MARS_INF("------------- DONE --------------\n");
//msleep(1000 * 92);
	// FIXME: this is never released!
	atomic_inc(&current->mm->mm_users);
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
#if 0
	debug_locks_off();
#endif
	make_test_instance();
	return 0;
}

MODULE_DESCRIPTION("MARS TEST");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_test);
module_exit(exit_test);
