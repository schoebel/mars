// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Check brick
 * checks various semantic properties, uses watchdog to find lost callbacks.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kthread.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_check.h"

///////////////////////// own helper functions ////////////////////////

#define CHECK_ERR(output,fmt,args...)					\
	do {								\
		struct check_input *input = (output)->brick->inputs[0];	\
		struct generic_output *other = (void*)input->connect;	\
		if (other) {						\
			MARS_ERR("instance %d/%s/%s: " fmt,		\
				 (output)->instance_nr,			\
				 other->type->type_name,		\
				 other->output_name,			\
				 ##args);				\
		} else {						\
			MARS_ERR("instance %d: " fmt,			\
				 (output)->instance_nr,			\
				 ##args);				\
		}							\
	} while (0)

static void check_buf_endio(struct generic_callback *cb)
{
	struct check_mref_aspect *mref_a;
	struct mref_object *mref;
	struct check_output *output;
	struct check_input *input;
	struct generic_callback *prev_cb;
	unsigned long flags;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, fatal);
	_CHECK(&mref_a->cb == cb, fatal);

	mref = mref_a->object;
	CHECK_PTR(mref, fatal);

	output = mref_a->output;
	CHECK_PTR(output, fatal);

	input = output->brick->inputs[0];
	CHECK_PTR(input, fatal);

	if (atomic_dec_and_test(&mref_a->callback_count)) {
		atomic_set(&mref_a->callback_count, 1);
		CHECK_ERR(output, "too many callbacks on %p\n", mref);
	}

#ifdef CHECK_LOCK
	traced_lock(&output->check_lock, flags);

	if (list_empty(&mref_a->mref_head)) {
		CHECK_ERR(output, "list entry missing on %p\n", mref);
	}
	list_del_init(&mref_a->mref_head);

	traced_unlock(&output->check_lock, flags);
#else
	(void)flags;
#endif

	mref_a->last_jiffies = jiffies;

	prev_cb = cb->cb_prev;
	if (!prev_cb) {
		MARS_FAT("cannot get chain callback\n");
		return;
	}
#if 1
	mref->ref_cb = prev_cb;
	mref_a->installed = false;
#endif
	prev_cb->cb_fn(prev_cb);
	return;
fatal:
	msleep(60000);
	return;
}

#ifdef CHECK_LOCK
static void dump_mem(void *data, int len)
{
	int i;
	char *tmp;
	char *buf = brick_string_alloc();

	if (!buf)
		return;

	for (i = 0, tmp = buf; i < len; i++) {
		unsigned char byte = ((unsigned char*)data)[i];
		if (!(i % 8)) {
			if (tmp != buf) {
				printk("%4d: %s\n", i, buf);
			}
			tmp = buf;
		}
		tmp += snprintf(tmp, 1024 - i * 3, " %02x", byte);
	}
	if (tmp != buf) {
		printk("%4d: %s\n", i, buf);
	}
	brick_string_free(buf);
}

static int check_watchdog(void *data)
{
	struct check_output *output = data;
	MARS_INF("watchdog has started.\n");
	while (!kthread_should_stop()) {
		struct list_head *h;
		unsigned long flags;
		unsigned long now;

		msleep_interruptible(5000);

		traced_lock(&output->check_lock, flags);

		now = jiffies;
		for (h = output->mref_anchor.next; h != &output->mref_anchor; h = h->next) {
			static int limit = 1;
			const int timeout = 30;
			struct check_mref_aspect *mref_a;
			struct mref_object *mref;
			unsigned long elapsed;

			mref_a = container_of(h, struct check_mref_aspect, mref_head);
			mref = mref_a->object;
			elapsed = now - mref_a->last_jiffies;
			if (elapsed > timeout * HZ && limit-- > 0) {
				struct generic_object_layout *object_layout;
				int i;
				mref_a->last_jiffies = now + 600 * HZ;
				MARS_INF("================================\n");
				CHECK_ERR(output, "mref %p callback is missing for more than %d seconds.\n", mref, timeout);
				object_layout = (void*)mref->object_layout;
				//dump_mem(mref, object_layout->object_size);
				for (i = 0; i < object_layout->aspect_count; i++) {
					struct generic_aspect_layout *aspect_layout;
					int pos;
					aspect_layout = object_layout->aspect_layouts_table[i];
					pos = aspect_layout->aspect_offset;
					if (i == 0) {
						MARS_INF("object %s:\n", object_layout->object_type->object_type_name);
						dump_mem(mref, pos);
					}
					MARS_INF("--- aspect %s ---:\n", aspect_layout->aspect_type->aspect_type_name);
					dump_mem(((void*)mref + pos), aspect_layout->aspect_type->aspect_size);
				}
				MARS_INF("================================\n");
			}
		}

		traced_unlock(&output->check_lock, flags);
	}
	return 0;
}
#endif

////////////////// own brick / input / output operations //////////////////

static int check_get_info(struct check_output *output, struct mars_info *info)
{
	struct check_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int check_ref_get(struct check_output *output, struct mref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mref_get, mref);
}

static void check_ref_put(struct check_output *output, struct mref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mref_put, mref);
}

static void check_ref_io(struct check_output *output, struct mref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	struct check_mref_aspect *mref_a = check_mref_get_aspect(output, mref);
	unsigned long flags;

	CHECK_PTR(mref_a, fatal);

	if (atomic_dec_and_test(&mref_a->call_count)) {
		atomic_set(&mref_a->call_count, 1);
		CHECK_ERR(output, "multiple parallel calls on %p\n", mref);
	}
	atomic_set(&mref_a->callback_count, 2);

#ifdef CHECK_LOCK
	traced_lock(&output->check_lock, flags);

	if (!list_empty(&mref_a->mref_head)) {
		CHECK_ERR(output, "list head not empty on %p\n", mref);
		list_del(&mref_a->mref_head);
	}
	list_add_tail(&mref_a->mref_head, &output->mref_anchor);

	traced_unlock(&output->check_lock, flags);
#else
	(void)flags;
#endif

	if (!mref_a->installed) {
		struct generic_callback *cb = &mref_a->cb;
		mref_a->installed = true;
		mref_a->output = output;
		cb->cb_fn = check_buf_endio;
		cb->cb_private = mref_a;
		cb->cb_error = 0;
		cb->cb_prev = mref->ref_cb;
		mref->ref_cb = cb;
	}
	mref_a->last_jiffies = jiffies;

	GENERIC_INPUT_CALL(input, mref_io, mref);

	atomic_inc(&mref_a->call_count);
fatal: ;
}

//////////////// object / aspect constructors / destructors ///////////////

static int check_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct check_mref_aspect *ini = (void*)_ini;
#ifdef CHECK_LOCK
	INIT_LIST_HEAD(&ini->mref_head);
#endif
	ini->last_jiffies = jiffies;
	atomic_set(&ini->call_count, 2);
	atomic_set(&ini->callback_count, 1);
	ini->installed = false;
	return 0;
}

static void check_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct check_mref_aspect *ini = (void*)_ini;
	(void)ini;
#ifdef CHECK_LOCK
	if (!list_empty(&ini->mref_head)) {
		struct check_output *output = ini->output;
		if (output) {
			CHECK_ERR(output, "list head not empty on %p\n", ini->object);
			INIT_LIST_HEAD(&ini->mref_head);
		} else {
			CHECK_HEAD_EMPTY(&ini->mref_head);
		}
	}
#endif
}

MARS_MAKE_STATICS(check);

////////////////////// brick constructors / destructors ////////////////////

static int check_brick_construct(struct check_brick *brick)
{
	return 0;
}

static int check_output_construct(struct check_output *output)
{
	static int count = 0;
#ifdef CHECK_LOCK
	struct task_struct *watchdog;

	spin_lock_init(&output->check_lock);
	INIT_LIST_HEAD(&output->mref_anchor);
	watchdog = kthread_create(check_watchdog, output, "check_watchdog%d", output->instance_nr);
	if (!IS_ERR(watchdog)) {
		output->watchdog = watchdog;
		wake_up_process(watchdog);
	}
#endif
	output->instance_nr = ++count;
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct check_brick_ops check_brick_ops = {
};

static struct check_output_ops check_output_ops = {
	.make_object_layout = check_make_object_layout,
	.mars_get_info = check_get_info,
	.mref_get = check_ref_get,
	.mref_put = check_ref_put,
	.mref_io = check_ref_io,
};

const struct check_input_type check_input_type = {
	.type_name = "check_input",
	.input_size = sizeof(struct check_input),
};

static const struct check_input_type *check_input_types[] = {
	&check_input_type,
};

const struct check_output_type check_output_type = {
	.type_name = "check_output",
	.output_size = sizeof(struct check_output),
	.master_ops = &check_output_ops,
	.output_construct = &check_output_construct,
	.aspect_types = check_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
};

static const struct check_output_type *check_output_types[] = {
	&check_output_type,
};

const struct check_brick_type check_brick_type = {
	.type_name = "check_brick",
	.brick_size = sizeof(struct check_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &check_brick_ops,
	.default_input_types = check_input_types,
	.default_output_types = check_output_types,
	.brick_construct = &check_brick_construct,
};
EXPORT_SYMBOL_GPL(check_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_check(void)
{
	printk(MARS_INFO "init_check()\n");
	return check_register_brick_type();
}

static void __exit exit_check(void)
{
	printk(MARS_INFO "exit_check()\n");
	check_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS check brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_check);
module_exit(exit_check);
