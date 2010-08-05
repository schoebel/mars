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

static void check_buf_endio(struct mars_ref_object *mref)
{
	struct check_output *output = mref->cb_private;
	struct check_input *input = output->brick->inputs[0];
	struct check_mars_ref_aspect *mref_a = check_mars_ref_get_aspect(output, mref);
	unsigned long flags;

	if (!mref_a) {
		MARS_FAT("cannot get aspect -- hanging up\n");
		msleep(60000);
		return;
	}

	traced_lock(&output->lock, flags);

	if (mref_a->call_count-- < 0) {
		mref_a->call_count = 0;
		MARS_ERR("instance %d/%s: too many callbacks on %p\n", output->instance_nr, input->connect->type->type_name, mref);
	}
	if (list_empty(&mref_a->mref_head)) {
		MARS_ERR("instance %d/%s: list entry missing on %p\n", output->instance_nr, input->connect->type->type_name, mref);
	}
	list_del_init(&mref_a->mref_head);

	traced_unlock(&output->lock, flags);

	mref->cb_private = mref_a->old_private;
	mref_a->last_jiffies = jiffies;
	mref_a->old_buf_endio(mref);
	mref->cb_private = output;
}

static void dump_mem(void *data, int len)
{
	int i;
	char *tmp;
	char buf[256];
	for (i = 0, tmp = buf; i < len; i++) {
		unsigned char byte = ((unsigned char*)data)[i];
		if (!(i % 8)) {
			if (tmp != buf) {
				MARS_INF("%4d: %s\n", i, buf);
			}
			tmp = buf;
		}
		tmp += sprintf(tmp, " %02x", byte);
	}
	if (tmp != buf) {
		MARS_INF("%4d: %s\n", i, buf);
	}
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

		traced_lock(&output->lock, flags);

		now = jiffies;
		for (h = output->mref_anchor.next; h != &output->mref_anchor; h = h->next) {
			struct check_mars_ref_aspect *mref_a;
			struct mars_ref_object *mref;
			unsigned long elapsed;

			mref_a = container_of(h, struct check_mars_ref_aspect, mref_head);
			mref = mref_a->object;
			elapsed = now - mref_a->last_jiffies;
			if (elapsed > 10 * HZ) {
				struct generic_object_layout *object_layout;
				int i;
				mref_a->last_jiffies = now + 600 * HZ;
				MARS_ERR("================================\n");
				MARS_ERR("instance %d: mref %p callback is missing for more than 10 seconds.\n", output->instance_nr, mref);
				object_layout = (void*)mref->object_layout;
				//dump_mem(mref, object_layout->object_size);
				for (i = 0; i < object_layout->aspect_count; i++) {
					struct generic_aspect_layout *aspect_layout;
					int pos;
					aspect_layout = object_layout->aspect_layouts[i];
					pos = aspect_layout->aspect_offset;
					if (i == 0) {
						MARS_INF("object %s:\n", object_layout->object_type->object_type_name);
						dump_mem(mref, pos);
					}
					MARS_INF("--- aspect %s ---:\n", aspect_layout->aspect_type->aspect_type_name);
					dump_mem(((void*)mref + pos), aspect_layout->aspect_type->aspect_size);
				}
				MARS_ERR("================================\n");
			}
		}
		traced_unlock(&output->lock, flags);
	}
	return 0;
}

////////////////// own brick / input / output operations //////////////////

static int check_get_info(struct check_output *output, struct mars_info *info)
{
	struct check_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int check_ref_get(struct check_output *output, struct mars_ref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_ref_get, mref);
}

static void check_ref_put(struct check_output *output, struct mars_ref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mars_ref_put, mref);
}

static void check_ref_io(struct check_output *output, struct mars_ref_object *mref, int rw)
{
	struct check_input *input = output->brick->inputs[0];
	struct check_mars_ref_aspect *mref_a = check_mars_ref_get_aspect(output, mref);
	unsigned long flags;

	if (!mref_a) {
		MARS_FAT("cannot get aspect -- hanging up\n");
		msleep(60000);
		return;
	}

	traced_lock(&output->lock, flags);
	if (mref_a->call_count++ > 1) {
		mref_a->call_count = 1;
		MARS_ERR("instance %d/%s: multiple parallel calls on %p\n", output->instance_nr, input->connect->type->type_name, mref);
	}
	if (!list_empty(&mref_a->mref_head)) {
		list_del(&mref_a->mref_head);
		MARS_ERR("instance %d/%s: list head not empty on %p\n", output->instance_nr, input->connect->type->type_name, mref);
	}
	list_add_tail(&mref_a->mref_head, &output->mref_anchor);
	if (mref->cb_ref_endio != check_buf_endio) {
		mref_a->old_buf_endio = mref->cb_ref_endio;
		mref->cb_ref_endio = check_buf_endio;
		mref_a->old_private = mref->cb_private;
		mref->cb_private = output;
	}
	mref_a->last_jiffies = jiffies;
	traced_unlock(&output->lock, flags);

	GENERIC_INPUT_CALL(input, mars_ref_io, mref, rw);
}

//////////////// object / aspect constructors / destructors ///////////////

static int check_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct check_mars_ref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->mref_head);
	ini->call_count = 0;
	return 0;
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
	struct task_struct *watchdog;

	spin_lock_init(&output->lock);
	output->instance_nr = ++count;
	INIT_LIST_HEAD(&output->mio_anchor);
	INIT_LIST_HEAD(&output->mref_anchor);
	watchdog = kthread_create(check_watchdog, output, "check_watchdog%d", output->instance_nr);
	if (!IS_ERR(watchdog)) {
		output->watchdog = watchdog;
		wake_up_process(watchdog);
	}
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct check_brick_ops check_brick_ops = {
};

static struct check_output_ops check_output_ops = {
	.make_object_layout = check_make_object_layout,
	.mars_get_info = check_get_info,
	.mars_ref_get = check_ref_get,
	.mars_ref_put = check_ref_put,
	.mars_ref_io = check_ref_io,
};

static const struct check_input_type check_input_type = {
	.type_name = "check_input",
	.input_size = sizeof(struct check_input),
};

static const struct check_input_type *check_input_types[] = {
	&check_input_type,
};

static const struct check_output_type check_output_type = {
	.type_name = "check_output",
	.output_size = sizeof(struct check_output),
	.master_ops = &check_output_ops,
	.output_construct = &check_output_construct,
	.aspect_types = check_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_ALL,
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
