// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick (just for demonstration)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bio.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_trans_logger.h"

////////////////// own brick / input / output helpers //////////////////

static int trans_logger_mars_io(struct trans_logger_output *output, struct mars_io_object *mio)
{
	return -EINVAL;
}

static int trans_logger_thread(void *data)
{
	struct trans_logger_output *output = data;
	MARS_INF("kthread has started.\n");
	//set_user_nice(current, -20);

	while (!kthread_should_stop()) {
		struct list_head *tmp;
		struct trans_logger_mars_io_aspect *aspect;
		struct mars_io_object *mio;

		wait_event_interruptible(output->event,
					 !list_empty(&output->mio_list) ||
					 kthread_should_stop());

		if (list_empty(&output->mio_list))
			continue;

		spin_lock_irq(&output->lock);
		tmp = output->mio_list.next;
		list_del_init(tmp);
		spin_unlock_irq(&output->lock);

		aspect = container_of(tmp, struct trans_logger_mars_io_aspect, io_head);
		mio = aspect->object;
		MARS_DBG("got %p %p\n", aspect, mio);
		trans_logger_mars_io(output, mio);
	}
	MARS_INF("kthread has stopped.\n");
	return 0;
}

static int trans_logger_io_write(struct trans_logger_output *output, struct trans_logger_output *other, struct mars_io_object *mio)
{
	struct trans_logger_mars_io_aspect *aspect;
	aspect = mars_io_get_aspect(mio, output->aspect_slot);
	MARS_DBG("queueing %p\n", mio);
	spin_lock_irq(&output->lock);
	list_add_tail(&aspect->io_head, &output->mio_list);
	spin_unlock_irq(&output->lock);

	wake_up(&output->event);

	return 0;
}

static int trans_logger_io_read(struct trans_logger_output *output, struct trans_logger_output *other, struct mars_io_object *mio)
{
	//TODO: ask writeback cache first
	return other->ops->mars_io(other, mio);
}

////////////////// own brick / input / output operations //////////////////

static int trans_logger_io(struct trans_logger_output *output, struct mars_io_object *mio)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	struct trans_logger_output *other;
	int direction;
	if (unlikely(!input))
		return -ENOSYS;
	other = input->connect;
	if (unlikely(!other || !other->ops || !other->ops->mars_io))
		return -ENOSYS;
	if (unlikely(!mio->orig_bio))
		return -EINVAL;
	direction = mio->orig_bio->bi_rw & 1;
	if (direction == READ) {
		return trans_logger_io_read(output, other, mio);
	}
	return trans_logger_io_write(output, other, mio);
}

static int trans_logger_get_info(struct trans_logger_output *output, struct mars_info *info)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

//////////////// object / aspect constructors / destructors ///////////////

static int trans_logger_aspect_init_fn(struct mars_io_aspect *_ini, void *_init_data)
{
	struct trans_logger_mars_io_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static int trans_logger_make_object_layout(struct trans_logger_output *output, struct generic_object_layout *object_layout)
{
	const struct generic_object_type *object_type = object_layout->type;
	int res;
	struct trans_logger_brick *brick = output->brick;
	int i;

	if (object_type != &mars_io_type)
		return 0;

	res = mars_io_add_aspect(object_layout, sizeof(struct trans_logger_mars_io_aspect), trans_logger_aspect_init_fn, output);
	if (res < 0)
		return res;

	output->aspect_slot = res;

	for (i = 0; i < brick->type->max_inputs; i++) {
		struct trans_logger_input *input = brick->inputs[i];
		if (input && input->connect) {
			int subres = input->connect->ops->make_object_layout(input->connect, object_layout);
			if (subres < 0)
				return subres;
			res += subres;
		}
	}

	return res + sizeof(struct trans_logger_mars_io_aspect);
}

////////////////////// brick constructors / destructors ////////////////////

static int trans_logger_brick_construct(struct trans_logger_brick *brick)
{
	return 0;
}

static int trans_logger_output_construct(struct trans_logger_output *output)
{
	spin_lock_init(&output->lock);
	INIT_LIST_HEAD(&output->mio_list);
	init_waitqueue_head(&output->event);
	output->thread = kthread_create(trans_logger_thread, output, "mars_logger%d", 0);
	if (IS_ERR(output->thread)) {
		int error = PTR_ERR(output->thread);
		MARS_ERR("cannot create thread, status=%d\n", error);
		return error;
	}
	wake_up_process(output->thread);
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct trans_logger_brick_ops trans_logger_brick_ops = {
};

static struct trans_logger_output_ops trans_logger_output_ops = {
	.make_object_layout = trans_logger_make_object_layout,
	.mars_io = trans_logger_io,
	.mars_get_info = trans_logger_get_info,
};

static struct trans_logger_input_type trans_logger_input_type = {
	.type_name = "data",
	.input_size = sizeof(struct trans_logger_input),
};

static struct trans_logger_input_type trans_logger_input_log_type = {
	.type_name = "log",
	.input_size = sizeof(struct trans_logger_input),
};

static struct trans_logger_input_type *trans_logger_input_types[] = {
	&trans_logger_input_type,
	&trans_logger_input_log_type,
};

static struct trans_logger_output_type trans_logger_output_type = {
	.type_name = "trans_logger_output",
	.output_size = sizeof(struct trans_logger_output),
	.master_ops = &trans_logger_output_ops,
	.output_construct = &trans_logger_output_construct,
};

static struct trans_logger_output_type *trans_logger_output_types[] = {
	&trans_logger_output_type,
};

struct trans_logger_brick_type trans_logger_brick_type = {
	.type_name = "trans_logger_brick",
	.brick_size = sizeof(struct trans_logger_brick),
	.max_inputs = 2,
	.max_outputs = 1,
	.master_ops = &trans_logger_brick_ops,
	.default_input_types = trans_logger_input_types,
	.default_output_types = trans_logger_output_types,
	.brick_construct = &trans_logger_brick_construct,
};
EXPORT_SYMBOL_GPL(trans_logger_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_trans_logger(void)
{
	printk(MARS_INFO "init_trans_logger()\n");
	return trans_logger_register_brick_type();
}

static void __exit exit_trans_logger(void)
{
	printk(MARS_INFO "exit_trans_logger()\n");
	trans_logger_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS trans_logger brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_trans_logger);
module_exit(exit_trans_logger);
