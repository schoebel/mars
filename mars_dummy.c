// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Dummy brick (just for demonstration)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_dummy.h"

////////////////// own brick / input / output operations //////////////////

static int dummy_io(struct dummy_output *output, struct mars_io_object *mio)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_io, mio);
}

static loff_t dummy_get_size(struct dummy_output *output)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_size);
}

static int dummy_buf_get(struct dummy_output *output, struct mars_buf_object **mbuf, struct mars_buf_object_layout *buf_layout, loff_t pos, int len)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_get, mbuf, buf_layout, pos, len);
}

static int dummy_buf_put(struct dummy_output *output, struct mars_buf_object *mbuf)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_put, mbuf);
}

static int dummy_buf_io(struct dummy_output *output, struct mars_buf_object *mbuf, int rw, int(*buf_endio)(struct mars_buf_object *mbuf))
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_io, mbuf, rw, buf_endio);
}

//////////////// object / aspect constructors / destructors ///////////////

static int dummy_mars_io_aspect_init_fn(struct mars_io_aspect *_ini, void *_init_data)
{
	struct dummy_mars_io_aspect *ini = (void*)_ini;
	ini->my_own = 0;
	return 0;
}

static int dummy_mars_buf_aspect_init_fn(struct mars_buf_aspect *_ini, void *_init_data)
{
	struct dummy_mars_buf_aspect *ini = (void*)_ini;
	ini->my_own = 0;
	return 0;
}

static int dummy_make_object_layout(struct dummy_output *output, struct generic_object_layout *object_layout)
{
	const struct generic_object_type *object_type = object_layout->type;
	int res;
	int aspect_size = 0;
	struct dummy_brick *brick = output->brick;
	int i;

	if (object_type == &mars_io_type) {
		aspect_size = sizeof(struct dummy_mars_io_aspect);
		res = mars_io_add_aspect(object_layout, aspect_size, dummy_mars_io_aspect_init_fn, output);
	} else if (object_type == &mars_buf_type) {
		aspect_size = sizeof(struct dummy_mars_buf_aspect);
		res = mars_buf_add_aspect(object_layout, aspect_size, dummy_mars_buf_aspect_init_fn, output);
	} else {
		return 0;
	}

	if (res < 0)
		return res;

	output->aspect_slot = res;

	for (i = 0; i < brick->type->max_inputs; i++) {
		struct dummy_input *input = brick->inputs[i];
		if (input && input->connect) {
			int subres = input->connect->ops->make_object_layout(input->connect, object_layout);
			if (subres < 0)
				return subres;
			res += subres;
		}
	}

	return res + aspect_size;
}

////////////////////// brick constructors / destructors ////////////////////

static int dummy_brick_construct(struct dummy_brick *brick)
{
	brick->my_own = 0;
	return 0;
}

static int dummy_output_construct(struct dummy_output *output)
{
	output->my_own = 0;
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct dummy_brick_ops dummy_brick_ops = {
};

static struct dummy_output_ops dummy_output_ops = {
	.make_object_layout = dummy_make_object_layout,
	.mars_io = dummy_io,
	.mars_get_size = dummy_get_size,
	.mars_buf_get = dummy_buf_get,
	.mars_buf_put = dummy_buf_put,
	.mars_buf_io = dummy_buf_io,
};

static struct dummy_input_type dummy_input_type = {
	.type_name = "dummy_input",
	.input_size = sizeof(struct dummy_input),
};

static struct dummy_input_type *dummy_input_types[] = {
	&dummy_input_type,
};

static struct dummy_output_type dummy_output_type = {
	.type_name = "dummy_output",
	.output_size = sizeof(struct dummy_output),
	.master_ops = &dummy_output_ops,
	.output_construct = &dummy_output_construct,
};

static struct dummy_output_type *dummy_output_types[] = {
	&dummy_output_type,
};

struct dummy_brick_type dummy_brick_type = {
	.type_name = "dummy_brick",
	.brick_size = sizeof(struct dummy_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &dummy_brick_ops,
	.default_input_types = dummy_input_types,
	.default_output_types = dummy_output_types,
	.brick_construct = &dummy_brick_construct,
};
EXPORT_SYMBOL_GPL(dummy_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_dummy(void)
{
	printk(MARS_INFO "init_dummy()\n");
	return dummy_register_brick_type();
}

static void __exit exit_dummy(void)
{
	printk(MARS_INFO "exit_dummy()\n");
	dummy_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS dummy brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_dummy);
module_exit(exit_dummy);
