// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Dummy brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_dummy.h"

///////////////////////// own helper functions ////////////////////////

////////////////// own brick / input / output operations //////////////////

static int dummy_io(struct dummy_output *output, struct mars_io_object *mio)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_io, mio);
}

static int dummy_get_info(struct dummy_output *output, struct mars_info *info)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int dummy_buf_get(struct dummy_output *output, struct mars_buf_object **mbuf, struct mars_alloc_helper *h, loff_t pos, int len)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_get, mbuf, h, pos, len);
}

static int dummy_buf_put(struct dummy_output *output, struct mars_buf_object *mbuf)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_put, mbuf);
}

static int dummy_buf_io(struct dummy_output *output, struct mars_buf_object *mbuf)
{
	struct dummy_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_io, mbuf);
}

//////////////// object / aspect constructors / destructors ///////////////

static int dummy_mars_io_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct dummy_mars_io_aspect *ini = (void*)_ini;
	ini->my_own = 0;
	return 0;
}

static int dummy_mars_buf_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct dummy_mars_buf_aspect *ini = (void*)_ini;
	ini->my_own = 0;
	return 0;
}

MARS_MAKE_STATICS(dummy);

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
	.mars_get_info = dummy_get_info,
	.mars_buf_get = dummy_buf_get,
	.mars_buf_put = dummy_buf_put,
	.mars_buf_io = dummy_buf_io,
};

static const struct dummy_input_type dummy_input_type = {
	.type_name = "dummy_input",
	.input_size = sizeof(struct dummy_input),
};

static const struct dummy_input_type *dummy_input_types[] = {
	&dummy_input_type,
};

static const struct dummy_output_type dummy_output_type = {
	.type_name = "dummy_output",
	.output_size = sizeof(struct dummy_output),
	.master_ops = &dummy_output_ops,
	.output_construct = &dummy_output_construct,
	.aspect_types = dummy_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_IO] = LAYOUT_ALL,
		[BRICK_OBJ_MARS_BUF] = LAYOUT_ALL,
	}
};

static const struct dummy_output_type *dummy_output_types[] = {
	&dummy_output_type,
};

const struct dummy_brick_type dummy_brick_type = {
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
