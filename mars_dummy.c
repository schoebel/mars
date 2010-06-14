// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Dummy brick (just for demonstration)

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

struct dummy_brick {
	MARS_BRICK(dummy);
	int my_own;
};

struct dummy_input {
	MARS_INPUT(dummy);
};

struct dummy_output {
	MARS_OUTPUT(dummy);
	int my_own;
};

MARS_TYPES(dummy);

////////////////// own brick / input / output operations //////////////////

///////////////////////// contructors / destructors ////////////////////////

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
