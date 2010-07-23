// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define _STRATEGY
#include "mars.h"

//////////////////////////////////////////////////////////////

// object stuff

const struct generic_object_type mars_io_type = {
	.object_type_name = "mars_io",
	.default_size = sizeof(struct mars_io_object),
	.brick_obj_nr = BRICK_OBJ_MARS_IO,
};
EXPORT_SYMBOL_GPL(mars_io_type);

const struct generic_object_type mars_buf_type = {
	.object_type_name = "mars_buf",
	.default_size = sizeof(struct mars_buf_object),
	.brick_obj_nr = BRICK_OBJ_MARS_BUF,
};
EXPORT_SYMBOL_GPL(mars_buf_type);

const struct generic_object_type mars_buf_callback_type = {
	.object_type_name = "mars_buf_callback",
	.default_size = sizeof(struct mars_buf_callback_object),
	.brick_obj_nr = BRICK_OBJ_MARS_BUF_CALLBACK,
};
EXPORT_SYMBOL_GPL(mars_buf_callback_type);

//////////////////////////////////////////////////////////////

// brick stuff

/////////////////////////////////////////////////////////////////////

static int __init init_mars(void)
{
	printk(MARS_INFO "init_mars()\n");
	return 0;
}

static void __exit exit_mars(void)
{
	printk(MARS_INFO "exit_mars()\n");
}

MODULE_DESCRIPTION("MARS block storage");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars);
module_exit(exit_mars);
