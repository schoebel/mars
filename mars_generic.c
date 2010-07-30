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

//////////////////////////////////////////////////////////////

// brick stuff

struct generic_object_layout *default_init_object_layout(struct generic_output *output, const struct generic_object_type *object_type)
{
	const int layout_size = 1024;
	const int max_aspects = 16;
	struct generic_object_layout *res;
	int status;
	void *data = kzalloc(layout_size, GFP_KERNEL);
	if (!data) {
		MARS_ERR("emergency, cannot allocate object_layout %s!\n", object_type->object_type_name);
		return NULL;
	}
	res = generic_init_object_layout(data, layout_size, max_aspects, object_type);
	if (unlikely(!res)) {
		MARS_ERR("emergency, cannot init object_layout %s!\n", object_type->object_type_name);
		goto err_free;
	}
	
	status = output->ops->make_object_layout(output, res);
	if (unlikely(status < 0)) {
		MARS_ERR("emergency, cannot add aspects to object_layout %s!\n", object_type->object_type_name);
		goto err_free;
	}
	MARS_INF("OK, object_layout %s init succeeded.\n", object_type->object_type_name);
	return res;

err_free:
	kfree(res);
	return NULL;
}
EXPORT_SYMBOL_GPL(default_init_object_layout);

struct generic_object *alloc_generic(struct generic_output *output, struct mars_alloc_helper *h, const struct generic_object_type *object_type)
{
	void *data;
	struct generic_object *object;

	// TODO: eliminate race
	if (unlikely(!h->object_layout)) {
		h->object_layout = default_init_object_layout(output, object_type);
		if (!h->object_layout)
			goto err;
	}
	if (unlikely(h->object_layout->object_type != object_type)) {
		MARS_ERR("inconsistent object_types: %s != %s\n", h->object_layout->object_type->object_type_name, object_type->object_type_name);
		goto err;
	}

	data = kzalloc(h->object_layout->object_size, GFP_KERNEL);
	if (unlikely(!data))
		goto err;

	object = generic_construct(data, h->object_layout);
	if (unlikely(!object))
		goto err_free;

	return object;

err_free:
	kfree(data);
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(alloc_generic);


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
