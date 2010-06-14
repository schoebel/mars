// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define _STRATEGY
#include "mars.h"

//////////////////////////////////////////////////////////////

// testing.....

#if 1
#include <linux/slab.h>

GENERIC_OBJECT_LAYOUT_FUNCTIONS(generic);
GENERIC_OBJECT_FUNCTIONS(generic);

void test(void)
{
	char data[1024];
	struct generic_object *obj;
	struct generic_object_layout *t = generic_init_object_layout(data, sizeof(data), 4);
	int slot = generic_add_aspect(t, 17);
	char *my_aspect;
	obj = kmalloc(t->max_size, GFP_KERNEL);
	obj = generic_construct(obj, t);
	my_aspect = (void*)obj + obj->object_layout->aspect_offsets[slot];
	my_aspect = generic_get_aspect(obj, slot);
}
#endif

//////////////////////////////////////////////////////////////

#define MAX_BRICK_TYPES 64

static int nr_brick_types = 0;
static struct generic_brick_type *brick_types[MAX_BRICK_TYPES] = {};

int generic_register_brick_type(struct generic_brick_type *new_type)
{
	int i;
	int found = -1;
	MARS_DBG("generic_register_brick_type()\n");
	for (i = 0; i < nr_brick_types; i++) {
		if (!brick_types[i]) {
			found = i;
			continue;
		}
		if (!strcmp(brick_types[i]->type_name, new_type->type_name)) {
			printk("sorry, bricktype %s is already registered.\n", new_type->type_name);
			return -EEXIST;
		}
	}
	if (found < 0) {
		if (nr_brick_types >= MAX_BRICK_TYPES) {
			printk("sorry, cannot register bricktype %s.\n", new_type->type_name);
			return -EEXIST;
		}
		found = nr_brick_types++;
	}
	brick_types[found] = new_type;
	MARS_DBG("generic_register_brick_type() done.\n");
	return 0;
}
EXPORT_SYMBOL_GPL(generic_register_brick_type);

int generic_unregister_brick_type(struct generic_brick_type *old_type)
{
	MARS_DBG("generic_unregister_brick_type()\n");
	return -1; // NYI
}
EXPORT_SYMBOL_GPL(generic_unregister_brick_type);

int generic_brick_init_full(
	void *data, 
	int size, 
	struct generic_brick_type *brick_type,
	struct generic_input_type **input_types,
	struct generic_output_type **output_types,
	char **names)
{
	struct generic_brick *brick = data;
	int status;
	int i;

	MARS_DBG("generic_brick_init_full()\n");
	// first, call the generic constructors

	status = generic_brick_init(brick_type, brick, *names++);
	if (status)
		return status;
	data += brick_type->brick_size;
	size -= brick_type->brick_size;
	if (size < 0)
		return -ENOMEM;
	if (!input_types) {
		MARS_DBG("generic_brick_init_full: switch to default input_types\n");
		input_types = brick_type->default_input_types;
		names = brick_type->default_input_names;
	}
	if (input_types) {
		MARS_DBG("generic_brick_init_full: input_types\n");
		brick->inputs = data;
		data += sizeof(void*) * brick_type->max_inputs;
		size -= sizeof(void*) * brick_type->max_inputs;
		if (size < 0)
			return -1;
		for (i = 0; i < brick_type->max_inputs; i++) {
			struct generic_input *input = data;
			struct generic_input_type *type = *input_types++;
			MARS_DBG("generic_brick_init_full: calling generic_input_init()\n");
			status = generic_input_init(brick, i, type, input, names ? *names++ : type->type_name);
			if (status)
				return status;
			data += type->input_size;
			size -= type->input_size;
			if (size < 0)
				return -ENOMEM;
		}
	}
	if (!output_types) {
		MARS_DBG("generic_brick_init_full: switch to default output_types\n");
		output_types = brick_type->default_output_types;
		names = brick_type->default_output_names;
	}
	if (output_types) {
		MARS_DBG("generic_brick_init_full: output_types\n");
		brick->outputs = data;
		data += sizeof(void*) * brick_type->max_outputs;
		size -= sizeof(void*) * brick_type->max_outputs;
		if (size < 0)
			return -1;
		for (i = 0; i < brick_type->max_outputs; i++) {
			struct generic_output *output = data;
			struct generic_output_type *type = *output_types++;
			MARS_DBG("generic_brick_init_full: calling generic_output_init()\n");
			generic_output_init(brick, i, type, output, names ? *names++ : type->type_name);
			if (status)
				return status;
			data += type->output_size;
			size -= type->output_size;
			if (size < 0)
				return -ENOMEM;
		}
	}

	// call the specific constructors
	MARS_DBG("generic_brick_init_full: call specific contructors.\n");
	if (brick_type->brick_construct) {
		MARS_DBG("generic_brick_init_full: calling brick_construct()\n");
		status = brick_type->brick_construct(brick);
		if (status)
			return status;
	}
	for (i = 0; i < brick_type->max_inputs; i++) {
		struct generic_input *input = brick->inputs[i];
		if (!input)
			continue;
		if (!input->type) {
			MARS_ERR("input has no associated type!\n");
			continue;
		}
		if (input->type->input_construct) {
			MARS_DBG("generic_brick_init_full: calling input_construct()\n");
			status = input->type->input_construct(input);
			if (status)
				return status;
		}
	}
	for (i = 0; i < brick_type->max_outputs; i++) {
		struct generic_output *output = brick->outputs[i];
		if (!output)
			continue;
		if (!output->type) {
			MARS_ERR("output has no associated type!\n");
			continue;
		}
		if (output->type->output_construct) {
			MARS_DBG("generic_brick_init_full: calling output_construct()\n");
			status = output->type->output_construct(output);
			if (status)
				return status;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(generic_brick_init_full);

int generic_brick_exit_full(struct generic_brick *brick)
{
	int i;
	int status;
	// first, check all outputs
	for (i = 0; i < brick->nr_outputs; i++) {
		struct generic_output *output = brick->outputs[i];
		if (!output)
			continue;
		if (!output->type) {
			MARS_ERR("output has no associated type!\n");
			continue;
		}
		if (output->nr_connected) {
			MARS_DBG("output is connected!\n");
			return -EPERM;
		}
	}
        // ok, test succeeded. start desctruction...
	for (i = 0; i < brick->type->max_outputs; i++) {
		struct generic_output *output = brick->outputs[i];
		if (!output)
			continue;
		if (!output->type) {
			MARS_ERR("output has no associated type!\n");
			continue;
		}
		if (output->type->output_destruct) {
			MARS_DBG("generic_brick_exit_full: calling output_destruct()\n");
			status = output->type->output_destruct(output);
			if (status)
				return status;
			brick->outputs[i] = NULL; // others may remain leftover
		}
	}
	for (i = 0; i < brick->type->max_inputs; i++) {
		struct generic_input *input = brick->inputs[i];
		if (!input)
			continue;
		if (!input->type) {
			MARS_ERR("input has no associated type!\n");
			continue;
		}
		if (input->type->input_destruct) {
			MARS_DBG("generic_brick_exit_full: calling input_destruct()\n");
			status = input->type->input_destruct(input);
			if (status)
				return status;
			brick->inputs[i] = NULL; // others may remain leftover
			status = generic_disconnect(input);
			if (status)
				return status;
		}
	}
	if (brick->type->brick_destruct) {
		MARS_DBG("generic_brick_exit_full: calling brick_destruct()\n");
		status = brick->type->brick_destruct(brick);
		if (status)
			return status;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(generic_brick_exit_full);

int generic_brick_exit_recursively(struct generic_brick *brick)
{
	int final_status = 0;
	LIST_HEAD(head);
	list_add(&brick->tmp_head, &head);
	while (!list_empty(&head)) {
		int i;
		int status;
		brick = container_of(head.next, struct generic_brick, tmp_head);
		for (i = 0; i < brick->nr_outputs; i++) {
			struct generic_output *output = brick->outputs[i];
			if (output->nr_connected) {
				list_del(&brick->tmp_head);
				continue;
			}
		}
		list_del(&brick->tmp_head);
		for (i = 0; i < brick->nr_inputs; i++) {
			struct generic_input *input = brick->inputs[i];
			if (input->connect) {
				struct generic_brick *other = input->connect->brick;
				list_add(&other->tmp_head, &head);
			}
		}
		status = generic_brick_exit_full(brick);
		if (status)
			final_status = status;
	}
	return final_status;
}
EXPORT_SYMBOL_GPL(generic_brick_exit_recursively);

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
