// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

//#define BRICK_DEBUGGING

#define _STRATEGY
#define BRICK_OBJ_NR /*empty => leads to an open array */
#define GFP_MARS GFP_ATOMIC

#include "brick.h"

//////////////////////////////////////////////////////////////

// object stuff

//////////////////////////////////////////////////////////////

// brick stuff

static int nr_brick_types = 0;
static const struct generic_brick_type *brick_types[MAX_BRICK_TYPES] = {};

int generic_register_brick_type(const struct generic_brick_type *new_type)
{
	int i;
	int found = -1;
	BRICK_DBG("generic_register_brick_type() name=%s\n", new_type->type_name);
	for (i = 0; i < nr_brick_types; i++) {
		if (!brick_types[i]) {
			found = i;
			continue;
		}
		if (!strcmp(brick_types[i]->type_name, new_type->type_name)) {
			BRICK_ERR("sorry, bricktype %s is already registered.\n", new_type->type_name);
			return -EEXIST;
		}
	}
	if (found < 0) {
		if (nr_brick_types >= MAX_BRICK_TYPES) {
			BRICK_ERR("sorry, cannot register bricktype %s.\n", new_type->type_name);
			return -ENOMEM;
		}
		found = nr_brick_types++;
	}
	brick_types[found] = new_type;
	BRICK_DBG("generic_register_brick_type() done.\n");
	return 0;
}
EXPORT_SYMBOL_GPL(generic_register_brick_type);

int generic_unregister_brick_type(const struct generic_brick_type *old_type)
{
	BRICK_DBG("generic_unregister_brick_type()\n");
	return -1; // NYI
}
EXPORT_SYMBOL_GPL(generic_unregister_brick_type);

int generic_brick_init_full(
	void *data, 
	int size, 
	const struct generic_brick_type *brick_type,
	const struct generic_input_type **input_types,
	const struct generic_output_type **output_types,
	char **names)
{
	struct generic_brick *brick = data;
	int status;
	int i;

	BRICK_DBG("generic_brick_init_full()\n");
	// first, call the generic constructors

	status = generic_brick_init(brick_type, brick, *names++);
	if (status)
		return status;
	data += brick_type->brick_size;
	size -= brick_type->brick_size;
	if (size < 0) {
		BRICK_ERR("Not enough MEMORY\n");
		return -ENOMEM;
	}
	if (!input_types) {
		BRICK_DBG("generic_brick_init_full: switch to default input_types\n");
		input_types = brick_type->default_input_types;
		names = brick_type->default_input_names;
	}
	if (input_types) {
		BRICK_DBG("generic_brick_init_full: input_types\n");
		brick->inputs = data;
		data += sizeof(void*) * brick_type->max_inputs;
		size -= sizeof(void*) * brick_type->max_inputs;
		if (size < 0) {
			return -ENOMEM;
		}
		for (i = 0; i < brick_type->max_inputs; i++) {
			struct generic_input *input = data;
			const struct generic_input_type *type = *input_types++;
			BRICK_DBG("generic_brick_init_full: calling generic_input_init()\n");
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
		BRICK_DBG("generic_brick_init_full: switch to default output_types\n");
		output_types = brick_type->default_output_types;
		names = brick_type->default_output_names;
	}
	if (output_types) {
		BRICK_DBG("generic_brick_init_full: output_types\n");
		brick->outputs = data;
		data += sizeof(void*) * brick_type->max_outputs;
		size -= sizeof(void*) * brick_type->max_outputs;
		if (size < 0)
			return -ENOMEM;
		for (i = 0; i < brick_type->max_outputs; i++) {
			struct generic_output *output = data;
			const struct generic_output_type *type = *output_types++;
			BRICK_DBG("generic_brick_init_full: calling generic_output_init()\n");
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
	BRICK_DBG("generic_brick_init_full: call specific contructors.\n");
	if (brick_type->brick_construct) {
		BRICK_DBG("generic_brick_init_full: calling brick_construct()\n");
		status = brick_type->brick_construct(brick);
		if (status)
			return status;
	}
	for (i = 0; i < brick_type->max_inputs; i++) {
		struct generic_input *input = brick->inputs[i];
		if (!input)
			continue;
		if (!input->type) {
			BRICK_ERR("input has no associated type!\n");
			continue;
		}
		if (input->type->input_construct) {
			BRICK_DBG("generic_brick_init_full: calling input_construct()\n");
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
			BRICK_ERR("output has no associated type!\n");
			continue;
		}
		if (output->type->output_construct) {
			BRICK_DBG("generic_brick_init_full: calling output_construct()\n");
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
			BRICK_ERR("output has no associated type!\n");
			continue;
		}
		if (output->nr_connected) {
			BRICK_DBG("output is connected!\n");
			return -EPERM;
		}
	}
        // ok, test succeeded. start destruction...
	for (i = 0; i < brick->type->max_outputs; i++) {
		struct generic_output *output = brick->outputs[i];
		if (!output)
			continue;
		if (!output->type) {
			BRICK_ERR("output has no associated type!\n");
			continue;
		}
		if (output->type->output_destruct) {
			BRICK_DBG("generic_brick_exit_full: calling output_destruct()\n");
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
			BRICK_ERR("input has no associated type!\n");
			continue;
		}
		if (input->type->input_destruct) {
			BRICK_DBG("generic_brick_exit_full: calling input_destruct()\n");
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
		BRICK_DBG("generic_brick_exit_full: calling brick_destruct()\n");
		status = brick->type->brick_destruct(brick);
		if (status)
			return status;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(generic_brick_exit_full);

int generic_brick_exit_recursively(struct generic_brick *brick, bool destroy_inputs)
{
	int final_status = 0;
	LIST_HEAD(tmp);

	list_add(&brick->tmp_head, &tmp);
	while (!list_empty(&tmp)) {
		int i;
		int status;
		int postpone = 0;
		brick = container_of(tmp.next, struct generic_brick, tmp_head);
		list_del_init(&brick->tmp_head);
		for (i = 0; i < brick->nr_outputs; i++) {
			struct generic_output *output = brick->outputs[i];
			if (output && output->nr_connected) {
				postpone += output->nr_connected;
			}
		}
		for (i = 0; i < brick->nr_inputs; i++) {
			struct generic_input *input = brick->inputs[i];
			if (input && input->connect) {
				struct generic_brick *other = input->connect->brick;
				if (destroy_inputs) {
					list_add(&other->tmp_head, &tmp);
					postpone++;
				} else {
				}
			}
		}
		if (postpone) {
			list_add_tail(&brick->tmp_head, &tmp);
			continue;
		}
		status = generic_brick_exit_full(brick);
		if (status)
			final_status = status;
	}
	return final_status;
}
EXPORT_SYMBOL_GPL(generic_brick_exit_recursively);

int generic_add_aspect(struct generic_output *output, struct generic_object_layout *object_layout, const struct generic_aspect_type *aspect_type)
{
	struct generic_aspect_layout *aspect_layout;
	int nr;

	if (unlikely(!object_layout->object_type)) {
		return -EINVAL;
	}
	nr = object_layout->object_type->brick_obj_nr;
	aspect_layout = (void*)&output->aspect_layouts[nr];
	if (aspect_layout->aspect_type) {
		/* aspect_layout is already initialized.
		 * this is a kind of "dynamic programming".
		 * ensure consistency to last call.
		 */
		int min_offset;
		BRICK_DBG("reusing aspect_type %s on object_layout %p\n", aspect_type->aspect_type_name, object_layout);
		if (unlikely(aspect_layout->aspect_type != aspect_type)) {
			BRICK_ERR("inconsistent use of aspect_type %s != %s\n", aspect_type->aspect_type_name, aspect_layout->aspect_type->aspect_type_name);
			return -EBADF;
		}
		if (unlikely(aspect_layout->init_data != output)) {
			BRICK_ERR("inconsistent output assigment (aspect_type=%s)\n", aspect_type->aspect_type_name);
			return -EBADF;
		}
		min_offset = aspect_layout->aspect_offset + aspect_type->aspect_size;
		   if (unlikely(object_layout->object_size > min_offset)) {
			BRICK_ERR("overlapping aspects %d > %d (aspect_type=%s)\n", object_layout->object_size, min_offset, aspect_type->aspect_type_name);
			return -ENOMEM;
		}
		BRICK_DBG("adjusting object_size %d to %d (aspect_type=%s)\n", object_layout->object_size, min_offset, aspect_type->aspect_type_name);
		object_layout->object_size = min_offset;
	} else {
		/* first call: initialize aspect_layout. */
		BRICK_DBG("initializing aspect_type %s on object_layout %p\n", aspect_type->aspect_type_name, object_layout);
		aspect_layout->aspect_type = aspect_type;
		aspect_layout->init_data = output;
		aspect_layout->aspect_offset = object_layout->object_size;
		object_layout->object_size += aspect_type->aspect_size;
	}
	nr = object_layout->aspect_count++;
	object_layout->aspect_layouts[nr] = aspect_layout;
	return 0;
}


EXPORT_SYMBOL_GPL(generic_add_aspect);

////////////////////////////////////////////////////////////////////////

// default implementations

int default_init_object_layout(struct generic_output *output, struct generic_object_layout *object_layout, int aspect_max, const struct generic_object_type *object_type)
{
	// TODO: make locking granularity finer (if it were worth).
	static DEFINE_SPINLOCK(global_lock);
	void *data;
	int status= -ENOMEM;
	unsigned long flags;

	data = kzalloc(aspect_max * sizeof(void*), GFP_MARS);
	if (unlikely(!data))
		goto done;

	traced_lock(&global_lock, flags);

	if (unlikely(object_layout->object_type)) {
		traced_unlock(&global_lock, flags);
		BRICK_INF("lost the race on object_layout %p (no harm)\n", object_layout);
		status = 0;
		goto done;
	}

	object_layout->aspect_layouts = data;
	object_layout->object_type = object_type;
	object_layout->aspect_count = 0;
	object_layout->aspect_max = aspect_max;
	object_layout->object_size = object_type->default_size;

	status = output->ops->make_object_layout(output, object_layout);

	traced_unlock(&global_lock, flags);
	
	if (unlikely(status < 0)) {
                object_layout->object_type = NULL;
		kfree(data);
		BRICK_ERR("emergency, cannot add aspects to object_layout %s!\n", object_type->object_type_name);
		goto done;
	}

	BRICK_INF("OK, object_layout %s init succeeded.\n", object_type->object_type_name);
done:
	return status;
}
EXPORT_SYMBOL_GPL(default_init_object_layout);

int default_make_object_layout(struct generic_output *output, struct generic_object_layout *object_layout)
{
	struct generic_brick *brick = output->brick;
	const struct generic_output_type *output_type = output->type;
	const struct generic_object_type *object_type = object_layout->object_type;
	const int nr = object_type->brick_obj_nr;
	const struct generic_aspect_type *aspect_type = output_type->aspect_types[nr];
	int layout_code = output_type->layout_code[nr];

	int status;
	int aspect_size;

	if (!aspect_type) {
		BRICK_ERR("aspect type on %s does not exist\n", output_type->type_name);
		return -ENOENT;
	}

	aspect_size = aspect_type->aspect_size;

	if (layout_code == LAYOUT_ALL) {
		int i;
		for (i = 0; i < brick->type->max_inputs; i++) {
			struct generic_input *input = brick->inputs[i];
			if (input && input->connect) {
				int substatus = input->connect->ops->make_object_layout(input->connect, object_layout);
				if (substatus < 0)
					return substatus;
				aspect_size += substatus;
			}
		}
	} else {
		for (; layout_code != 0; layout_code >>= 8) {
			unsigned int my_code = layout_code & 255;
			struct generic_input *input;
			int substatus;
			if (my_code == 255)
				break;
			if (my_code >= brick->type->max_inputs)
				continue;
			input = brick->inputs[my_code];
			if (!input || !input->connect)
				continue;
			substatus = input->connect->ops->make_object_layout(input->connect, object_layout);
			if (substatus < 0)
				return substatus;
			aspect_size += substatus;
		}
	}


	status = generic_add_aspect(output, object_layout, aspect_type);

	if (status < 0)
		return status;

	return aspect_size;
}
EXPORT_SYMBOL_GPL(default_make_object_layout);


struct generic_object *alloc_generic(struct generic_object_layout *object_layout)
{
	void *data;
	struct generic_object *object;

	data = kzalloc(object_layout->object_size, GFP_MARS);
	if (unlikely(!data))
		goto err;

	object = generic_construct(data, object_layout);
	if (unlikely(!object))
		goto err_free;

	return object;

err_free:
	kfree(data);
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(alloc_generic);

void free_generic(struct generic_object *object)
{
	kfree(object);
}
EXPORT_SYMBOL_GPL(free_generic);
