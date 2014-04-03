/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

//#define BRICK_DEBUGGING

#define _STRATEGY

#include "brick.h"
#include "brick_mem.h"

//////////////////////////////////////////////////////////////

// init / exit functions

void _generic_output_init(struct generic_brick *brick, const struct generic_output_type *type, struct generic_output *output)
{
	output->brick = brick;
	output->type = type;
	output->ops = type->master_ops;
	output->nr_connected = 0;
	INIT_LIST_HEAD(&output->output_head);
}
EXPORT_SYMBOL_GPL(_generic_output_init);

void _generic_output_exit(struct generic_output *output)
{
	list_del_init(&output->output_head);
	output->brick = NULL;
	output->type = NULL;
	output->ops = NULL;
	output->nr_connected = 0;
}
EXPORT_SYMBOL_GPL(_generic_output_exit);

int generic_brick_init(const struct generic_brick_type *type, struct generic_brick *brick)
{
	brick->aspect_context.brick_index = get_nr();
	brick->type = type;
	brick->ops = type->master_ops;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	brick->power.led_off = true;
	init_waitqueue_head(&brick->power.event);
	INIT_LIST_HEAD(&brick->tmp_head);
	return 0;
}
EXPORT_SYMBOL_GPL(generic_brick_init);

void generic_brick_exit(struct generic_brick *brick)
{
	list_del_init(&brick->tmp_head);
	brick->type = NULL;
	brick->ops = NULL;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	put_nr(brick->aspect_context.brick_index);
}
EXPORT_SYMBOL_GPL(generic_brick_exit);

int generic_input_init(struct generic_brick *brick, int index, const struct generic_input_type *type, struct generic_input *input)
{
	if (index < 0 || index >= brick->type->max_inputs)
		return -EINVAL;
	if (brick->inputs[index])
		return -EEXIST;
	input->brick = brick;
	input->type = type;
	input->connect = NULL;
	INIT_LIST_HEAD(&input->input_head);
	brick->inputs[index] = input;
	brick->nr_inputs++;
	return 0;
}
EXPORT_SYMBOL_GPL(generic_input_init);

void generic_input_exit(struct generic_input *input)
{
	list_del_init(&input->input_head);
	input->brick = NULL;
	input->type = NULL;
	input->connect = NULL;
}
EXPORT_SYMBOL_GPL(generic_input_exit);

int generic_output_init(struct generic_brick *brick, int index, const struct generic_output_type *type, struct generic_output *output)
{
	if (index < 0 || index >= brick->type->max_outputs)
		return -ENOMEM;
	if (brick->outputs[index])
		return -EEXIST;
	_generic_output_init(brick, type, output);
	brick->outputs[index] = output;
	brick->nr_outputs++;
	return 0;
}
EXPORT_SYMBOL_GPL(generic_output_init);

int generic_size(const struct generic_brick_type *brick_type)
{
	int size = brick_type->brick_size;
	int i;
	size += brick_type->max_inputs * sizeof(void*);
	for (i = 0; i < brick_type->max_inputs; i++) {
		size += brick_type->default_input_types[i]->input_size;
	}
	size += brick_type->max_outputs * sizeof(void*);
	for (i = 0; i < brick_type->max_outputs; i++) {
		size += brick_type->default_output_types[i]->output_size;
	}
	return size;
}
EXPORT_SYMBOL_GPL(generic_size);

int generic_connect(struct generic_input *input, struct generic_output *output)
{
	BRICK_DBG("generic_connect(input=%p, output=%p)\n", input, output);
	if (unlikely(!input || !output))
		return -EINVAL;
	if (unlikely(input->connect))
		return -EEXIST;
	if (unlikely(!list_empty(&input->input_head)))
		return -EINVAL;
	// helps only against the most common errors
	if (unlikely(input->brick == output->brick))
		return -EDEADLK;

	input->connect = output;
	output->nr_connected++;
	list_add(&input->input_head, &output->output_head);
	BRICK_DBG("now nr_connected=%d\n", output->nr_connected);
	return 0;
}
EXPORT_SYMBOL_GPL(generic_connect);

int generic_disconnect(struct generic_input *input)
{
	struct generic_output *connect;
	BRICK_DBG("generic_disconnect(input=%p)\n", input);
	if (!input)
		return -EINVAL;
	connect = input->connect;
	if (connect) {
		connect->nr_connected--;
		BRICK_DBG("now nr_connected=%d\n", connect->nr_connected);
		input->connect = NULL;
		list_del_init(&input->input_head);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(generic_disconnect);


//////////////////////////////////////////////////////////////

// general

int _brick_msleep(int msecs, bool shorten)
{
	unsigned long timeout;
	flush_signals(current);			\
	if (msecs <= 0) {
		schedule();
		return 0;
	}
	timeout = msecs_to_jiffies(msecs) + 1;

	timeout = schedule_timeout_interruptible(timeout);

	if (!shorten) {
		while ((long)timeout > 0) {
			timeout = schedule_timeout_uninterruptible(timeout);
		}
	}

	return jiffies_to_msecs(timeout);
}
EXPORT_SYMBOL_GPL(_brick_msleep);

//////////////////////////////////////////////////////////////

// number management

static char *nr_table = NULL;
int nr_max = 256;
EXPORT_SYMBOL_GPL(nr_max);

int get_nr(void)
{
	char *new;
	int nr;

	if (unlikely(!nr_table)) {
		nr_table = brick_zmem_alloc(nr_max);
	}

	for (;;) {
		for (nr = 1; nr < nr_max; nr++) {
			if (!nr_table[nr]) {
				nr_table[nr] = 1;
				return nr;
			}
		}
		new = brick_zmem_alloc(nr_max << 1);
		memcpy(new, nr_table, nr_max);
		brick_mem_free(nr_table);
		nr_table = new;
		nr_max <<= 1;
	}
}
EXPORT_SYMBOL_GPL(get_nr);

void put_nr(int nr)
{
	if (likely(nr_table && nr > 0 && nr < nr_max)) {
		nr_table[nr] = 0;
	}
}
EXPORT_SYMBOL_GPL(put_nr);

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
			BRICK_DBG("bricktype %s is already registered.\n", new_type->type_name);
			return 0;
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
	const struct generic_output_type **output_types)
{
	struct generic_brick *brick = data;
	int status;
	int i;

	BRICK_DBG("brick_type = %s\n", brick_type->type_name);
	if (unlikely(!data)) {
		BRICK_ERR("invalid memory\n");
		return -EINVAL;
	}

	// call the generic constructors

	status = generic_brick_init(brick_type, brick);
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
		if (unlikely(!input_types)) {
			BRICK_ERR("no input types specified\n");
			return -EINVAL;
		}
	}
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
		if (!type || type->input_size <= 0) {
			return -EINVAL;
		}
		BRICK_DBG("generic_brick_init_full: calling generic_input_init()\n");
		status = generic_input_init(brick, i, type, input);
		if (status < 0)
			return status;
		data += type->input_size;
		size -= type->input_size;
		if (size < 0)
			return -ENOMEM;
	}
	if (!output_types) {
		BRICK_DBG("generic_brick_init_full: switch to default output_types\n");
		output_types = brick_type->default_output_types;
		if (unlikely(!output_types)) {
			BRICK_ERR("no output types specified\n");
			return -EINVAL;
		}
	}
	BRICK_DBG("generic_brick_init_full: output_types\n");
	brick->outputs = data;
	data += sizeof(void*) * brick_type->max_outputs;
	size -= sizeof(void*) * brick_type->max_outputs;
	if (size < 0)
		return -ENOMEM;
	for (i = 0; i < brick_type->max_outputs; i++) {
		struct generic_output *output = data;
		const struct generic_output_type *type = *output_types++;
		if (!type || type->output_size <= 0) {
			return -EINVAL;
		}
		BRICK_DBG("generic_brick_init_full: calling generic_output_init()\n");
		generic_output_init(brick, i, type, output);
		if (status < 0)
			return status;
		data += type->output_size;
		size -= type->output_size;
		if (size < 0)
			return -ENOMEM;
	}

	// call the specific constructors
	BRICK_DBG("generic_brick_init_full: call specific contructors.\n");
	if (brick_type->brick_construct) {
		BRICK_DBG("generic_brick_init_full: calling brick_construct()\n");
		status = brick_type->brick_construct(brick);
		if (status < 0)
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
			if (status < 0)
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
			if (status < 0)
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
	for (i = 0; i < brick->type->max_outputs; i++) {
		struct generic_output *output = brick->outputs[i];
		if (!output)
			continue;
		if (!output->type) {
			BRICK_ERR("output has no associated type!\n");
			continue;
		}
		if (output->nr_connected) {
			BRICK_ERR("output is connected!\n");
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
			if (status < 0)
				return status;
			_generic_output_exit(output);
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
			status = generic_disconnect(input);
			if (status < 0)
				return status;
			BRICK_DBG("generic_brick_exit_full: calling input_destruct()\n");
			status = input->type->input_destruct(input);
			if (status < 0)
				return status;
			brick->inputs[i] = NULL; // others may remain leftover
			generic_input_exit(input);
		}
	}
	if (brick->type->brick_destruct) {
		BRICK_DBG("generic_brick_exit_full: calling brick_destruct()\n");
		status = brick->type->brick_destruct(brick);
		if (status < 0)
			return status;
	}
	generic_brick_exit(brick);
	return 0;
}
EXPORT_SYMBOL_GPL(generic_brick_exit_full);

////////////////////////////////////////////////////////////////////////

// default implementations

struct generic_object *generic_alloc(struct generic_object_layout *object_layout, const struct generic_object_type *object_type)
{
	struct generic_object *object;
	void *data;
	int object_size;
	int aspect_nr_max;
	int total_size;
	int hint_size;

	CHECK_PTR_NULL(object_type, err);
	CHECK_PTR(object_layout, err);

	object_size = object_type->default_size;
	aspect_nr_max = nr_max;
	total_size = object_size + aspect_nr_max * sizeof(void*);
	hint_size = object_layout->size_hint;
	if (likely(total_size <= hint_size)) {
		total_size = hint_size;
	} else { // usually happens only at the first time
		object_layout->size_hint = total_size;
	}

	data = brick_zmem_alloc(total_size);

	atomic_inc(&object_layout->alloc_count);
	atomic_inc(&object_layout->total_alloc_count);

	object = data;
	object->object_type = object_type;
	object->object_layout = object_layout;
	object->aspects = data + object_size;
	object->aspect_nr_max = aspect_nr_max;
	object->free_offset = object_size + aspect_nr_max * sizeof(void*);
	object->max_offset = total_size;

	if (object_type->init_fn) {
		int status = object_type->init_fn(object);
		if (status < 0) {
			goto err_free;
		}
	}

	return object;

err_free:
	brick_mem_free(data);
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(generic_alloc);

void generic_free(struct generic_object *object)
{
	const struct generic_object_type *object_type;
	struct generic_object_layout *object_layout;
	int i;

	CHECK_PTR(object, done);
	object_type = object->object_type;
	CHECK_PTR_NULL(object_type, done);
	object_layout = object->object_layout;
	CHECK_PTR(object_layout, done);
	_CHECK_ATOMIC(&object->ref_count, !=, 0);

	atomic_dec(&object_layout->alloc_count);
	for (i = 0; i < object->aspect_nr_max; i++) {
		const struct generic_aspect_type *aspect_type;
		struct generic_aspect *aspect = object->aspects[i];
		if (!aspect)
			continue;
		object->aspects[i] = NULL;
		aspect_type = aspect->aspect_type;
		CHECK_PTR_NULL(aspect_type, done);
		if (aspect_type->exit_fn) {
			aspect_type->exit_fn(aspect);
		}
		if (aspect->shortcut)
			continue;
		brick_mem_free(aspect);
		atomic_dec(&object_layout->aspect_count);
	}
	if (object_type->exit_fn) {
		object_type->exit_fn(object);
	}
	brick_mem_free(object);
done: ;
}
EXPORT_SYMBOL_GPL(generic_free);

static inline
struct generic_aspect *_new_aspect(const struct generic_aspect_type *aspect_type, struct generic_object *obj)
{
	struct generic_aspect *res = NULL;
	int size;
	int rest;
	
	size = aspect_type->aspect_size;
	rest = obj->max_offset - obj->free_offset;
	if (likely(size <= rest)) {
		/* Optimisation: re-use single memory allocation for both
		 * the object and the new aspect.
		 */
		res = ((void*)obj) + obj->free_offset;
		obj->free_offset += size;
		res->shortcut = true;
	} else {
		struct generic_object_layout *object_layout = obj->object_layout;
		CHECK_PTR(object_layout, done);
		/* Maintain the size hint.
		 * In future, only small aspects should be integrated into
		 * the same memory block, and the hint should not grow larger
		 * than PAGE_SIZE if it was smaller before.
		 */
		if (size < PAGE_SIZE / 2) {
			int max;
			max = obj->free_offset + size;
			/* This is racy, but races won't do any harm because
			 * it is just a hint, not essential.
			 */
			if ((max < PAGE_SIZE || object_layout->size_hint > PAGE_SIZE) && 
			    object_layout->size_hint < max)
				object_layout->size_hint = max;
		}

		res = brick_zmem_alloc(size);
		atomic_inc(&object_layout->aspect_count);
		atomic_inc(&object_layout->total_aspect_count);
	}
	res->object = obj;
	res->aspect_type = aspect_type;

	if (aspect_type->init_fn) {
		int status = aspect_type->init_fn(res);
		if (unlikely(status < 0)) {
			BRICK_ERR("aspect init %p %p %p status = %d\n", aspect_type, obj, res, status);
			goto done;
		}
	}

done:
	return res;
}

struct generic_aspect *generic_get_aspect(struct generic_brick *brick, struct generic_object *obj)
{
	struct generic_aspect *res = NULL;
	int nr;

	CHECK_PTR(brick, done);
	CHECK_PTR(obj, done);

	nr = brick->aspect_context.brick_index;
	if (unlikely(nr <= 0 || nr >= obj->aspect_nr_max)) {
		BRICK_ERR("bad nr = %d\n", nr);
		goto done;
	}

	res = obj->aspects[nr];
	if (!res) {
		const struct generic_object_type *object_type = obj->object_type;
		const struct generic_brick_type *brick_type = brick->type;
		const struct generic_aspect_type *aspect_type;
		int object_type_nr;

		CHECK_PTR_NULL(object_type, done);
		CHECK_PTR_NULL(brick_type, done);
		object_type_nr = object_type->object_type_nr;
		aspect_type = brick_type->aspect_types[object_type_nr];
		CHECK_PTR_NULL(aspect_type, done);

		res = _new_aspect(aspect_type, obj);

		obj->aspects[nr] = res;
	}
	CHECK_PTR(res, done);
	CHECK_PTR(res->object, done);
	_CHECK(res->object == obj, done);

done:
	return res;
}
EXPORT_SYMBOL_GPL(generic_get_aspect);

/////////////////////////////////////////////////////////////////

// helper stuff

void set_button(struct generic_switch *sw, bool val, bool force)
{
	bool oldval = sw->button;
	if ((sw->force_off |= force))
		val = false;
	if (val != oldval) {
		sw->button = val;
		wake_up_interruptible(&sw->event);
	}
}
EXPORT_SYMBOL_GPL(set_button);

void set_led_on(struct generic_switch *sw, bool val)
{
	bool oldval = sw->led_on;
	if (val != oldval) {
		sw->led_on = val;
		wake_up_interruptible(&sw->event);
	}
}
EXPORT_SYMBOL_GPL(set_led_on);

void set_led_off(struct generic_switch *sw, bool val)
{
	bool oldval = sw->led_off;
	if (val != oldval) {
		sw->led_off = val;
		wake_up_interruptible(&sw->event);
	}
}
EXPORT_SYMBOL_GPL(set_led_off);

void set_button_wait(struct generic_brick *brick, bool val, bool force, int timeout)
{
	set_button(&brick->power, val, force);
	if (brick->ops)
		(void)brick->ops->brick_switch(brick);
	if (val) {
		wait_event_interruptible_timeout(brick->power.event, brick->power.led_on, timeout);
	} else {
		wait_event_interruptible_timeout(brick->power.event, brick->power.led_off, timeout);
	}
}
EXPORT_SYMBOL_GPL(set_button_wait);

/////////////////////////////////////////////////////////////////

// meta stuff

const struct meta *find_meta(const struct meta *meta, const char *field_name)
{
	const struct meta *tmp;
	for (tmp = meta; tmp->field_name; tmp++) {
		if (!strcmp(field_name, tmp->field_name)) {
			return tmp;
		}
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(find_meta);

/////////////////////////////////////////////////////////////////////////

// module init stuff

int __init init_brick(void)
{
	nr_table = brick_zmem_alloc(nr_max);
	return 0;
}

void exit_brick(void)
{
	if (nr_table) {
		brick_mem_free(nr_table);
		nr_table = NULL;
	}
}
