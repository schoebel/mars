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

int _brick_msleep(int msecs, bool shorten)
{
	unsigned long timeout;
	flush_signals(current);
	if (msecs <= 0) {
		brick_yield();
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
		if (!nr_table) {
			return 0;
		}
	}

	for (;;) {
		for (nr = 1; nr < nr_max; nr++) {
			if (!nr_table[nr]) {
				nr_table[nr] = 1;
				return nr;
			}
		}
		new = brick_zmem_alloc(nr_max << 1);
		if (!new)
			return 0;
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

struct generic_object *generic_alloc(struct generic_brick *brick, struct generic_object_layout *object_layout, const struct generic_object_type *object_type)
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
	if (!data)
		goto err;

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

static
struct generic_aspect *_new_aspect(struct generic_brick *brick, struct generic_object *obj)
{
	struct generic_aspect *res = NULL;
	const struct generic_brick_type *brick_type = brick->type;
	const struct generic_object_type *object_type;
	const struct generic_aspect_type *aspect_type;
	int object_type_nr;
	int size;
	int rest;
	
	object_type = obj->object_type;
	CHECK_PTR_NULL(object_type, done);
	object_type_nr = object_type->object_type_nr;
	aspect_type = brick_type->aspect_types[object_type_nr];
	CHECK_PTR_NULL(aspect_type, done);
	
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
		if (unlikely(!res)) {
			goto done;
		}
		atomic_inc(&object_layout->aspect_count);
		atomic_inc(&object_layout->total_aspect_count);
	}
	res->object = obj;
	res->aspect_type = aspect_type;

	if (aspect_type->init_fn) {
		int status = aspect_type->init_fn(res);
		if (unlikely(status < 0)) {
			BRICK_ERR("aspect init %p %p %p status = %d\n", brick, obj, res, status);
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

	nr = brick->brick_index;
	if (unlikely(nr <= 0 || nr >= obj->aspect_nr_max)) {
		BRICK_ERR("bad nr = %d\n", nr);
		goto done;
	}

	res = obj->aspects[nr];
	if (!res) {
		res = _new_aspect(brick, obj);
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
		//sw->trigger = true;
		wake_up_interruptible(&sw->event);
	}
}
EXPORT_SYMBOL_GPL(set_button);

void set_led_on(struct generic_switch *sw, bool val)
{
	bool oldval = sw->led_on;
	if (val != oldval) {
		sw->led_on = val;
		//sw->trigger = true;
		wake_up_interruptible(&sw->event);
	}
}
EXPORT_SYMBOL_GPL(set_led_on);

void set_led_off(struct generic_switch *sw, bool val)
{
	bool oldval = sw->led_off;
	if (val != oldval) {
		sw->led_off = val;
		//sw->trigger = true;
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

#if 0 // currently not needed, but this may change
void free_meta(void *data, const struct meta *meta)
{
	for (; meta->field_name[0]; meta++) {
		void *item;
		switch (meta->field_type) {
		case FIELD_SUB:
			if (meta->field_ref) {
				item = data + meta->field_offset;
				free_meta(item, meta->field_ref);
			}
			break;
		case FIELD_REF:
		case FIELD_STRING:
			item = data + meta->field_offset;
			item = *(void**)item;
			if (meta->field_ref)
				free_meta(item, meta->field_ref);
			brick_mem_free(item);
		}
	}
}
EXPORT_SYMBOL_GPL(free_meta);
#endif

/////////////////////////////////////////////////////////////////////////

// module init stuff

int __init init_brick(void)
{
	nr_table = brick_zmem_alloc(nr_max);
	if (!nr_table) {
		return -ENOMEM;
	}
	return 0;
}

void exit_brick(void)
{
	brick_mem_free(nr_table);
}
