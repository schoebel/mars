// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/semaphore.h>

//#define BRICK_DEBUGGING

//#define USE_FREELIST // use this, but improve freeing

#define _STRATEGY
#define BRICK_OBJ_MAX /*empty => leads to an open array */
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
	const struct generic_output_type **output_types,
	const char **names)
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

	status = generic_brick_init(brick_type, brick, names ? *names++ : NULL);
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
		status = generic_input_init(brick, i, type, input, (names && *names) ? *names++ : type->type_name);
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
		names = brick_type->default_output_names;
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
		generic_output_init(brick, i, type, output, (names && *names) ? *names++ : type->type_name);
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
		for (i = 0; i < brick->type->max_outputs; i++) {
			struct generic_output *output = brick->outputs[i];
			if (output && output->nr_connected) {
				postpone += output->nr_connected;
			}
		}
		for (i = 0; i < brick->type->max_inputs; i++) {
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
	int i;

	(void)i;

	if (unlikely(!object_layout->object_type)) {
		return -EINVAL;
	}

#if 0
	nr = object_layout->object_type->brick_obj_nr;
	if (nr < 0 || nr >= BRICK_OBJ_NR) {
		return -EINVAL;
	}
#else
	nr = 0;
#endif
	aspect_layout = (void*)&output->output_aspect_layouts[nr];
	if (aspect_layout->aspect_type && aspect_layout->aspect_layout_generation == object_layout->object_layout_generation) {
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
		aspect_layout->aspect_type = aspect_type;
		aspect_layout->init_data = output;
		aspect_layout->aspect_offset = object_layout->object_size;
		object_layout->object_size += aspect_type->aspect_size;
		aspect_layout->aspect_layout_generation = object_layout->object_layout_generation;
		BRICK_DBG("initializing aspect_type %s on object_layout %p, object_size=%d\n", aspect_type->aspect_type_name, object_layout, object_layout->object_size);
	}
	// find an empty slot
	nr = -1;
#if 0
	for (i = 0; i < object_layout->aspect_count; i++) {
		if (!object_layout->aspect_layouts_table[nr]) {
			nr = i;
			break;
		}
	}
#endif
	if (nr < 0) {
		nr = object_layout->aspect_count++;
		if (nr >= object_layout->aspect_max) {
			BRICK_ERR("aspect overflow\n");
			return -ENOMEM;
		}
	}
	object_layout->aspect_layouts_table[nr] = aspect_layout;
	return 0;
}


EXPORT_SYMBOL_GPL(generic_add_aspect);

////////////////////////////////////////////////////////////////////////

// default implementations

int brick_layout_generation = 1;
EXPORT_SYMBOL_GPL(brick_layout_generation);

/* (Re-)Make an object layout
 */
int default_init_object_layout(struct generic_output *output, struct generic_object_layout *object_layout, int aspect_max, const struct generic_object_type *object_type, char *module_name)
{
	// TODO: make locking granularity finer (if it were worth).
	static DEFINE_SPINLOCK(global_lock);
	void *data;
	void *olddata;
	int status= -ENOMEM;
	unsigned long flags;

	if (unlikely(!module_name)) {
		module_name = "(unknown)";
	}

	data = kzalloc(aspect_max * sizeof(void*), GFP_MARS);
	if (unlikely(!data)) {
		BRICK_ERR("kzalloc failed, size = %lu\n", aspect_max * sizeof(void*));
		goto done;
	}

	traced_lock(&global_lock, flags);

	if (unlikely(object_layout->object_type && object_layout->object_layout_generation == brick_layout_generation)) {
		traced_unlock(&global_lock, flags);
		BRICK_DBG("lost the race on object_layout %p/%s (no harm)\n", object_layout, module_name);
		status = 0;
		goto done;
	}

	olddata = object_layout->aspect_layouts_table;

	object_layout->aspect_layouts_table = data;
	object_layout->object_layout_generation = brick_layout_generation;
	object_layout->object_type = object_type;
	object_layout->init_data = output;
	object_layout->aspect_count = 0;
	object_layout->aspect_max = aspect_max;
	object_layout->object_size = object_type->default_size;
	atomic_set(&object_layout->alloc_count, 0);
	atomic_set(&object_layout->free_count, 0);
	spin_lock_init(&object_layout->free_lock);
	object_layout->free_list = NULL;
	object_layout->module_name = module_name;

	status = output->ops->make_object_layout(output, object_layout);

	traced_unlock(&global_lock, flags);
	
	if (unlikely(status < 0)) {
                object_layout->object_type = NULL;
		kfree(data);
		BRICK_ERR("emergency, cannot add aspects to object_layout %s (module %s)\n", object_type->object_type_name, module_name);
		goto done;
	}

	BRICK_INF("OK, object_layout %s init succeeded (size = %d).\n", object_type->object_type_name, object_layout->object_size);

done:
	if (olddata) {
#if 0 // FIXME: use RCU here
		kfree(olddata);
#endif
	}
	return status;
}
EXPORT_SYMBOL_GPL(default_init_object_layout);

/* Callback, usually called for each brick instance.
 * Initialize the information for single aspect associated to a single brick.
 */
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
	struct generic_object *object = object_layout->free_list;

	if (object) {
		unsigned long flags;
		traced_lock(&object_layout->free_lock, flags);
		object = object_layout->free_list;
		if (object) {
			object_layout->free_list = *(struct generic_object**)object;
			*(struct generic_object**)object = NULL;
			traced_unlock(&object_layout->free_lock, flags);
			atomic_dec(&object_layout->free_count);
			data = object;
			goto ok;
		}
		traced_unlock(&object_layout->free_lock, flags);
	}

	data = kzalloc(object_layout->object_size, GFP_MARS);
	if (unlikely(!data))
		goto err;

	atomic_inc(&object_layout->alloc_count);

ok:
	object = generic_construct(data, object_layout);
	if (unlikely(!object))
		goto err_free;

#if 1
	{
		int count = atomic_read(&object_layout->alloc_count);
		if (count >= object_layout->last_count + 1000 || ((int)jiffies - object_layout->last_jiffies) >= 30 * HZ) {
			object_layout->last_count = count;
			object_layout->last_jiffies = jiffies;
			BRICK_INF("pool %s/%p/%s alloc=%d free=%d\n", object_layout->object_type->object_type_name, object_layout, object_layout->module_name, count, atomic_read(&object_layout->free_count));
		}
	}
#endif

	return object;

err_free:
	kfree(data);
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(alloc_generic);

void free_generic(struct generic_object *object)
{
	struct generic_object_layout *object_layout;
	if (unlikely(!object)) {
		BRICK_ERR("free_generic on NULL object\n");
		return;
	}
	object_layout = object->object_layout;
	if (likely(object_layout)) {
		generic_destruct(object);

#ifdef USE_FREELIST
		memset(object, 0, object_layout->object_size);
		atomic_inc(&object_layout->free_count);

		{
			unsigned long flags;

			traced_lock(&object_layout->free_lock, flags);

			*(struct generic_object**)object = object_layout->free_list;
			object_layout->free_list = object;
			
			traced_unlock(&object_layout->free_lock, flags);
		}
		return;
#endif
		atomic_dec(&object_layout->alloc_count);
	}

	kfree(object);
}
EXPORT_SYMBOL_GPL(free_generic);

/////////////////////////////////////////////////////////////////

// helper stuff

struct semaphore lamport_sem = __SEMAPHORE_INITIALIZER(lamport_sem, 1); // TODO: replace with spinlock if possible (first check)
struct timespec lamport_now = {};

void get_lamport(struct timespec *now)
{
	int diff;

	down(&lamport_sem);

	*now = CURRENT_TIME;
	diff = timespec_compare(now, &lamport_now);
	if (diff > 0) {
		memcpy(&lamport_now, now, sizeof(lamport_now));
	} else {
		timespec_add_ns(&lamport_now, 1);
		memcpy(now, &lamport_now, sizeof(*now));
	}

	up(&lamport_sem);
}

EXPORT_SYMBOL_GPL(get_lamport);

void set_lamport(struct timespec *old)
{
	int diff;

	down(&lamport_sem);

	diff = timespec_compare(old, &lamport_now);
	if (diff > 0) {
		memcpy(&lamport_now, old, sizeof(lamport_now));
	}

	up(&lamport_sem);
}
EXPORT_SYMBOL_GPL(set_lamport);



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

/* Do it iteratively behind the scenes ;)
 */
int set_recursive_button(struct generic_brick *orig_brick, brick_switch_t mode, int timeout)
{
	struct generic_brick **table = NULL;
	int max = PAGE_SIZE / sizeof(void*) / 2;
	int stack;
	bool val = (mode == BR_ON_ONE || mode == BR_ON_ALL);
	bool force = (mode != BR_OFF_ONE && mode != BR_OFF_ALL);
	int pos;
	int status;

#define PUSH_STACK(next)						\
	{								\
		int j;							\
		bool found = false;					\
		/* eliminate duplicates	*/				\
		for (j = 0; j < stack; j++) {				\
			if (table[j] == (next)) {			\
				BRICK_DBG("  double entry %d '%s' stack = %d\n", i, (next)->brick_name, stack); \
				found = true;				\
				break;					\
			}						\
		}							\
		if (!found) {						\
			BRICK_DBG("  push '%s' stack = %d\n", (next)->brick_name, stack); \
			table[stack++] = (next);			\
			if (unlikely(stack > max)) {			\
				BRICK_ERR("---- max = %d overflow, restarting...\n", max); \
				goto restart;				\
			}						\
		}							\
	}

 restart:
	BRICK_DBG("-> orig_brick = '%s'\n", orig_brick->brick_name);
	if (table)
		kfree(table);
	max <<= 1;
	table = kmalloc(max * sizeof(void*), GFP_MARS);
	status = -ENOMEM;
	if (unlikely(!table))
		goto done;
	
	stack = 0;
	table[stack++] = orig_brick;

	status = -EAGAIN;
	for (pos = 0; pos < stack; pos++) {
		struct generic_brick *brick = table[pos];

		BRICK_DBG("--> pos = %d stack = %d brick = '%s' inputs = %d/%d outputs = %d/%d\n", pos, stack, brick->brick_name, brick->nr_inputs, brick->type->max_inputs, brick->nr_outputs, brick->type->max_outputs);

		if (val) {
			force = false;
			if (unlikely(brick->power.force_off)) {
				status = -EDEADLK;
				goto done;
			}
			if (mode >= BR_ON_ALL) {
				int i;
				for (i = 0; i < brick->type->max_inputs; i++) {
					struct generic_input *input = brick->inputs[i];
					struct generic_output *output;
					struct generic_brick *next;
					BRICK_DBG("---> i = %d\n", i);
					msleep(1000);
					if (!input)
						continue;
					output = input->connect;
					if (!output)
						continue;
					next = output->brick;
					if (!next)
						continue;

					PUSH_STACK(next);
				}
			}
		} else if (mode >= BR_ON_ALL) {
			int i;
			for (i = 0; i < brick->type->max_outputs; i++) {
				struct generic_output *output = brick->outputs[i];
				struct list_head *tmp;
				BRICK_DBG("---> i = %d output = %p\n", i, output);
				msleep(1000);
				if (!output)
					continue;
				for (tmp = output->output_head.next; tmp && tmp != &output->output_head; tmp = tmp->next) {
					struct generic_input *input = container_of(tmp, struct generic_input, input_head);
					struct generic_brick *next = input->brick;
					BRICK_DBG("----> tmp = %p input = %p next = %p\n", tmp, input, next);
					msleep(1000);
					if (unlikely(!next)) {
						BRICK_ERR("oops, bad brick pointer\n");
						status = -EINVAL;
						goto done;
					}
					PUSH_STACK(next);
				}
			}
		}
	}

	BRICK_DBG("-> stack = %d\n", stack);

	while (stack > 0) {
		struct generic_brick *brick = table[--stack];
		BRICK_DBG("--> switch '%s' stack = %d\n", brick->brick_name, stack);
		set_button_wait(brick, val, force, timeout);
		if (val ? !brick->power.led_on : !brick->power.led_off) {
			BRICK_DBG("switching to %d: brick '%s' not ready (%s)\n", val, brick->brick_name, orig_brick->brick_name);
			goto done;
		}

		if (force && !val && (mode == BR_FREE_ONE || mode == BR_FREE_ALL) && brick->free) {
			BRICK_DBG("---> freeing '%s'\n", brick->brick_name);
			status = brick->free(brick);
			BRICK_DBG("---> freeing '%s' status = %d\n", brick->brick_name, status);
			if (status < 0) {
				BRICK_DBG("freeing brick '%s' (%s) failed, status = %d\n", brick->brick_name, orig_brick->brick_name, status);
				goto done;
			}
		}

	}
	status = 0;

done:
	BRICK_DBG("-> done '%s' status = %d\n", orig_brick->brick_name, status);
	if (table)
		kfree(table);
	return status;
}
EXPORT_SYMBOL_GPL(set_recursive_button);


/////////////////////////////////////////////////////////////////

// meta stuff

const struct meta *find_meta(const struct meta *meta, const char *field_name)
{
	const struct meta *tmp;
	for (tmp = meta; tmp->field_name[0]; tmp++) {
		if (!strncmp(field_name, tmp->field_name, MAX_FIELD_LEN)) {
			return tmp;
		}
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(find_meta);

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
			kfree(item);
		}
	}
}
EXPORT_SYMBOL_GPL(free_meta);


MODULE_LICENSE("GPL");
