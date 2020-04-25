/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2020 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2020 1&1 Ionos
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


//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_gate.h"

///////////////////////// own helper functions ////////////////////////

static
void gate_enqueue(struct gate_brick *brick, struct gate_mref_aspect *mref_a)
{
	mutex_lock(&brick->mutex);
	list_add_tail(&mref_a->gate_head, &brick->gate_anchor);
	brick->gate_queued++;
	mutex_unlock(&brick->mutex);

	wake_up_interruptible_all(&brick->gate_event);
}

static
struct gate_mref_aspect *gate_dequeue(struct gate_brick *brick)
{
	struct gate_mref_aspect *res = NULL;

	mutex_lock(&brick->mutex);
	if (!list_empty(&brick->gate_anchor)) {
		struct list_head *elem = brick->gate_anchor.next;

		res = container_of(elem, struct gate_mref_aspect, gate_head);
		list_del_init(elem);
		brick->gate_queued--;
	}
	mutex_unlock(&brick->mutex);
	return res;
}

////////////////// own brick / input / output operations //////////////////

static
int gate_get_info(struct gate_output *output, struct mars_info *info)
{
	struct gate_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static
int gate_ref_get(struct gate_output *output, struct mref_object *mref)
{
	struct gate_brick *brick = output->brick;
	struct gate_input *input = brick->inputs[0];

#if 0
	/* only for testing */
	if (brick->inhibit_mask < 0 && (brick->inhibit_mask & 1024)) {
		/* allow separate testing for ref_get() and for ref_io() */
		return (brick->inhibit_mask & ~1024);
	}
#endif
	return GENERIC_INPUT_CALL(input, mref_get, mref);
}

static
void gate_ref_put(struct gate_output *output, struct mref_object *mref)
{
	struct gate_input *input = output->brick->inputs[0];

	GENERIC_INPUT_CALL(input, mref_put, mref);
}

static
void gate_ref_io(struct gate_output *output, struct mref_object *mref)
{
	struct gate_brick *brick = output->brick;
	struct gate_input *input = brick->inputs[0];
	int error = (int)brick->inhibit_mask;

	/* Forceful abortion of IO requests */
	if (error < 0 ||
	    !brick->power.led_on) {
		if (error >= 0)
			error = -ESHUTDOWN;
		SIMPLE_CALLBACK(mref, error);
		GENERIC_INPUT_CALL(input, mref_put, mref);
		return;
	}

	/* Writes must never permute with each other.
	 * Queue them until fully drained.
	 */
	if (mref->ref_flags & brick->inhibit_mask ||
	    (brick->gate_queued > 0 &&
	     mref->ref_flags & MREF_WRITE)) {
		struct gate_mref_aspect *mref_a = gate_mref_get_aspect(brick, mref);

		_mref_get(mref);
		gate_enqueue(brick, mref_a);
		return;
	}
	GENERIC_INPUT_CALL(input, mref_io, mref);
}

static
int gate_thread(void *data)
{
	struct gate_brick *brick = data;

	while (brick->power.button || brick->gate_queued) {
		struct gate_mref_aspect *mref_a;
		int error;

		cond_resched();

		wait_event_interruptible_timeout(brick->gate_event,
						 (brick->gate_queued &&
						  brick->inhibit_mask <= 0) ||
						 !brick->power.button,
						 HZ);

		if (brick->inhibit_mask > 0 && brick->power.button)
			continue;

		mref_a = gate_dequeue(brick);
		if (!mref_a)
			continue;

		/* catch up the delayed requests */
		error = (int)brick->inhibit_mask;
		if (!brick->power.button || error < 0) {
			/* signal forceful termination for any remaining IO requests */
			if (error >= 0)
				error = -ESTALE;
			SIMPLE_CALLBACK(mref_a->object, error);
		} else {
			GENERIC_INPUT_CALL(brick->inputs[0], mref_io, mref_a->object);
		}
		GENERIC_INPUT_CALL(brick->inputs[0], mref_put, mref_a->object);
	}
	brick->terminated = true;
	return 0;
}

static
int gate_switch(struct gate_brick *brick)
{
	static int gate_thread_nr;

	if (brick->power.button || brick->gate_queued) {
		bool success = false;

		if (brick->power.led_on &&
		    !brick->terminated &&
		    brick->gate_thread)
			goto done;
		mars_power_led_off((void *)brick, false);
		if (!brick->gate_thread || brick->terminated) {
			brick->terminated = false;
			brick->gate_thread =
			  brick_thread_create(gate_thread, brick,
					      "mars_gate%d", ++gate_thread_nr);
		}
		success = (brick->gate_thread != NULL);
		if (success) {
			mars_power_led_on((void *)brick, true);
		}
	} else {
		bool success = false;

		if (brick->power.led_off)
			goto done;
		mars_power_led_on((void *)brick, false);
		wake_up_interruptible_all(&brick->gate_event);
		if (brick->terminated) {
			brick_thread_stop(brick->gate_thread);
			brick->gate_thread = NULL;
		}
		success = (!brick->gate_thread && !brick->gate_queued);
		if (success) {
			mars_power_led_off((void *)brick, true);
		}
	}
done:
	return 0;
}


//////////////// informational / statistics ///////////////

static
char *gate_statistics(struct gate_brick *brick, int verbose)
{
	char *res = brick_string_alloc(1024);
	if (!res)
		return NULL;

	snprintf(res, 1023,
		 "thread=%p "
		 "terminated=%d "
		 "inhibit=0x%x "
		 "queued=%d\n",
		 brick->gate_thread,
		 brick->terminated,
		 brick->inhibit_mask,
		 brick->gate_queued
		);

	return res;
}

static
void gate_reset_statistics(struct gate_brick *brick)
{
}

//////////////// object / aspect constructors / destructors ///////////////

static
int gate_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct gate_mref_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->gate_head);
	return 0;
}

static
void gate_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct gate_mref_aspect *ini = (void *)_ini;

	CHECK_HEAD_EMPTY(&ini->gate_head);
}

MARS_MAKE_STATICS(gate);

////////////////////// brick constructors / destructors ////////////////////

static
int gate_brick_construct(struct gate_brick *brick)
{
	mutex_init(&brick->mutex);
	INIT_LIST_HEAD(&brick->gate_anchor);
	init_waitqueue_head(&brick->gate_event);
	return 0;
}

static
int gate_brick_destruct(struct gate_brick *brick)
{
	CHECK_HEAD_EMPTY(&brick->gate_anchor);
	return 0;
}

static
int gate_output_construct(struct gate_output *output)
{
	return 0;
}

static
int gate_output_destruct(struct gate_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static
struct gate_brick_ops gate_brick_ops = {
	.brick_switch = gate_switch,
	.brick_statistics = gate_statistics,
	.reset_statistics = gate_reset_statistics,
};

static
struct gate_output_ops gate_output_ops = {
	.mars_get_info = gate_get_info,
	.mref_get = gate_ref_get,
	.mref_put = gate_ref_put,
	.mref_io = gate_ref_io,
};

const struct gate_input_type gate_input_type = {
	.type_name = "gate_input",
	.input_size = sizeof(struct gate_input),
};

static
const struct gate_input_type *gate_input_types[] = {
	&gate_input_type,
};

const struct gate_output_type gate_output_type = {
	.type_name = "gate_output",
	.output_size = sizeof(struct gate_output),
	.master_ops = &gate_output_ops,
	.output_construct = &gate_output_construct,
	.output_destruct = &gate_output_destruct,
};

static
const struct gate_output_type *gate_output_types[] = {
	&gate_output_type,
};

const struct gate_brick_type gate_brick_type = {
	.type_name = "gate_brick",
	.brick_size = sizeof(struct gate_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &gate_brick_ops,
	.aspect_types = gate_aspect_types,
	.default_input_types = gate_input_types,
	.default_output_types = gate_output_types,
	.brick_construct = &gate_brick_construct,
	.brick_destruct = &gate_brick_destruct,
};
EXPORT_SYMBOL_GPL(gate_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_gate(void)
{
	MARS_INF("init_gate()\n");
	return gate_register_brick_type();
}

void exit_mars_gate(void)
{
	MARS_INF("exit_gate()\n");
	gate_unregister_brick_type();
}
