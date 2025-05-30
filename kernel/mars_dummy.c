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


/* Dummy brick (just for demonstration)
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

/* ///////////////////////// own type definitions //////////////////////// */

#include "mars_dummy.h"

/* ///////////////////////// own helper functions //////////////////////// */

/* ////////////////// own brick / input / output operations ////////////////// */

static
bool dummy_switch_on(struct dummy_brick *brick)
{
	return false;
}

static
bool dummy_switch_off(struct dummy_brick *brick)
{
	return false;
}

static
int dummy_get_info(struct dummy_output *output, struct mars_info *info)
{
	struct dummy_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static
int dummy_ref_get(struct dummy_output *output, struct mref_object *mref)
{
	struct dummy_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, mref_get, mref);
}

static
void dummy_ref_put(struct dummy_output *output, struct mref_object *mref)
{
	struct dummy_input *input = output->brick->inputs[0];

	GENERIC_INPUT_CALL_VOID(input, mref_put, mref);
}

static
void dummy_ref_io(struct dummy_output *output, struct mref_object *mref)
{
	struct dummy_input *input = output->brick->inputs[0];

	GENERIC_INPUT_CALL_VOID(input, mref_io, mref);
}

static
int dummy_switch(struct dummy_brick *brick)
{
	if (brick->power.button) {
		bool success = false;

		if (brick->power.led_on)
			goto done;
		mars_power_led_off((void *)brick, false);
		success = dummy_switch_on(brick);
		if (success) {
			mars_power_led_on((void *)brick, true);
		}
	} else {
		bool success = false;

		if (brick->power.led_off)
			goto done;
		mars_power_led_on((void *)brick, false);
		success = dummy_switch_off(brick);
		if (success) {
			mars_power_led_off((void *)brick, true);
		}
	}
done:
	return 0;
}


/* //////////////// informational / statistics /////////////// */

static
char *dummy_statistics(struct dummy_brick *brick, int verbose)
{
	char *res = brick_string_alloc(1024);
	if (!res)
		return NULL;

	snprintf(res, 1023,
		 "nothing has happened.\n"
		);

	return res;
}

static
void dummy_reset_statistics(struct dummy_brick *brick)
{
}

/* //////////////// object / aspect constructors / destructors /////////////// */

static
int dummy_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct dummy_mref_aspect *ini = (void *)_ini;
	(void)ini;
	// ini->my_own = 0;
	return 0;
}

static
void dummy_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct dummy_mref_aspect *ini = (void *)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(dummy);

/* ////////////////////// brick constructors / destructors //////////////////// */

static
int dummy_brick_construct(struct dummy_brick *brick)
{
	//brick->my_own = 0;
	return 0;
}

static
int dummy_brick_destruct(struct dummy_brick *brick)
{
	return 0;
}

static
int dummy_output_construct(struct dummy_output *output)
{
	//output->my_own = 0;
	return 0;
}

static
int dummy_output_destruct(struct dummy_output *output)
{
	return 0;
}

/* ///////////////////////// static structs //////////////////////// */

static
struct dummy_brick_ops dummy_brick_ops = {
	.brick_switch = dummy_switch,
	.brick_statistics = dummy_statistics,
	.reset_statistics = dummy_reset_statistics,
};

static
struct dummy_output_ops dummy_output_ops = {
	.mars_get_info = dummy_get_info,
	.mref_get = dummy_ref_get,
	.mref_put = dummy_ref_put,
	.mref_io = dummy_ref_io,
};

const struct dummy_input_type dummy_input_type = {
	.type_name = "dummy_input",
	.input_size = sizeof(struct dummy_input),
};

static
const struct dummy_input_type *dummy_input_types[] = {
	&dummy_input_type,
};

const struct dummy_output_type dummy_output_type = {
	.type_name = "dummy_output",
	.output_size = sizeof(struct dummy_output),
	.master_ops = &dummy_output_ops,
	.output_construct = &dummy_output_construct,
	.output_destruct = &dummy_output_destruct,
};

static
const struct dummy_output_type *dummy_output_types[] = {
	&dummy_output_type,
};

const struct dummy_brick_type dummy_brick_type = {
	.type_name = "dummy_brick",
	.brick_size = sizeof(struct dummy_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &dummy_brick_ops,
	.aspect_types = dummy_aspect_types,
	.default_input_types = dummy_input_types,
	.default_output_types = dummy_output_types,
	.brick_construct = &dummy_brick_construct,
	.brick_destruct = &dummy_brick_destruct,
};
EXPORT_SYMBOL_GPL(dummy_brick_type);

/* ////////////////// module init stuff ///////////////////////// */

int __init init_mars_dummy(void)
{
	MARS_INF("init_dummy()\n");
	return dummy_register_brick_type();
}

void exit_mars_dummy(void)
{
	MARS_INF("exit_dummy()\n");
	dummy_unregister_brick_type();
}
