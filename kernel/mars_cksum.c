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


/* cksum - safeguarding by checksums
 */

//#define BRICK_DEBUGGING
#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_cksum.h"

///////////////////////// own helper functions ////////////////////////

////////////////// own brick / input / output operations //////////////////

static
int cksum_get_info(struct cksum_output *output, struct mars_info *info)
{
	struct cksum_input_orig *input_orig = (void *)output->brick->inputs[0];
	struct cksum_input_cksum *input_cksum = (void *)output->brick->inputs[1];

	return GENERIC_INPUT_CALL(&input_orig->inp, mars_get_info, info);
}

static
int cksum_ref_get(struct cksum_output *output, struct mref_object *mref)
{
	struct cksum_input_orig *input_orig = (void *)output->brick->inputs[0];

	return GENERIC_INPUT_CALL(&input_orig->inp, mref_get, mref);
}

static
void cksum_ref_put(struct cksum_output *output, struct mref_object *mref)
{
	struct cksum_input_orig *input_orig = (void *)output->brick->inputs[0];

	GENERIC_INPUT_CALL(&input_orig->inp, mref_put, mref);
}

static
void cksum_ref_io(struct cksum_output *output, struct mref_object *mref)
{
	struct cksum_input_orig *input_orig = (void *)output->brick->inputs[0];

	GENERIC_INPUT_CALL(&input_orig->inp, mref_io, mref);
}

static
int cksum_switch(struct cksum_brick *brick)
{
	if (brick->power.button) {
		bool success = false;
		if (brick->power.led_on)
			goto done;
		mars_power_led_off((void*)brick, false);
		//...
		success = true;
		if (success) {
			mars_power_led_on((void*)brick, true);
		}
	} else {
		bool success = false;
		if (brick->power.led_off)
			goto done;
		mars_power_led_on((void*)brick, false);
		//...
		success = true;
		if (success) {
			mars_power_led_off((void*)brick, true);
		}
	}
done:
	return 0;
}


//////////////// informational / statistics ///////////////

static
char *cksum_statistics(struct cksum_brick *brick, int verbose)
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
void cksum_reset_statistics(struct cksum_brick *brick)
{
}

//////////////// object / aspect constructors / destructors ///////////////

static
int cksum_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct cksum_mref_aspect *ini = (void*)_ini;
	(void)ini;
	return 0;
}

static
void cksum_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct cksum_mref_aspect *ini = (void*)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(cksum);

////////////////////// brick constructors / destructors ////////////////////

static
int cksum_brick_construct(struct cksum_brick *brick)
{
	return 0;
}

static
int cksum_brick_destruct(struct cksum_brick *brick)
{
	return 0;
}

static
int cksum_output_construct(struct cksum_output *output)
{
	return 0;
}

static
int cksum_output_destruct(struct cksum_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static
struct cksum_brick_ops cksum_brick_ops = {
	.brick_switch = cksum_switch,
	.brick_statistics = cksum_statistics,
	.reset_statistics = cksum_reset_statistics,
};

static
struct cksum_output_ops cksum_output_ops = {
	.mars_get_info = cksum_get_info,
	.mref_get = cksum_ref_get,
	.mref_put = cksum_ref_put,
	.mref_io = cksum_ref_io,
};

const struct cksum_input_type cksum_input_orig_type = {
	.type_name = "cksum_input_orig",
	.input_size = sizeof(struct cksum_input_orig),
};

const struct cksum_input_type cksum_input_cksum_type = {
	.type_name = "cksum_input_cksum",
	.input_size = sizeof(struct cksum_input_cksum),
};

static
const struct cksum_input_type *cksum_input_types[] = {
	&cksum_input_orig_type,
	&cksum_input_cksum_type,
};

const struct cksum_output_type cksum_output_type = {
	.type_name = "cksum_output",
	.output_size = sizeof(struct cksum_output),
	.master_ops = &cksum_output_ops,
	.output_construct = &cksum_output_construct,
	.output_destruct = &cksum_output_destruct,
};

static
const struct cksum_output_type *cksum_output_types[] = {
	&cksum_output_type,
};

const struct cksum_brick_type cksum_brick_type = {
	.type_name = "cksum_brick",
	.brick_size = sizeof(struct cksum_brick),
	.max_inputs = 2,
	.max_outputs = 1,
	.master_ops = &cksum_brick_ops,
	.aspect_types = cksum_aspect_types,
	.default_input_types = cksum_input_types,
	.default_output_types = cksum_output_types,
	.brick_construct = &cksum_brick_construct,
	.brick_destruct = &cksum_brick_destruct,
};
EXPORT_SYMBOL_GPL(cksum_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_cksum(void)
{
	MARS_INF("init_cksum()\n");
	return cksum_register_brick_type();
}

void exit_mars_cksum(void)
{
	MARS_INF("exit_cksum()\n");
	cksum_unregister_brick_type();
}
