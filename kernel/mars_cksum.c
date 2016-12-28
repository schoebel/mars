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

static
void compute_cksum(struct cksum_mref_aspect *mref_a, struct cksum_record_v1 *cs, bool clear)
{
	struct mref_object *mref = mref_a->object;

	if (clear) {
		memset(cs->cs_cksum, 0, sizeof(cs->cs_cksum));
	} else {
		mars_digest(cs->cs_cksum, mref->ref_data, mref->ref_len);
	}
	get_lamport(&cs->cs_stamp);
}

static
int compare_cksum(struct cksum_record_v1 *a, struct cksum_record_v1 *b)
{
	static const struct cksum_record_v1 zero = {};
	int status = memcmp(a->cs_cksum, b->cs_cksum, sizeof(zero.cs_cksum));

	/* Zero means "undefined" => report special values in such cases */
	if (status) {
		if (!memcmp(a->cs_cksum, zero.cs_cksum, sizeof(zero.cs_cksum)))
			status = INT_MIN;
		else if (!memcmp(b->cs_cksum, zero.cs_cksum, sizeof(zero.cs_cksum)))
			status = INT_MAX;
	}
	return status;
}

static inline
loff_t sub_pos(loff_t pos)
{
	return pos / CKSUM_PAGE_SIZE * sizeof(struct cksum_record_v1) + CKSUM_PAGE_SIZE;
}

static
void cksum_endio(struct generic_callback *cb);

static
void dummy_endio(struct generic_callback *cb)
{
	/* do nothing */
}

static
void start_my_io(struct cksum_mref_aspect *mref_a, bool do_endio)
{
	struct cksum_brick *brick = mref_a->brick;
	struct cksum_input_cksum*input_cksum = (void *)brick->inputs[1];
	struct mref_object *sub_mref = cksum_alloc_mref(brick);
	struct mref_object *mref = mref_a->object;
	loff_t pos = mref->ref_pos;
	int rw = mref->ref_rw;
	int status;

	sub_mref->ref_data = &mref_a->cs;
	sub_mref->ref_pos = sub_pos(pos);
	sub_mref->ref_len = sizeof(struct cksum_record_v1);
	sub_mref->ref_rw = rw;
	if (do_endio) {
		_mref_get(mref);
		mref_a->delayed_dec++;
		SETUP_CALLBACK(sub_mref, cksum_endio, mref_a);
		atomic_inc(&mref_a->cb_count);
	} else {
		SETUP_CALLBACK(sub_mref, dummy_endio, mref_a);
	}

	status = GENERIC_INPUT_CALL(&input_cksum->inp, mref_get, sub_mref);
	if (unlikely(status < 0)) {
		MARS_ERR("bad read pos=%lld, status = %d", pos, status);
		goto err_callback;
	}
	if (unlikely(sub_mref->ref_len != sizeof(struct cksum_record_v1))) {
		MARS_ERR("bad ref_len=%d, pos=%lld\n", sub_mref->ref_len, pos);
		status = -EPROTO;
		goto err_callback;
	}
	GENERIC_INPUT_CALL(&input_cksum->inp, mref_io, sub_mref);
	GENERIC_INPUT_CALL(&input_cksum->inp, mref_put, sub_mref);
	return;

 err_callback:
	memset(&mref_a->cs, 0, sizeof(mref_a->cs));
	SIMPLE_CALLBACK(sub_mref, status);
}

static
void cksum_do_start(struct cksum_mref_aspect *mref_a)
{
	struct cksum_brick *brick = mref_a->brick;

	if (mref_a->orig_rw == READ) {
		atomic_inc(&brick->total_reads);
		if (mref_a->is_right_sized)
			start_my_io(mref_a, true);
		else
			atomic_inc(&brick->total_small_reads);
	} else {
		atomic_inc(&brick->total_writes);
		if (!mref_a->is_right_sized)
			atomic_inc(&brick->total_small_writes);
		compute_cksum(mref_a, &mref_a->cs, !mref_a->is_right_sized);
		start_my_io(mref_a, true);
	}
}

static
void cksum_do_finish(struct cksum_mref_aspect *mref_a, int error)
{
	if (mref_a->orig_rw == READ && mref_a->is_right_sized) {
		struct cksum_brick *brick = mref_a->brick;
		struct cksum_record_v1 real;
		int status;

		compute_cksum(mref_a, &real, false);
		status = compare_cksum(&mref_a->cs, &real);
		if (!status) {
			atomic_inc(&brick->total_success);
		} else if (status != INT_MAX && status != INT_MIN) {
			struct mref_object *mref = mref_a->object;

			atomic_inc(&brick->total_errors);
			if (brick->report_errors) {
				MARS_ERR("CKSUM MISMATCH status=%d pos=%lld len=%d\n",
					 status, mref->ref_pos, mref->ref_len);
			}
			/* Hard blocking exactly where it is */
			while (brick->block_on_errors) {
				brick_msleep(100);
			}
		}
	}
}

static
void cksum_endio(struct generic_callback *cb)
{
	struct cksum_mref_aspect *mref_a = cb->cb_private;
	struct generic_callback *master_cb;
	int error;

	CHECK_PTR(mref_a, err);

	error = cb->cb_error;
	if (mref_a->cb_error >= 0)
		mref_a->cb_error = error;

	if (!atomic_dec_and_test(&mref_a->cb_count))
		return;

	cksum_do_finish(mref_a, mref_a->cb_error);

	master_cb = mref_a->master_cb;
	CHECK_PTR(master_cb, err);
	master_cb->cb_error = mref_a->cb_error;
	master_cb->cb_fn(master_cb);

	while (mref_a->delayed_dec > 0) {
		struct cksum_brick *brick = mref_a->brick;
		struct cksum_input_orig *input_orig = (void *)brick->inputs[0];
		struct mref_object *mref = mref_a->object;

		GENERIC_INPUT_CALL(&input_orig->inp, mref_put, mref);
		mref_a->delayed_dec--;
	}
	return;
err:
        MARS_FAT("cannot handle callback\n");
}

static
void setup_callback(struct cksum_mref_aspect *mref_a, struct mref_object *mref)
{
	if (!mref_a->master_cb && mref->object_cb && mref->object_cb->cb_fn) {
		mref_a->master_cb = mref->object_cb;
		INSERT_CALLBACK(mref, &mref_a->inter_cb, cksum_endio, mref_a);
	}
}

////////////////// own brick / input / output operations //////////////////

static
int cksum_get_info(struct cksum_output *output, struct mars_info *info)
{
	struct cksum_brick *brick = output->brick;
	struct cksum_input_orig *input_orig = (void *)brick->inputs[0];

	return GENERIC_INPUT_CALL(&input_orig->inp, mars_get_info, info);
}

static
int cksum_ref_get(struct cksum_output *output, struct mref_object *mref)
{
	struct cksum_brick *brick = output->brick;
	struct cksum_input_orig *input_orig = (void *)brick->inputs[0];
	struct cksum_mref_aspect *mref_a;
	int offset;
	int status;

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

	mref_a = cksum_mref_get_aspect(brick, mref);
	mref_a->brick = brick;
	setup_callback(mref_a, mref);

	offset = mref->ref_pos & (CKSUM_PAGE_SIZE - 1);
	if (!offset && mref->ref_len > CKSUM_PAGE_SIZE)
		mref->ref_len = CKSUM_PAGE_SIZE;

	status = GENERIC_INPUT_CALL(&input_orig->inp, mref_get, mref);

	mref_a->is_right_sized = !offset && mref->ref_len == CKSUM_PAGE_SIZE;
	return status;
}

static
void cksum_ref_put(struct cksum_output *output, struct mref_object *mref)
{
	struct cksum_brick *brick = output->brick;
	struct cksum_input_orig *input_orig = (void *)brick->inputs[0];

	GENERIC_INPUT_CALL(&input_orig->inp, mref_put, mref);
}

static
void cksum_ref_io(struct cksum_output *output, struct mref_object *mref)
{
	struct cksum_brick *brick = output->brick;
	struct cksum_input_orig *input_orig = (void *)brick->inputs[0];
	struct cksum_mref_aspect *mref_a;

	mref_a = cksum_mref_get_aspect(brick, mref);
	mref_a->brick = brick;
	setup_callback(mref_a, mref);

	atomic_set(&mref_a->cb_count, 1);
	mref_a->orig_rw = mref->ref_rw;

	cksum_do_start(mref_a);

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
		 "total_reads = %d "
		 "total_writes = %d "
		 "total_small_reads = %d "
		 "total_small_writes = %d "
		 "total_success = %d "
		 "total_errors = %d\n",
		 atomic_read(&brick->total_reads),
		 atomic_read(&brick->total_writes),
		 atomic_read(&brick->total_small_reads),
		 atomic_read(&brick->total_small_writes),
		 atomic_read(&brick->total_success),
		 atomic_read(&brick->total_errors));
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
