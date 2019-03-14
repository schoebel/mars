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


// Usebuf brick (just for demonstration)

/* FIXME: this code has been unused for a long time, it is unlikly
 * to work at all.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING

//#define FAKE_ALL // only for testing
//#define DIRECT_IO // shortcut solely for testing: do direct IO
//#define DIRECT_WRITE // only for testing: this risks trashing the data by omitting read-before-write in case of false sharing

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_usebuf.h"

#define SHORTCUT

///////////////////////// own helper functions ////////////////////////

////////////////// own brick / input / output operations //////////////////

static int usebuf_get_info(struct usebuf_output *output, struct mars_info *info)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static inline
void _usebuf_copy(struct mref_object *mref, struct mref_object *sub_mref, int rw)
{
	MARS_IO("memcpy rw = %d %p %p %d\n", rw, mref->ref_data, sub_mref->ref_data, mref->ref_len);
#ifndef FAKE_ALL
	if (rw == 0) {
		memcpy(mref->ref_data, sub_mref->ref_data, mref->ref_len);
	} else {
		memcpy(sub_mref->ref_data, mref->ref_data, mref->ref_len);
	}
#endif
}

static void _usebuf_endio(struct generic_callback *cb)
{
	struct usebuf_mref_aspect *mref_a = cb->cb_private;
	struct mref_object *mref;
	struct usebuf_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;

	LAST_CALLBACK(cb);
	CHECK_PTR(mref_a, done);
	mref = mref_a->object;
	CHECK_PTR(mref, done);
	sub_mref_a = mref_a->sub_mref_a;
	CHECK_PTR(sub_mref_a, done);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, done);

	if (mref->ref_data != sub_mref->ref_data && cb->cb_error >= 0) {
		if (!(sub_mref->ref_flags & MREF_MAY_WRITE)) {
			if (sub_mref->ref_flags & MREF_UPTODATE) {
				_usebuf_copy(mref, sub_mref, 0);
				mref->ref_flags |= MREF_UPTODATE;
			}
#ifndef FAKE_ALL
		} else if (!(sub_mref->ref_flags & MREF_WRITE)) {
			MARS_IO("re-kick %p\n", sub_mref);
			sub_mref->ref_flags |= MREF_WRITE;
			_usebuf_copy(mref, sub_mref, 1);
			mref->ref_flags |= MREF_UPTODATE;
			GENERIC_INPUT_CALL(mref_a->input, mref_io, sub_mref);
			return;
#endif
		}
	}

#if 1
	if (mref_a->yyy++ > 0)
		MARS_ERR("yyy = %d\n", mref_a->yyy - 1);
	if (cb->cb_error < 0)
		MARS_ERR("error = %d\n", cb->cb_error);
#endif
	CHECKED_CALLBACK(mref, cb->cb_error, done);

	if (!_mref_put(mref))
		return;

#if 1
	_mref_put(sub_mref);
#endif

	usebuf_free_mref(mref);
done:;
}

static int usebuf_ref_get(struct usebuf_output *output, struct mref_object *mref)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mref_aspect *mref_a;
	struct usebuf_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	int status = 0;

	might_sleep();

	mref_a = usebuf_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return -EILSEQ;
	}

	sub_mref_a = mref_a->sub_mref_a;
	if (!sub_mref_a) {
		sub_mref = usebuf_alloc_mref(output->brick);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot get sub_mref\n");
			return -ENOMEM;
		}

		sub_mref_a = usebuf_mref_get_aspect(output->brick, sub_mref);
		if (unlikely(!sub_mref_a)) {
			MARS_FAT("cannot get aspect\n");
			return -EILSEQ;
		}

		mref_a->sub_mref_a = sub_mref_a;
		sub_mref->ref_pos = mref->ref_pos;
		sub_mref->ref_len = mref->ref_len;
		sub_mref->ref_flags = mref->ref_flags & MREF_MAY_WRITE;
#ifdef DIRECT_IO // shortcut solely for testing: do direct IO
		if (!mref->ref_data)
			MARS_ERR("NULL.......\n");
		sub_mref->ref_data = mref->ref_data;
#else // normal case: buffered IO
		sub_mref->ref_data = NULL;
#endif
		SETUP_CALLBACK(sub_mref, _usebuf_endio, mref_a);
		mref->ref_flags = 0;
	} else {
		sub_mref = sub_mref_a->object;
#if 1
		MARS_ERR("please do not use this broken feature\n");
#endif		
	}

	status = GENERIC_INPUT_CALL(input, mref_get, sub_mref);
	if (status < 0) {
		return status;
	}

	mref->ref_len = sub_mref->ref_len;
	//MARS_INF("GOT %p %p flags = %x\n", mref, sub_mref, sub_mref->ref_flags);
	if (!mref->ref_data) {
		MARS_INF("uiiiiiiiiiii\n");
		mref->ref_data = sub_mref->ref_data;
	}
	_mref_get(mref);

	return status;
}

static void usebuf_ref_put(struct usebuf_output *output, struct mref_object *mref)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mref_aspect *mref_a;
	struct usebuf_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;

	mref_a = usebuf_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return;
	}

	sub_mref_a = mref_a->sub_mref_a;
	if (!sub_mref_a) {
		MARS_FAT("sub_mref_a is missing\n");
		return;
	}

	sub_mref = sub_mref_a->object;
	if (!sub_mref) {
		MARS_FAT("sub_mref is missing\n");
		return;
	}

	if (!_mref_put(mref))
		return;

	GENERIC_INPUT_CALL(input, mref_put, sub_mref);
	usebuf_free_mref(mref);
}

static void usebuf_ref_io(struct usebuf_output *output, struct mref_object *mref)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mref_aspect *mref_a;
	struct usebuf_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	int error = -EILSEQ;

	might_sleep();

	_mref_check(mref);

	mref_a = usebuf_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		goto err;
	}

	sub_mref_a = mref_a->sub_mref_a;
	if (!sub_mref_a) {
		MARS_FAT("sub_mref is missing\n");
		goto err;
	}

	sub_mref = sub_mref_a->object;
	if (!sub_mref) {
		MARS_FAT("sub_mref is missing\n");
		goto err;
	}

	if ((mref->ref_flags % MREF_WRITE) && !(sub_mref->ref_flags & MREF_MAY_WRITE)) {
		MARS_ERR("mref_may_write was not set before\n");
		goto err;
	}

	_mref_get(mref);

	sub_mref->ref_flags |= mref->ref_flags & MREF_WRITE;
	sub_mref->ref_len = mref->ref_len;
	mref_a->input = input;
	/* Optimization: when buffered IO is used and buffer is already
	 * uptodate, skip real IO operation.
	 */
	if (mref->ref_flags & MREF_WRITE) {
#ifdef DIRECT_WRITE
		sub_mref->ref_flags |= MREF_WRITE;
#else // normal case
		sub_mref->ref_flags &= ~MREF_WRITE;
		if (sub_mref->ref_flags & MREF_UPTODATE) {
			sub_mref->ref_flags |= MREF_WRITE;
		}
#endif
	} else if (sub_mref->ref_flags & MREF_UPTODATE) {
		MARS_IO("direct _usebuf_endio\n");
		_usebuf_endio(sub_mref->object_cb);
		return;
	}
	if (mref->ref_data != sub_mref->ref_data) {
		if (sub_mref->ref_flags & MREF_WRITE) {
			_usebuf_copy(mref, sub_mref, 1);
			mref->ref_flags |= MREF_UPTODATE;
		}
	}

#ifdef FAKE_ALL
	_usebuf_endio(sub_mref->ref_cb);
	return;
#endif
	GENERIC_INPUT_CALL(input, mref_io, sub_mref);

	return;

err:
	SIMPLE_CALLBACK(mref, error);
	return;
}

//////////////// object / aspect constructors / destructors ///////////////

static int usebuf_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct usebuf_mref_aspect *ini = (void*)_ini;
	(void)ini;
	return 0;
}

static void usebuf_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct usebuf_mref_aspect *ini = (void*)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(usebuf);

////////////////////// brick constructors / destructors ////////////////////

static int usebuf_brick_construct(struct usebuf_brick *brick)
{
	return 0;
}

static int usebuf_output_construct(struct usebuf_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct usebuf_brick_ops usebuf_brick_ops = {
};

static struct usebuf_output_ops usebuf_output_ops = {
	.mars_get_info = usebuf_get_info,
	.mref_get = usebuf_ref_get,
	.mref_put = usebuf_ref_put,
	.mref_io = usebuf_ref_io,
};

const struct usebuf_input_type usebuf_input_type = {
	.type_name = "usebuf_input",
	.input_size = sizeof(struct usebuf_input),
};

static const struct usebuf_input_type *usebuf_input_types[] = {
	&usebuf_input_type,
};

const struct usebuf_output_type usebuf_output_type = {
	.type_name = "usebuf_output",
	.output_size = sizeof(struct usebuf_output),
	.master_ops = &usebuf_output_ops,
	.output_construct = &usebuf_output_construct,
};

static const struct usebuf_output_type *usebuf_output_types[] = {
	&usebuf_output_type,
};

const struct usebuf_brick_type usebuf_brick_type = {
	.type_name = "usebuf_brick",
	.brick_size = sizeof(struct usebuf_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &usebuf_brick_ops,
	.aspect_types = usebuf_aspect_types,
	.default_input_types = usebuf_input_types,
	.default_output_types = usebuf_output_types,
	.brick_construct = &usebuf_brick_construct,
};
EXPORT_SYMBOL_GPL(usebuf_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_usebuf(void)
{
	MARS_INF("init_usebuf()\n");
	return usebuf_register_brick_type();
}

void exit_mars_usebuf(void)
{
	MARS_INF("exit_usebuf()\n");
	usebuf_unregister_brick_type();
}
