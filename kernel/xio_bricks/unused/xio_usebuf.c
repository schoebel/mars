/*
 * MARS Long Distance Replication Software
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
 */

/*  Usebuf brick (just for demonstration) */

/* FIXME: this code has been unused for a long time, it is unlikly
 * to work at all.
 */

//#define BRICK_DEBUGGING
//#define XIO_DEBUGGING

//#define FAKE_ALL /*  only for testing */
//#define DIRECT_IO /*	shortcut solely for testing: do direct IO */
/*  only for testing: this risks trashing the data by omitting read-before-write in case of false sharing */
//#define DIRECT_WRITE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "../xio.h"

/************************ own type definitions ***********************/

#include "xio_usebuf.h"

#define SHORTCUT

/************************ own helper functions ***********************/

/***************** own brick * input * output operations *****************/

static int usebuf_get_info(struct usebuf_output *output, struct xio_info *info)
{
	struct usebuf_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, xio_get_info, info);
}

static inline
void _usebuf_copy(struct aio_object *aio, struct aio_object *sub_aio, int rw)
{
#ifndef FAKE_ALL
	if (rw == 0)
		memcpy(aio->io_data, sub_aio->io_data, aio->io_len);
	else
		memcpy(sub_aio->io_data, aio->io_data, aio->io_len);
#endif
}

static void _usebuf_endio(struct generic_callback *cb)
{
	struct usebuf_aio_aspect *aio_a = cb->cb_private;
	struct aio_object *aio;
	struct usebuf_aio_aspect *sub_aio_a;
	struct aio_object *sub_aio;

	LAST_CALLBACK(cb);
	CHECK_PTR(aio_a, done);
	aio = aio_a->object;
	CHECK_PTR(aio, done);
	sub_aio_a = aio_a->sub_aio_a;
	CHECK_PTR(sub_aio_a, done);
	sub_aio = sub_aio_a->object;
	CHECK_PTR(sub_aio, done);

	if (aio->io_data != sub_aio->io_data && cb->cb_error >= 0) {
		if (sub_aio->io_may_write == 0) {
			if (sub_aio->io_flags & AIO_UPTODATE) {
				_usebuf_copy(aio, sub_aio, 0);
				aio->io_flags |= AIO_UPTODATE;
			}
#ifndef FAKE_ALL
		} else if (sub_aio->io_rw == 0) {
			sub_aio->io_rw = 1;
			_usebuf_copy(aio, sub_aio, 1);
			aio->io_flags |= AIO_UPTODATE;
			GENERIC_INPUT_CALL(aio_a->input, aio_io, sub_aio);
			goto out_return;
#endif
		}
	}

#if 1
	if (aio_a->yyy++ > 0)
		XIO_ERR("yyy = %d\n", aio_a->yyy - 1);
	if (cb->cb_error < 0)
		XIO_ERR("error = %d\n", cb->cb_error);
#endif
	CHECKED_CALLBACK(aio, cb->cb_error, done);

	if (!obj_put(aio))
		goto out_return;
#if 1
	obj_put(sub_aio);
#endif

	obj_free(aio);
done:;
out_return:;
}

static int usebuf_io_get(struct usebuf_output *output, struct aio_object *aio)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_aio_aspect *aio_a;
	struct usebuf_aio_aspect *sub_aio_a;
	struct aio_object *sub_aio;
	int status = 0;

	might_sleep();

	aio_a = usebuf_aio_get_aspect(output->brick, aio);
	if (unlikely(!aio_a)) {
		XIO_FAT("cannot get aspect\n");
		return -EILSEQ;
	}

	sub_aio_a = aio_a->sub_aio_a;
	if (!sub_aio_a) {
		sub_aio = usebuf_alloc_aio(output->brick);

		sub_aio_a = usebuf_aio_get_aspect(output->brick, sub_aio);
		if (unlikely(!sub_aio_a)) {
			XIO_FAT("cannot get aspect\n");
			return -EILSEQ;
		}

		aio_a->sub_aio_a = sub_aio_a;
		sub_aio->io_pos = aio->io_pos;
		sub_aio->io_len = aio->io_len;
		sub_aio->io_may_write = aio->io_may_write;
#ifdef DIRECT_IO /*  shortcut solely for testing: do direct IO */
		if (!aio->io_data)
			XIO_ERR("NULL.......\n");
		sub_aio->io_data = aio->io_data;
#else /*  normal case: buffered IO */
		sub_aio->io_data = NULL;
#endif
		SETUP_CALLBACK(sub_aio, _usebuf_endio, aio_a);
		aio->io_flags = 0;
	} else {
		sub_aio = sub_aio_a->object;
#if 1
		XIO_ERR("please do not use this broken feature\n");
#endif
	}

	status = GENERIC_INPUT_CALL(input, aio_get, sub_aio);
	if (status < 0)
		return status;

	aio->io_len = sub_aio->io_len;
	if (!aio->io_data)
		aio->io_data = sub_aio->io_data;
	obj_get(aio);

	return status;
}

static void usebuf_io_put(struct usebuf_output *output, struct aio_object *aio)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_aio_aspect *aio_a;
	struct usebuf_aio_aspect *sub_aio_a;
	struct aio_object *sub_aio;

	aio_a = usebuf_aio_get_aspect(output->brick, aio);
	if (unlikely(!aio_a)) {
		XIO_FAT("cannot get aspect\n");
		goto out_return;
	}

	sub_aio_a = aio_a->sub_aio_a;
	if (!sub_aio_a) {
		XIO_FAT("sub_aio_a is missing\n");
		goto out_return;
	}

	sub_aio = sub_aio_a->object;
	if (!sub_aio) {
		XIO_FAT("sub_aio is missing\n");
		goto out_return;
	}

	if (!obj_put(aio))
		goto out_return;
	GENERIC_INPUT_CALL(input, aio_put, sub_aio);
	obj_free(aio);
out_return:;
}

static void usebuf_io_io(struct usebuf_output *output, struct aio_object *aio)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_aio_aspect *aio_a;
	struct usebuf_aio_aspect *sub_aio_a;
	struct aio_object *sub_aio;
	int error = -EILSEQ;

	might_sleep();

	obj_check(aio);

	aio_a = usebuf_aio_get_aspect(output->brick, aio);
	if (unlikely(!aio_a)) {
		XIO_FAT("cannot get aspect\n");
		goto err;
	}

	sub_aio_a = aio_a->sub_aio_a;
	if (!sub_aio_a) {
		XIO_FAT("sub_aio is missing\n");
		goto err;
	}

	sub_aio = sub_aio_a->object;
	if (!sub_aio) {
		XIO_FAT("sub_aio is missing\n");
		goto err;
	}

	if (aio->io_rw != 0 && sub_aio->io_may_write == 0) {
		XIO_ERR("aio_may_write was not set before\n");
		goto err;
	}

	obj_get(aio);

	sub_aio->io_rw = aio->io_rw;
	sub_aio->io_len = aio->io_len;
	aio_a->input = input;
	/* Optimization: when buffered IO is used and buffer is already
	 * uptodate, skip real IO operation.
	 */
	if (aio->io_rw != 0) {
#ifdef DIRECT_WRITE
		sub_aio->io_rw = 1;
#else /*  normal case */
		sub_aio->io_rw = 0;
		if (sub_aio->io_flags & AIO_UPTODATE)
			sub_aio->io_rw = 1;
#endif
	} else if (sub_aio->io_flags & AIO_UPTODATE) {
		_usebuf_endio(sub_aio->object_cb);
		goto out_return;
	}
	if (aio->io_data != sub_aio->io_data) {
		if (sub_aio->io_rw != 0) {
			_usebuf_copy(aio, sub_aio, 1);
			aio->io_flags |= AIO_UPTODATE;
		}
	}

#ifdef FAKE_ALL
	_usebuf_endio(sub_aio->io_cb);
	goto out_return;
#endif
	GENERIC_INPUT_CALL(input, aio_io, sub_aio);

	goto out_return;
err:
	SIMPLE_CALLBACK(aio, error);
	goto out_return;
out_return:;
}

/*************** object * aspect constructors * destructors **************/

static int usebuf_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct usebuf_aio_aspect *ini = (void *)_ini;

	(void)ini;
	return 0;
}

static void usebuf_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct usebuf_aio_aspect *ini = (void *)_ini;

	(void)ini;
}

XIO_MAKE_STATICS(usebuf);

/********************* brick constructors * destructors *******************/

static int usebuf_brick_construct(struct usebuf_brick *brick)
{
	return 0;
}

static int usebuf_output_construct(struct usebuf_output *output)
{
	return 0;
}

/************************ static structs ***********************/

static struct usebuf_brick_ops usebuf_brick_ops;

static struct usebuf_output_ops usebuf_output_ops = {
	.xio_get_info = usebuf_get_info,
	.aio_get = usebuf_io_get,
	.aio_put = usebuf_io_put,
	.aio_io = usebuf_io_io,
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

/***************** module init stuff ************************/

int __init init_xio_usebuf(void)
{
	XIO_INF("init_usebuf()\n");
	return usebuf_register_brick_type();
}

void exit_xio_usebuf(void)
{
	XIO_INF("exit_usebuf()\n");
	usebuf_unregister_brick_type();
}
