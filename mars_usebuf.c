// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Usebuf brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define FAKE_ALL // only for testing
//#define DIRECT_IO // shortcut solely for testing: do direct IO
//#define DIRECT_WRITE // only for testing: this risks trashing the data by omitting read-before-write in case of false sharing
//#define LOG

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
#ifdef LOG
	MARS_INF("memcpy rw = %d %p %p %d\n", rw, mref->ref_data, sub_mref->ref_data, mref->ref_len);
#endif
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

	CHECK_PTR(mref_a, done);
	mref = mref_a->object;
	CHECK_PTR(mref, done);
	CHECK_PTR(mref->ref_cb, done);
	sub_mref_a = mref_a->sub_mref_a;
	CHECK_PTR(sub_mref_a, done);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, done);

	//MARS_INF("HALLO %p %p len = %d may_write = %d rw = %d flags = %d\n", mref, sub_mref, sub_mref->ref_len, sub_mref->ref_may_write, sub_mref->ref_rw, sub_mref->ref_flags);

	if (mref->ref_data != sub_mref->ref_data && cb->cb_error >= 0) {
		if (sub_mref->ref_may_write == 0) {
			if (sub_mref->ref_flags & MREF_UPTODATE) {
				_usebuf_copy(mref, sub_mref, 0);
				mref->ref_flags |= MREF_UPTODATE;
			}
#ifndef FAKE_ALL
		} else if (sub_mref->ref_rw == 0) {
#ifdef LOG
			MARS_INF("re-kick %p\n", sub_mref);
#endif
			sub_mref->ref_rw = 1;
			sub_mref->ref_cb = &sub_mref_a->cb;
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
	mref->ref_cb->cb_error = cb->cb_error;
	mref->ref_cb->cb_fn(mref->ref_cb);

	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count))
		return;

#if 1
	CHECK_ATOMIC(&sub_mref->ref_count, 2);
	atomic_dec(&sub_mref->ref_count);
	{
		int test = atomic_read(&sub_mref->ref_count);
		if (test > 1) {
			MARS_INF("ref_count = %d\n", test);
		}
	}
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

	mref_a = usebuf_mref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return -EILSEQ;
	}

	sub_mref_a = mref_a->sub_mref_a;
	if (!sub_mref_a) {
		sub_mref = usebuf_alloc_mref(output, &output->mref_object_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot get sub_mref\n");
			return -ENOMEM;
		}

		sub_mref_a = usebuf_mref_get_aspect(output, sub_mref);
		if (unlikely(!sub_mref_a)) {
			MARS_FAT("cannot get aspect\n");
			return -EILSEQ;
		}

		mref_a->sub_mref_a = sub_mref_a;
		sub_mref->ref_pos = mref->ref_pos;
		sub_mref->ref_len = mref->ref_len;
		sub_mref->ref_may_write = mref->ref_may_write;
#ifdef DIRECT_IO // shortcut solely for testing: do direct IO
		if (!mref->ref_data)
			MARS_ERR("NULL.......\n");
		sub_mref->ref_data = mref->ref_data;
#else // normal case: buffered IO
		sub_mref->ref_data = NULL;
#endif
		sub_mref->ref_cb = &sub_mref_a->cb;
		sub_mref_a->cb.cb_private = mref_a;
		sub_mref_a->cb.cb_fn = _usebuf_endio;
		sub_mref_a->cb.cb_error = 0;
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
	//MARS_INF("GOT %p %p flags = %d\n", mref, sub_mref, sub_mref->ref_flags);
	if (!mref->ref_data) {
		MARS_INF("uiiiiiiiiiii\n");
		mref->ref_data = sub_mref->ref_data;
	}
	atomic_inc(&mref->ref_count);

	return status;
}

static void usebuf_ref_put(struct usebuf_output *output, struct mref_object *mref)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mref_aspect *mref_a;
	struct usebuf_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;

	mref_a = usebuf_mref_get_aspect(output, mref);
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

	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count))
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
	struct generic_callback *cb;
	int error = -EILSEQ;

	might_sleep();

	mref_a = usebuf_mref_get_aspect(output, mref);
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

	if (mref->ref_rw != 0 && sub_mref->ref_may_write == 0) {
		MARS_ERR("mref_may_write was not set before\n");
		goto err;
	}

	atomic_inc(&mref->ref_count);

	sub_mref->ref_rw = mref->ref_rw;
	sub_mref->ref_len = mref->ref_len;
	mref_a->input = input;
	/* Optimization: when buffered IO is used and buffer is already
	 * uptodate, skip real IO operation.
	 */
	if (mref->ref_rw != 0) {
#ifdef DIRECT_WRITE
		sub_mref->ref_rw = 1;
#else // normal case
		sub_mref->ref_rw = 0;
		if (sub_mref->ref_flags & MREF_UPTODATE) {
			sub_mref->ref_rw = 1;
		}
#endif
	} else if (sub_mref->ref_flags & MREF_UPTODATE) {
#ifdef LOG
		MARS_INF("direct _usebuf_endio\n");
#endif
		_usebuf_endio(sub_mref->ref_cb);
		return;
	}
	if (mref->ref_data != sub_mref->ref_data) {
		if (sub_mref->ref_rw != 0) {
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
	cb = mref->ref_cb;
	cb->cb_error = error;
	cb->cb_fn(cb);
	return;
}

//////////////// object / aspect constructors / destructors ///////////////

static int usebuf_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct usebuf_mref_aspect *ini = (void*)_ini;
	(void)ini;
	return 0;
}

static void usebuf_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
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
	.aspect_types = usebuf_aspect_types,
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
	.default_input_types = usebuf_input_types,
	.default_output_types = usebuf_output_types,
	.brick_construct = &usebuf_brick_construct,
};
EXPORT_SYMBOL_GPL(usebuf_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_usebuf(void)
{
	printk(MARS_INFO "init_usebuf()\n");
	return usebuf_register_brick_type();
}

static void __exit exit_usebuf(void)
{
	printk(MARS_INFO "exit_usebuf()\n");
	usebuf_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS usebuf brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_usebuf);
module_exit(exit_usebuf);
