// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Usebuf brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

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

static inline void _copy_mref(struct mars_ref_object *b, struct mars_ref_object *a)
{
	b->ref_pos = a->ref_pos;
	b->ref_len = a->ref_len;
	b->ref_may_write = a->ref_may_write;
	// ref_data is NOT copied!
	b->ref_flags = a->ref_flags;
	b->ref_rw = a->ref_rw;
}

static void _usebuf_endio(struct generic_callback *cb)
{
	struct usebuf_mars_ref_aspect *mref_a = cb->cb_private;
	struct mars_ref_object *mref;
	struct mars_ref_object *sub_mref;

	CHECK_PTR(mref_a, done);
	mref = mref_a->object;
	CHECK_PTR(mref, done);
	CHECK_PTR(mref->ref_cb, done);
	sub_mref = mref_a->sub_mref;
	CHECK_PTR(sub_mref, done);

	_copy_mref(mref, sub_mref);

	if (mref->ref_data != sub_mref->ref_data) {
		if (mref->ref_rw == 0) {
			memcpy(mref->ref_data, sub_mref->ref_data, mref->ref_len);
		}
	}

#if 1
	mref->ref_cb->cb_error = cb->cb_error;
	mref->ref_cb->cb_fn(mref->ref_cb);
#endif

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

	usebuf_free_mars_ref(mref);
done:;
}

static int usebuf_ref_get(struct usebuf_output *output, struct mars_ref_object *mref)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mars_ref_aspect *mref_a;
	struct mars_ref_object *sub_mref;
	int status = 0;

	mref_a = usebuf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return -EILSEQ;
	}

	sub_mref = mref_a->sub_mref;
	if (!sub_mref) {
		sub_mref = usebuf_alloc_mars_ref(output, &output->mref_object_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot get sub_mref\n");
			return -ENOMEM;
		}

		mref_a->sub_mref = sub_mref;
		_copy_mref(sub_mref, mref);
#if 1 // shortcut: do direct IO
		if (!mref->ref_data)
			MARS_ERR("NULL.......\n");
		sub_mref->ref_data = mref->ref_data;
#else // normal case: buffered IO
		sub_mref->ref_data = NULL;
#endif
		sub_mref->ref_cb = &mref_a->cb;
		mref_a->cb.cb_private = mref_a;
		mref_a->cb.cb_fn = _usebuf_endio;
	}
		
	status = GENERIC_INPUT_CALL(input, mars_ref_get, sub_mref);
	if (status < 0) {
		return status;
	}
	_copy_mref(mref, sub_mref);
	if (!mref->ref_data) {
		MARS_INF("uiiiiiiiiiii\n");
		mref->ref_data = sub_mref->ref_data;
	}
	if ((sub_mref->ref_flags & MARS_REF_UPTODATE) && mref->ref_data != sub_mref->ref_data) {
		memcpy(mref->ref_data, sub_mref->ref_data, mref->ref_len);
	}

	atomic_inc(&mref->ref_count);

	return status;
}

static void usebuf_ref_put(struct usebuf_output *output, struct mars_ref_object *mref)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mars_ref_aspect *mref_a;
	struct mars_ref_object *sub_mref;

	mref_a = usebuf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return;
	}

	sub_mref = mref_a->sub_mref;
	if (!sub_mref) {
		MARS_FAT("sub_mref is missing\n");
		return;
	}

	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count))
		return;

	GENERIC_INPUT_CALL(input, mars_ref_put, sub_mref);
	usebuf_free_mars_ref(mref);
}

static void usebuf_ref_io(struct usebuf_output *output, struct mars_ref_object *mref, int rw)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct usebuf_mars_ref_aspect *mref_a;
	struct mars_ref_object *sub_mref;
	struct generic_callback *cb;
	int error = -EILSEQ;

	mref_a = usebuf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		goto err;
	}

	sub_mref = mref_a->sub_mref;
	if (!sub_mref) {
		MARS_FAT("sub_mref is missing\n");
		goto err;
	}

	if (mref->ref_data != sub_mref->ref_data) {
		if (rw != 0) {
			memcpy(sub_mref->ref_data, mref->ref_data, mref->ref_len);
		}
	}

	atomic_inc(&mref->ref_count);

	/* Optimization: when buffered IO is used and buffer is already
	 * uptodate, skip real IO operation.
	 */
	if (rw != 0 || !(sub_mref->ref_flags & MARS_REF_UPTODATE)) {
		GENERIC_INPUT_CALL(input, mars_ref_io, sub_mref, rw);
		_copy_mref(mref, sub_mref);
	} else {
		_usebuf_endio(sub_mref->ref_cb);
	}

	return;

err:
	cb = mref->ref_cb;
	cb->cb_error = error;
	cb->cb_fn(cb);
	return;
}

//////////////// object / aspect constructors / destructors ///////////////

static int usebuf_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct usebuf_mars_ref_aspect *ini = (void*)_ini;
	(void)ini;
	return 0;
}

static void usebuf_mars_ref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct usebuf_mars_ref_aspect *ini = (void*)_ini;
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
	.make_object_layout = usebuf_make_object_layout,
	.mars_get_info = usebuf_get_info,
	.mars_ref_get = usebuf_ref_get,
	.mars_ref_put = usebuf_ref_put,
	.mars_ref_io = usebuf_ref_io,
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
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_ALL,
	}
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
