// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Usebuf brick.
 * translates from unbuffered IO (mars_io) to buffered IO (mars_{get,put}_buf)
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_usebuf.h"

///////////////////////// own helper functions ////////////////////////

/* currently we have copy semantics :(
 */
static void _usebuf_copy(struct usebuf_mars_buf_aspect *mbuf_a, int rw)
{
	void *buf_data = mbuf_a->object->buf_data;
	void *bio_base = kmap_atomic(mbuf_a->bvec->bv_page, KM_USER0);
	void *bio_data = bio_base + mbuf_a->bvec_offset;
	int len = mbuf_a->bvec_len;

#if 1
	if (rw == READ) {
		memcpy(bio_data, buf_data, len);
		//memset(bio_data, 0, len);
	} else {
		memcpy(buf_data, bio_data, len);
	}
#endif
	kunmap_atomic(bio_base, KM_USER0);
}

static int _usebuf_mio_endio(struct usebuf_output *output, struct mars_io_object *mio, int error)
{
	struct usebuf_mars_io_aspect *mio_a;
	int status = -EFAULT;

	mio_a = usebuf_mars_io_get_aspect(output, mio);
	if (unlikely(!mio_a)) {
		MARS_ERR("cannot get mio_a\n");
		goto out;
	}

	MARS_DBG("mio=%p mio_count=%d error=%d\n", mio, atomic_read(&mio_a->mio_count), error);
	// this may race, but we don't care about the exact error code
	if (error)
		mio_a->mio_error = error;

	status = 0;
	if (!atomic_dec_and_test(&mio_a->mio_count)) {
		goto out;
	}

	if (likely(!mio_a->mio_error)) {
		struct bio *bio = mio->orig_bio;
		if (unlikely(!bio)) {
			MARS_ERR("bad bio setup on mio %p", mio);
		} else {
			bio->bi_size = 0;
		}
	}

	status = mio->mars_endio(mio, mio_a->mio_error);

out:
	return status;
}

static int _usebuf_mbuf_endio(struct mars_buf_object *mbuf)
{
	struct usebuf_output *output;
	struct usebuf_mars_buf_aspect *mbuf_a;
	struct mars_io_object *mio;
	int status = -EFAULT;

	output = mbuf->cb_private;
	if (unlikely(!output)) {
		MARS_ERR("bad argument output\n");
		goto out;
	}
	
	mbuf_a = usebuf_mars_buf_get_aspect(output, mbuf);
	if (unlikely(!mbuf_a)) {
		MARS_ERR("cannot get aspect\n");
		goto out;
	}
	
	mio = mbuf_a->mio;
	if (unlikely(!mio)) {
		MARS_ERR("cannot get mio\n");
		goto out;
	}

	if (likely(!mbuf->cb_error)) {
		struct bio *bio = mio->orig_bio;
		if (unlikely(!bio)) {
			MARS_ERR("bad bio setup on mio %p", mio);
		} else if (bio->bi_rw == READ) {
			_usebuf_copy(mbuf_a, READ);
		}
	}

	status = _usebuf_mio_endio(output, mio, mbuf->cb_error);
	
out:
	return status;
}

////////////////// own brick / input / output operations //////////////////

static int usebuf_io(struct usebuf_output *output, struct mars_io_object *mio)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct bio *bio = mio->orig_bio;
	struct bio_vec *bvec;
	struct usebuf_mars_io_aspect *mio_a = usebuf_mars_io_get_aspect(output, mio);
	loff_t start_pos;
	int start_len;
	int status;
	int i;


	status = -EINVAL;
	if (unlikely(!bio)) {
		MARS_ERR("cannot get bio\n");
		goto done;
	}
	if (unlikely(!mio_a)) {
		MARS_ERR("cannot get mio_a\n");
		goto done;
	}
	if (unlikely(atomic_read(&mio_a->mio_count) != 0)) {
		MARS_ERR("bad preset of mio_count %d\n", atomic_read(&mio_a->mio_count));
	}
	// initial refcount: prevent intermediate drops
	atomic_set(&mio_a->mio_count, 1);
	mio_a->mio_error = 0;

	start_pos = ((loff_t)bio->bi_sector) << 9; // TODO: make dynamic
	start_len = bio->bi_size;

	bio_for_each_segment(bvec, bio, i) {
		int this_len = bvec->bv_len;
		int my_offset = 0;

		while (this_len > 0) {
			struct mars_buf_object *mbuf = NULL;
			struct usebuf_mars_buf_aspect *mbuf_a;
			int my_len;
			int ignore;
			
			status = GENERIC_INPUT_CALL(input, mars_buf_get, &mbuf, (struct mars_alloc_helper*)&output->buf_helper, start_pos, this_len);
			if (status < 0) {
				MARS_ERR("cannot get buffer, status=%d\n", status);
				goto done_drop;
			}
			my_len = status;

			status = -ENOMEM;
			if (!mbuf)
				goto done_drop;

			mbuf_a = usebuf_mars_buf_get_aspect(output, mbuf);
			if (!mbuf_a) {
				MARS_ERR("cannot get mbuf aspect\n");
				goto put;
			}
			
			mbuf_a->mio = mio;
			mbuf_a->bvec = bvec;
			mbuf_a->bvec_offset = bvec->bv_offset + my_offset;
			mbuf_a->bvec_len = my_len;

			if ((mbuf->buf_flags & MARS_BUF_UPTODATE) && bio->bi_rw == READ) {
				// cache hit: immediately signal success
				_usebuf_copy(mbuf_a, READ);
				status = 0;
				goto put;
			}
			
			status = -ENOMEM;
			mbuf->cb_private = output;
			mbuf->cb_rw = bio->bi_rw;
			mbuf->cb_buf_endio = _usebuf_mbuf_endio;

			atomic_inc(&mio_a->mio_count);
			
			if (!(bio->bi_rw == READ)) {
				_usebuf_copy(mbuf_a, WRITE);
			}

			status = GENERIC_OUTPUT_CALL(output, mars_buf_io, mbuf);
			MARS_DBG("buf_io (status=%d)\n", status);
			if (unlikely(status < 0)) {
				atomic_dec(&mio_a->mio_count);
			}

		put:
			ignore = GENERIC_OUTPUT_CALL(output, mars_buf_put, mbuf);
			MARS_DBG("buf_put (status=%d)\n", ignore);
			
			if (unlikely(status < 0))
				break;

			start_len -= my_len;
			start_pos += my_len;
			this_len -= my_len;
			my_offset += my_len;
		}
		if (unlikely(this_len != 0)) {
			MARS_ERR("bad internal length %d\n", this_len);
		}
	}

	if (unlikely(start_len != 0 && !status)) {
		MARS_ERR("length mismatch %d\n", start_len);
	}

done_drop:
	// drop initial refcount
	if (!status) {
		(void)_usebuf_mio_endio(output, mio, 0);
	}

done:
	MARS_DBG("usebuf_io() status=%d\n", status);
	return status;

}

static int usebuf_get_info(struct usebuf_output *output, struct mars_info *info)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int usebuf_buf_get(struct usebuf_output *output, struct mars_buf_object **mbuf, struct mars_alloc_helper *h, loff_t pos, int len)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_get, mbuf, h, pos, len);
}

static int usebuf_buf_put(struct usebuf_output *output, struct mars_buf_object *mbuf)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_put, mbuf);
}

static int usebuf_buf_io(struct usebuf_output *output, struct mars_buf_object *mbuf)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_io, mbuf);
}

//////////////// object / aspect constructors / destructors ///////////////

static int usebuf_mars_io_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct usebuf_mars_io_aspect *ini = (void*)_ini;
	atomic_set(&ini->mio_count, 0);
	return 0;
}

static int usebuf_mars_buf_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct usebuf_mars_buf_aspect *ini = (void*)_ini;
	ini->mio = NULL;
	ini->bvec = NULL;
	return 0;
}

MARS_MAKE_STATICS(usebuf);

////////////////////// brick constructors / destructors ////////////////////

static int usebuf_brick_construct(struct usebuf_brick *brick)
{
	return 0;
}

static int usebuf_output_construct(struct usebuf_output *output)
{
	usebuf_init_helper(&output->buf_helper);
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct usebuf_brick_ops usebuf_brick_ops = {
};

static struct usebuf_output_ops usebuf_output_ops = {
	.make_object_layout = usebuf_make_object_layout,
	.mars_io = usebuf_io,
	.mars_get_info = usebuf_get_info,
	.mars_buf_get = usebuf_buf_get,
	.mars_buf_put = usebuf_buf_put,
	.mars_buf_io = usebuf_buf_io,
};

static const struct usebuf_input_type usebuf_input_type = {
	.type_name = "usebuf_input",
	.input_size = sizeof(struct usebuf_input),
};

static const struct usebuf_input_type *usebuf_input_types[] = {
	&usebuf_input_type,
};

static const struct usebuf_output_type usebuf_output_type = {
	.type_name = "usebuf_output",
	.output_size = sizeof(struct usebuf_output),
	.master_ops = &usebuf_output_ops,
	.output_construct = &usebuf_output_construct,
	.aspect_types = usebuf_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_IO] = LAYOUT_NONE,
		[BRICK_OBJ_MARS_BUF] = LAYOUT_ALL,
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
