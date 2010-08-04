// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Usebuf brick.
 * translates from unbuffered IO to buffered IO (mars_{get,put}_buf)
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

	if (rw == READ) {
		memcpy(bio_data, buf_data, len);
	} else {
		memcpy(buf_data, bio_data, len);
	}

	kunmap_atomic(bio_base, KM_USER0);
}

static void _usebuf_origmbuf_endio(struct usebuf_output *output, struct mars_buf_object *origmbuf)
{
	struct usebuf_mars_buf_aspect *origmbuf_a;

	origmbuf_a = usebuf_mars_buf_get_aspect(output, origmbuf);
	if (unlikely(!origmbuf_a)) {
		MARS_FAT("cannot get origmbuf_a from origmbuf %p\n", origmbuf);
		goto out;
	}

	MARS_DBG("origmbuf=%p origmbuf_count=%d error=%d\n", origmbuf, atomic_read(&origmbuf_a->mbuf_count), origmbuf->cb_error);

	if (!atomic_dec_and_test(&origmbuf_a->mbuf_count)) {
		goto out;
	}

	MARS_DBG("DONE error=%d\n", origmbuf->cb_error);
	origmbuf->cb_buf_endio(origmbuf);

out:
	return;
}

static void _usebuf_mbuf_endio(struct mars_buf_object *mbuf)
{
	struct usebuf_output *output;
	struct usebuf_mars_buf_aspect *mbuf_a;
	struct mars_buf_object *origmbuf;
	struct usebuf_mars_buf_aspect *origmbuf_a;
	int status;

	output = mbuf->cb_private;
	if (unlikely(!output)) {
		MARS_FAT("bad argument output\n");
		goto out_fatal;
	}
	mbuf_a = usebuf_mars_buf_get_aspect(output, mbuf);
	if (unlikely(!mbuf_a)) {
		MARS_FAT("cannot get aspect\n");
		goto out_fatal;
	}
	origmbuf = mbuf_a->origmbuf;
	if (unlikely(!origmbuf)) {
		MARS_FAT("cannot get origmbuf\n");
		goto out_fatal;
	}
	MARS_DBG("origmbuf=%p\n", origmbuf);
	status = -EINVAL;
	origmbuf_a = usebuf_mars_buf_get_aspect(output, origmbuf);
	if (unlikely(!origmbuf_a)) {
		MARS_ERR("cannot get origmbuf_a\n");
		goto out_err;
	}

	
	// check if we have an initial read => now start the final write
	if (mbuf->buf_may_write != READ && mbuf->buf_rw == READ && mbuf->cb_error >= 0) {
		struct usebuf_input *input = output->brick->inputs[0];

		status = -EIO;
		if (unlikely(!(mbuf->buf_flags & MARS_BUF_UPTODATE))) {
			MARS_ERR("not UPTODATE after initial read\n");
			goto out_err;
		}

		_usebuf_copy(mbuf_a, WRITE);

		// grab extra reference
		atomic_inc(&origmbuf_a->mbuf_count);

		GENERIC_INPUT_CALL(input, mars_buf_io, mbuf, WRITE);
	} else {
		// finalize the read or final write
		if (likely(!mbuf->cb_error)) {
			struct bio *bio = origmbuf->orig_bio;
			int direction;
			status = -EINVAL;
			if (unlikely(!bio)) {
				MARS_ERR("bad bio setup on origmbuf %p", origmbuf);
				goto out_err;
			}
			direction = bio->bi_rw & 1;
			if (direction == READ) {
				_usebuf_copy(mbuf_a, READ);
			}
		}
	}

#if 1
	if (atomic_read(&origmbuf_a->mbuf_count) <= 0)
		MARS_ERR("bad refcount mbuf_count\n");

	if (atomic_read(&mbuf->buf_count) <= 0)
		MARS_ERR("bad refcount buf_count\n");
#endif

	status = mbuf->cb_error;

out_err:	
	if (status < 0) {
		origmbuf->cb_error = status;
		MARS_ERR("error %d\n", status);
	}
	_usebuf_origmbuf_endio(output, origmbuf);

out_fatal: // no chance to call callback; this will result in mem leak :(
	;
}

////////////////// own brick / input / output operations //////////////////

static void usebuf_buf_io(struct usebuf_output *output, struct mars_buf_object *origmbuf, int rw)
{
	struct usebuf_input *input = output->brick->inputs[0];
	struct bio *bio = origmbuf->orig_bio;
	struct bio_vec *bvec;
	struct usebuf_mars_buf_aspect *origmbuf_a;
	loff_t start_pos;
	int start_len;
	int status;
	int i;

	MARS_DBG("START origmbuf=%p\n", origmbuf);

	status = -EINVAL;
	if (unlikely(!bio)) {
		MARS_ERR("cannot get bio\n");
		goto done;
	}
	origmbuf_a = usebuf_mars_buf_get_aspect(output, origmbuf);
	if (unlikely(!origmbuf_a)) {
		MARS_ERR("cannot get origmbuf_a\n");
		goto done;
	}
	if (unlikely(atomic_read(&origmbuf_a->mbuf_count) != 0)) {
		MARS_ERR("bad preset of mbuf_count %d\n", atomic_read(&origmbuf_a->mbuf_count));
	}

	// initial refcount: prevent intermediate drops
	atomic_set(&origmbuf_a->mbuf_count, 1);
	origmbuf->cb_error = 0;

	start_pos = ((loff_t)bio->bi_sector) << 9; // TODO: make dynamic
	start_len = bio->bi_size;

	bio_for_each_segment(bvec, bio, i) {
		int this_len = bvec->bv_len;
		int my_offset = 0;

		while (this_len > 0) {
			struct mars_buf_object *mbuf;
			struct usebuf_mars_buf_aspect *mbuf_a;
			int my_len;
			int my_rw;

			mbuf = usebuf_alloc_mars_buf(output, &output->buf_object_layout);
			status = -ENOMEM;
			if (unlikely(!mbuf)) {
				MARS_ERR("cannot alloc buffer, status=%d\n", status);
				goto done_drop;
			}

			mbuf->buf_pos = start_pos;
			mbuf->buf_len = this_len;
			mbuf->buf_may_write = rw;
			mbuf->cb_private = output;
			
			status = GENERIC_INPUT_CALL(input, mars_buf_get, mbuf);
			if (unlikely(status < 0)) {
				MARS_ERR("cannot get buffer, status=%d\n", status);
				goto done_drop;
			}
			my_len = status;
			MARS_DBG("origmbuf=%p got mbuf=%p pos=%lld len=%d mode=%d flags=%d status=%d\n", origmbuf, mbuf, start_pos, this_len, mbuf->buf_may_write, mbuf->buf_flags, status);

			status = -ENOMEM;
			mbuf_a = usebuf_mars_buf_get_aspect(output, mbuf);
			if (unlikely(!mbuf_a)) {
				MARS_ERR("cannot get my own mbuf aspect\n");
				goto put;
			}
			
			mbuf_a->origmbuf = origmbuf;
			mbuf_a->bvec = bvec;
			mbuf_a->bvec_offset = bvec->bv_offset + my_offset;
			mbuf_a->bvec_len = my_len;

			if ((mbuf->buf_flags & MARS_BUF_UPTODATE) && rw == READ) {
				// cache hit: immediately signal success
				_usebuf_copy(mbuf_a, READ);
				status = 0;
				goto put;
			}
			
			mbuf->cb_buf_endio = _usebuf_mbuf_endio;

			// grab extra references
			atomic_inc(&origmbuf_a->mbuf_count);
			
			my_rw = rw;
			if (!(my_rw == READ)) { 
				if (mbuf->buf_flags & MARS_BUF_UPTODATE) {
					// buffer uptodate: start writing.
					_usebuf_copy(mbuf_a, WRITE);
				} else {
					// first start initial read, to get the whole buffer UPTODATE
					MARS_DBG("AHA\n");
					my_rw = READ;
				}
			}

			GENERIC_INPUT_CALL(input, mars_buf_io, mbuf, my_rw);
			status = mbuf->cb_error;
			MARS_DBG("buf_io (status=%d)\n", status);

		put:
			GENERIC_INPUT_CALL(input, mars_buf_put, mbuf);
			
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
	if (status < 0)
		origmbuf->cb_error = status;
	_usebuf_origmbuf_endio(output, origmbuf);

done:
	MARS_DBG("status=%d\n", status);
	return;
}

static int usebuf_get_info(struct usebuf_output *output, struct mars_info *info)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int usebuf_buf_get(struct usebuf_output *output, struct mars_buf_object *mbuf)
{
	struct usebuf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_buf_get, mbuf);
}

static void usebuf_buf_put(struct usebuf_output *output, struct mars_buf_object *mbuf)
{
	struct usebuf_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mars_buf_put, mbuf);
}

//////////////// object / aspect constructors / destructors ///////////////

static int usebuf_mars_buf_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct usebuf_mars_buf_aspect *ini = (void*)_ini;
	ini->origmbuf = NULL;
	ini->bvec = NULL;
	atomic_set(&ini->mbuf_count, 0);
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
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct usebuf_brick_ops usebuf_brick_ops = {
};

static struct usebuf_output_ops usebuf_output_ops = {
	.make_object_layout = usebuf_make_object_layout,
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
