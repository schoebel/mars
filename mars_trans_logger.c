// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_trans_logger.h"

////////////////////////////////////////////////////////////////////

#define CODE_UNKNOWN     0
#define CODE_WRITE_NEW   1

#define START_MAGIC  0xa8f7e908d9177957ll
#define END_MAGIC    0x74941fb74ab5726dll

#define OVERHEAD						\
	(							\
		sizeof(START_MAGIC) +				\
		sizeof(char) * 2 +				\
		sizeof(short) +					\
		sizeof(int) +					\
		sizeof(struct log_header) +                     \
		sizeof(END_MAGIC) +				\
		sizeof(char) * 2 +				\
		sizeof(short) +					\
		sizeof(int) +					\
		sizeof(struct timespec) +			\
		0						\
	)

// TODO: make this bytesex-aware.
#define DATA_PUT(data,offset,val)				\
	do {							\
		*((typeof(val)*)(data+offset)) = val;		\
		offset += sizeof(val);				\
	} while (0)

#define DATA_GET(data,offset,val)				\
	do {							\
		val = *((typeof(val)*)(data+offset));		\
		offset += sizeof(val);				\
	} while (0)

void *log_reserve(struct trans_logger_input *input, struct log_header *l)
{
	struct mars_ref_object *mref;
	void *data;
	int total_len;
	int status;
	int offset;

	if (unlikely(input->log_mref)) {
		MARS_ERR("mref already existing\n");
		goto err;
	}

	mref = trans_logger_alloc_mars_ref(&input->hidden_output, &input->ref_object_layout);
	if (unlikely(!mref))
		goto err;

	mref->ref_pos = input->log_pos;
	total_len = l->l_len + OVERHEAD;
	mref->ref_len = total_len;
	mref->ref_may_write = WRITE;

	status = GENERIC_INPUT_CALL(input, mars_ref_get, mref);
	if (unlikely(status < 0)) {
		goto err_free;
	}
	if (unlikely(status < total_len)) {
		goto put;
	}

	input->log_mref = mref;
	data = mref->ref_data;
	offset = 0;
	DATA_PUT(data, offset, START_MAGIC);
	DATA_PUT(data, offset, (char)1); // version of format, currently there is no other one
	input->validflag_offset = offset;
	DATA_PUT(data, offset, (char)0); // valid_flag
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, total_len); // start of next header
	DATA_PUT(data, offset, l->l_stamp.tv_sec);
	DATA_PUT(data, offset, l->l_stamp.tv_nsec);
	DATA_PUT(data, offset, l->l_pos);
	input->reallen_offset = offset;
	DATA_PUT(data, offset, l->l_len);
	DATA_PUT(data, offset, l->l_code);

	input->payload_offset = offset;
	input->payload_len = l->l_len;

	return data + offset;

put:
	GENERIC_INPUT_CALL(input, mars_ref_put, mref);

err_free:
	trans_logger_free_mars_ref(mref);
err:
	return NULL;
}

bool log_finalize(struct trans_logger_input *input, int len, void (*endio)(struct generic_callback *cb), void *private)
{
	struct mars_ref_object *mref = input->log_mref;
	struct trans_logger_mars_ref_aspect *mref_a;
	struct generic_callback *cb;
	struct timespec now;
	void *data;
	int offset;
	bool ok = false;

	if (unlikely(!input->log_mref)) {
		MARS_ERR("mref is missing\n");
		goto err;
	}
	if (unlikely(len > input->payload_len)) {
		MARS_ERR("trying to write more than reserved\n");
		goto put;
	}
	mref_a = trans_logger_mars_ref_get_aspect(&input->hidden_output, mref);
	if (unlikely(!mref_a)) {
		MARS_ERR("mref_a is missing\n");
		goto put;
	}

	data = mref->ref_data;

	/* Correct the length in the header.
	 */
	offset = input->reallen_offset;
	DATA_PUT(data, offset, len);

	/* Write the trailer.
	 */
	offset = input->payload_offset + len;
	DATA_PUT(data, offset, END_MAGIC);
	DATA_PUT(data, offset, (char)1);  // valid_flag copy
	DATA_PUT(data, offset, (char)0);  // spare
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, (int)0);   // spare
	now = CURRENT_TIME;    // when the log entry was ready.
	DATA_PUT(data, offset, now.tv_sec);  
	DATA_PUT(data, offset, now.tv_nsec);

	input->log_pos += offset;

	/* This must come last. In case of incomplete
	 * or even operlapping disk transfers, this indicates
	 * the completeness / integrity of the payload at
	 * the time of starting the transfer.
	 */
	offset = input->validflag_offset;
	DATA_PUT(data, offset, (char)1);

	cb = &mref_a->cb;
	cb->cb_fn = endio;
	cb->cb_private = private;
	cb->cb_error = 0;
	cb->cb_prev = NULL;
	mref->ref_cb = cb;

	GENERIC_INPUT_CALL(input, mars_ref_io, mref, WRITE);

	ok = true;
put:
	GENERIC_INPUT_CALL(input, mars_ref_put, mref);

err:
	return ok;
}

////////////////////////////////////////////////////////////////////

static inline void q_init(struct logger_queue *q)
{
	spin_lock_init(&q->q_lock);
	INIT_LIST_HEAD(&q->q_anchor);
}

static inline void q_insert(struct logger_queue *q, struct trans_logger_mars_ref_aspect *mref_a)
{
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	list_add_tail(&mref_a->q_head, &q->q_anchor);

	traced_unlock(&q->q_lock, flags);
}

static inline struct trans_logger_mars_ref_aspect *q_fetch(struct logger_queue *q)
{
	struct trans_logger_mars_ref_aspect *mref_a = NULL;
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	if (likely(!list_empty(&q->q_anchor))) {
		mref_a = container_of(q->q_anchor.next, struct trans_logger_mars_ref_aspect, q_head);
		list_del_init(q->q_anchor.next);
	}

	traced_unlock(&q->q_lock, flags);

	return mref_a;
}

///////////////////////// own helper functions ////////////////////////


static inline int hash_fn(unsigned int base_index)
{
	// simple and stupid
	unsigned int tmp;
	tmp = base_index ^ (base_index / TRANS_HASH_MAX);
	tmp += tmp / 13;
	tmp ^= tmp / (TRANS_HASH_MAX * TRANS_HASH_MAX);
	return tmp % TRANS_HASH_MAX;
}

static struct trans_logger_mars_ref_aspect *hash_find(struct hash_anchor *table, loff_t pos, int len)
{
	unsigned int base_index = ((unsigned int)pos) >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &table[hash];
	struct list_head *tmp;
	struct trans_logger_mars_ref_aspect *res = NULL;
	struct trans_logger_mars_ref_aspect *test_a;
	struct mars_ref_object *test;
	loff_t min_pos = -1;
	int count = 0;
	unsigned int flags;

	traced_readlock(&start->hash_lock, flags);

	/* The lists are always sorted according to age.
	 * Caution: there may be duplicates in the list, some of them
	 * overlapping with the search area in many different ways.
	 * Always find the both _newest_ and _lowest_ overlapping element.
	 */
	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
#if 1
		static int max = 0;
		if (++count > max) {
			max = count;
			if (!(max % 10)) {
				MARS_INF("hash maxlen=%d hash=%d base_index=%u\n", max, hash, base_index);
			}
		}
#endif
		test_a = container_of(tmp, struct trans_logger_mars_ref_aspect, hash_head);
		test = test_a->object;
		// are the regions overlapping?
		if (pos < test->ref_pos + test->ref_len && pos + len > test->ref_pos) {
			
			if (
				// always take the newest one
				min_pos < 0 ||
				// prefer the lowest positive distance
				(test->ref_pos < min_pos && test->ref_pos >= pos)
				) {
				min_pos = test->ref_pos;
				res = test_a;
			}
		}
	}

	if (res) {
		atomic_inc(&res->hash_count);
	}

	traced_readunlock(&start->hash_lock, flags);

	return res;
}

static inline void hash_insert(struct hash_anchor *table, struct trans_logger_mars_ref_aspect *elem)
{
        unsigned int base_index = ((unsigned int)elem->object->ref_pos) >> REGION_SIZE_BITS;
        int hash = hash_fn(base_index);
        struct hash_anchor *start = &table[hash];
        unsigned int flags;

        traced_writelock(&start->hash_lock, flags);

        list_add(&elem->hash_head, &start->hash_anchor);

        traced_writeunlock(&start->hash_lock, flags);
}

static inline void hash_put(struct hash_anchor *table, struct trans_logger_mars_ref_aspect *elem)
{
	unsigned int base_index = ((unsigned int)elem->object->ref_pos) >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &table[hash];
	unsigned int flags;

	traced_writelock(&start->hash_lock, flags);

	CHECK_ATOMIC(&elem->hash_count, 1);
	if (atomic_dec_and_test(&elem->hash_count)) {
		list_del_init(&elem->hash_head);
	}

	traced_writeunlock(&start->hash_lock, flags);
}

////////////////// own brick / input / output operations //////////////////

static int trans_logger_get_info(struct trans_logger_output *output, struct mars_info *info)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int _read_ref_get(struct trans_logger_output *output, struct trans_logger_mars_ref_aspect *mref_a)
{
	struct mars_ref_object *mref = mref_a->object;
	struct trans_logger_input *input = output->brick->inputs[0];
	struct trans_logger_mars_ref_aspect *shadow_a;

	/* Look if there is a newer version on the fly, shadowing
	 * the old one.
	 * When a shadow is found, use it as buffer for the mref.
	 */
	shadow_a = hash_find(output->hash_table, mref->ref_pos, mref->ref_len);
	if (shadow_a) {
		struct mars_ref_object *shadow = shadow_a->object;
		int diff = shadow->ref_pos - mref->ref_pos;
		int restlen;
		if (diff > 0) {
			/* Although the shadow is overlapping, the
			 * region before its start is _not_ shadowed.
			 * Thus we return this (smaller) unshadowed
			 * region.
			 */
			mref->ref_len = diff;
			hash_put(output->hash_table, shadow_a);
			goto call_through;
		}
		/* Attach mref to the existing shadow.
		 */
		restlen = shadow->ref_len + diff;
		if (mref->ref_len > restlen)
			mref->ref_len = restlen;
		mref->ref_data = shadow->ref_data - diff;
		mref_a->orig_data = shadow->ref_data;
		mref->ref_flags = shadow->ref_flags;
		mref_a->is_shadow = true;
		return mref->ref_len;
	}

call_through:
	return GENERIC_INPUT_CALL(input, mars_ref_get, mref);
}

static int _write_ref_get(struct trans_logger_output *output, struct trans_logger_mars_ref_aspect *mref_a)
{
	struct mars_ref_object *mref = mref_a->object;

	// unconditionally create a new shadow buffer
	mref->ref_data = kmalloc(mref->ref_len, GFP_MARS);
	if (unlikely(!mref->ref_data)) {
		return -ENOMEM;
	}

	mref_a->orig_data = mref->ref_data;
	mref_a->output = output;
	mref_a->stamp = CURRENT_TIME;
	mref->ref_flags = 0;
	mref_a->is_shadow = true;
	return mref->ref_len;
}

static int trans_logger_ref_get(struct trans_logger_output *output, struct mars_ref_object *mref)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	unsigned int base_offset;

	mref_a = trans_logger_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		return -EINVAL;
	}

	base_offset = ((unsigned int)mref->ref_pos) & (REGION_SIZE - 1);
	if (base_offset + mref->ref_len > REGION_SIZE)
		mref->ref_len = REGION_SIZE - base_offset;

	if (mref->ref_may_write == READ) {
		return _read_ref_get(output, mref_a);
	}
	return _write_ref_get(output, mref_a);
}

static void trans_logger_ref_put(struct trans_logger_output *output, struct mars_ref_object *mref)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	struct trans_logger_input *input = output->brick->inputs[0];

	mref_a = trans_logger_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get mref_a on %p\n", mref);
		return;
	}

	if (mref_a->is_shadow) {
		hash_put(output->hash_table, mref_a);

		CHECK_ATOMIC(&mref->ref_count, 1);
		if (!atomic_dec_and_test(&mref->ref_count))
			return;

		kfree(mref_a->orig_data);
		trans_logger_free_mars_ref(mref);
		return;
	}

	GENERIC_INPUT_CALL(input, mars_ref_put, mref);
}

static void trans_logger_ref_io(struct trans_logger_output *output, struct mars_ref_object *mref, int rw)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	struct trans_logger_input *input = output->brick->inputs[0];

	mref_a = trans_logger_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get mref_a on %p\n", mref);
		return;
	}

	// is this a shadow buffer?
	if (mref_a->is_shadow) {
		if (rw == READ) {
			struct generic_callback *cb = mref->ref_cb;
			cb->cb_error = 0;
			cb->cb_fn(cb);
			trans_logger_ref_put(output, mref);
		} else {
			hash_insert(output->hash_table, mref_a);
			q_insert(&output->q_phase1, mref_a);
		}
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(rw != READ)) {
		MARS_FAT("bad operation %d without shadow\n", rw);
	}

	GENERIC_INPUT_CALL(input, mars_ref_io, mref, rw);
}

////////////////////////////// worker thread //////////////////////////////

static void phase2_endio(struct generic_callback *cb)
{
	//struct trans_logger_mars_ref_aspect *mref_a = cb->cb_private;
	//struct mars_ref_object *mref = mref_a->object;
	struct generic_callback *cb_prev = cb->cb_prev;

	if (unlikely(!cb_prev)) {
		MARS_FAT("callback chain is corrupted\n");
		return;
	}

	cb_prev->cb_error = cb->cb_error;
	cb_prev->cb_fn(cb_prev);

	//trans_logger_ref_put(mref_a->output, mref);
}

static void phase2_startio(struct trans_logger_mars_ref_aspect *mref_a)
{
	struct mars_ref_object *mref = mref_a->object;
	struct generic_callback *cb = &mref_a->cb;
	struct trans_logger_output *output = mref_a->output;
	struct trans_logger_input *input = output->brick->inputs[0];

	cb->cb_fn = phase2_endio;
	cb->cb_private = mref_a;
	cb->cb_error = 0;
	cb->cb_prev = mref->ref_cb;
	mref->ref_cb = cb;

	GENERIC_INPUT_CALL(input, mars_ref_io, mref, READ);
}

static void phase1_endio(struct generic_callback *cb)
{
	struct trans_logger_mars_ref_aspect *mref_a = cb->cb_private;
	//struct mars_ref_object *mref = mref_a->object;
	struct trans_logger_output *output = mref_a->output;
	struct generic_callback *cb_prev = &mref_a->cb;

	cb_prev->cb_error = cb->cb_error;
	cb_prev->cb_fn(cb_prev);

	q_insert(&output->q_phase2, mref_a);
}

static bool phase1_startio(struct trans_logger_mars_ref_aspect *mref_a)
{
	struct mars_ref_object *mref = mref_a->object;
	struct trans_logger_output *output = mref_a->output;
	struct trans_logger_input *input = output->brick->inputs[1];
	struct log_header l = {
		.l_stamp = mref_a->stamp,
		.l_pos = mref->ref_pos,
		.l_len = mref->ref_len,
		.l_code = CODE_WRITE_NEW,
	};
	void *data;
	bool ok;

	data = log_reserve(input, &l);
	if (unlikely(!data)) {
		return false;
	}

	memcpy(data, mref->ref_data, mref->ref_len);

	ok = log_finalize(input, mref->ref_len, phase1_endio, mref_a);
	if (unlikely(!ok)) {
		return false;
	}
	return true;
}

//////////////// object / aspect constructors / destructors ///////////////

static int trans_logger_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mars_ref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->q_head);
	atomic_set(&ini->hash_count, 1);
	return 0;
}

static void trans_logger_mars_ref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mars_ref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->hash_head);
	CHECK_HEAD_EMPTY(&ini->q_head);
}

MARS_MAKE_STATICS(trans_logger);

////////////////////// brick constructors / destructors ////////////////////

static int trans_logger_brick_construct(struct trans_logger_brick *brick)
{
	return 0;
}

static int trans_logger_output_construct(struct trans_logger_output *output)
{
	int i;
	for (i = 0; i < TRANS_HASH_MAX; i++) {
		struct hash_anchor *start = &output->hash_table[i];
		rwlock_init(&start->hash_lock);
		INIT_LIST_HEAD(&start->hash_anchor);
	}
	q_init(&output->q_phase1);
	q_init(&output->q_phase2);
	q_init(&output->q_phase3);
	return 0;
}

static int trans_logger_input_construct(struct trans_logger_input *input)
{
	struct trans_logger_output *hidden = &input->hidden_output;
	_trans_logger_output_init(input->brick, hidden, "internal");
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct trans_logger_brick_ops trans_logger_brick_ops = {
};

static struct trans_logger_output_ops trans_logger_output_ops = {
	.make_object_layout = trans_logger_make_object_layout,
	.mars_get_info = trans_logger_get_info,
	.mars_ref_get = trans_logger_ref_get,
	.mars_ref_put = trans_logger_ref_put,
	.mars_ref_io = trans_logger_ref_io,
};

const struct trans_logger_input_type trans_logger_input_type = {
	.type_name = "trans_logger_input",
	.input_size = sizeof(struct trans_logger_input),
	.input_construct = &trans_logger_input_construct,
};

static const struct trans_logger_input_type *trans_logger_input_types[] = {
	&trans_logger_input_type,
	&trans_logger_input_type,
	&trans_logger_input_type,
};

const struct trans_logger_output_type trans_logger_output_type = {
	.type_name = "trans_logger_output",
	.output_size = sizeof(struct trans_logger_output),
	.master_ops = &trans_logger_output_ops,
	.output_construct = &trans_logger_output_construct,
	.aspect_types = trans_logger_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_ALL,
	}
};

static const struct trans_logger_output_type *trans_logger_output_types[] = {
	&trans_logger_output_type,
};

const struct trans_logger_brick_type trans_logger_brick_type = {
	.type_name = "trans_logger_brick",
	.brick_size = sizeof(struct trans_logger_brick),
	.max_inputs = 3,
	.max_outputs = 1,
	.master_ops = &trans_logger_brick_ops,
	.default_input_types = trans_logger_input_types,
	.default_output_types = trans_logger_output_types,
	.brick_construct = &trans_logger_brick_construct,
};
EXPORT_SYMBOL_GPL(trans_logger_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_trans_logger(void)
{
	printk(MARS_INFO "init_trans_logger()\n");
	return trans_logger_register_brick_type();
}

static void __exit exit_trans_logger(void)
{
	printk(MARS_INFO "exit_trans_logger()\n");
	trans_logger_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS trans_logger brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_trans_logger);
module_exit(exit_trans_logger);
