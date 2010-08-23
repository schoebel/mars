// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/kthread.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_trans_logger.h"

//#define inline /**/
#define inline __attribute__((__noinline__))
#define _noinline /**/
//#define _noinline __attribute__((__noinline__))

////////////////////////////////////////////////////////////////////

#define CODE_UNKNOWN     0
#define CODE_WRITE_NEW   1
#define CODE_WRITE_OLD   2

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

static inline void log_skip(struct trans_logger_input *input) _noinline
{
	int bits;
	if (!input->info.transfer_size) {
		int status = GENERIC_INPUT_CALL(input, mars_get_info, &input->info);
		if (status < 0) {
			MARS_FAT("cannot get transfer log info (code=%d)\n", status);
		}
	}
	bits = input->info.transfer_order + PAGE_SHIFT;
	input->log_pos = ((input->log_pos >> bits) + 1) << bits;
}

static void *log_reserve(struct trans_logger_input *input, struct log_header *l)
{
	struct mars_ref_object *mref;
	void *data;
	int total_len;
	int status;
	int offset;

	//MARS_INF("reserving %d at %lld\n", l->l_len, input->log_pos);

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
	return NULL;

err_free:
	trans_logger_free_mars_ref(mref);
err:
	return NULL;
}

bool log_finalize(struct trans_logger_input *input, int len, void (*endio)(struct generic_callback *cb), struct trans_logger_mars_ref_aspect *orig_mref_a)
{
	struct mars_ref_object *mref = input->log_mref;
	struct trans_logger_mars_ref_aspect *mref_a;
	struct generic_callback *cb;
	struct timespec now;
	void *data;
	int offset;
	bool ok = false;

	CHECK_PTR(mref, err);

	input->log_mref = NULL;
	if (unlikely(len > input->payload_len)) {
		MARS_ERR("trying to write more than reserved\n");
		goto put;
	}
	mref_a = trans_logger_mars_ref_get_aspect(&input->hidden_output, mref);
	CHECK_PTR(mref_a, put);

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
	cb->cb_error = 0;
	cb->cb_prev = NULL;
	cb->cb_private = orig_mref_a;
	mref->ref_cb = cb;

	GENERIC_INPUT_CALL(input, mars_ref_io, mref, WRITE);

	ok = true;
put:
	GENERIC_INPUT_CALL(input, mars_ref_put, mref);

err:
	return ok;
}

////////////////////////////////////////////////////////////////////

static inline void q_init(struct logger_queue *q) _noinline
{
	spin_lock_init(&q->q_lock);
	atomic_set(&q->q_queued, 0);
	atomic_set(&q->q_flying, 0);
	INIT_LIST_HEAD(&q->q_anchor);
}

static inline void q_insert(struct logger_queue *q, struct trans_logger_mars_ref_aspect *mref_a) _noinline
{
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	list_add_tail(&mref_a->q_head, &q->q_anchor);
	atomic_inc(&q->q_queued);
	q->q_last_action = jiffies;

	traced_unlock(&q->q_lock, flags);
}

static inline void q_pushback(struct logger_queue *q, struct trans_logger_mars_ref_aspect *mref_a) _noinline
{
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	list_add(&mref_a->q_head, &q->q_anchor);
	atomic_inc(&q->q_queued);
	q->q_last_action = jiffies;

	traced_unlock(&q->q_lock, flags);
}

static inline struct trans_logger_mars_ref_aspect *q_fetch(struct logger_queue *q) _noinline
{
	struct trans_logger_mars_ref_aspect *mref_a = NULL;
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	if (likely(!list_empty(&q->q_anchor))) {
		struct list_head *next = q->q_anchor.next;
		list_del_init(next);
		atomic_dec(&q->q_queued);
		q->q_last_action = jiffies;
		mref_a = container_of(next, struct trans_logger_mars_ref_aspect, q_head);
	}

	traced_unlock(&q->q_lock, flags);

	return mref_a;
}

///////////////////////// own helper functions ////////////////////////


static inline int hash_fn(unsigned int base_index) _noinline
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
		atomic_inc(&res->object->ref_count);
	}

	traced_readunlock(&start->hash_lock, flags);

	return res;
}

static inline void hash_insert(struct hash_anchor *table, struct trans_logger_mars_ref_aspect *elem_a, atomic_t *cnt) _noinline
{
        unsigned int base_index = ((unsigned int)elem_a->object->ref_pos) >> REGION_SIZE_BITS;
        int hash = hash_fn(base_index);
        struct hash_anchor *start = &table[hash];
        unsigned int flags;

        traced_writelock(&start->hash_lock, flags);

#if 1
	CHECK_HEAD_EMPTY(&elem_a->hash_head);
#endif

        list_add(&elem_a->hash_head, &start->hash_anchor);
	atomic_inc(&elem_a->object->ref_count); // paired with hash_put()
	atomic_inc(cnt); // only for statistics

        traced_writeunlock(&start->hash_lock, flags);
}

static inline bool hash_put(struct hash_anchor *table, struct trans_logger_mars_ref_aspect *elem_a, atomic_t *cnt) _noinline
{
	struct mars_ref_object *elem = elem_a->object;
	unsigned int base_index = ((unsigned int)elem->ref_pos) >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &table[hash];
	unsigned int flags;
	bool res;

	traced_writelock(&start->hash_lock, flags);

	CHECK_ATOMIC(&elem->ref_count, 1);
	res = atomic_dec_and_test(&elem->ref_count);

	if (res) {
		list_del_init(&elem_a->hash_head);
		atomic_dec(cnt);
	}

	traced_writeunlock(&start->hash_lock, flags);
	return res;
}

////////////////// own brick / input / output operations //////////////////

static int trans_logger_get_info(struct trans_logger_output *output, struct mars_info *info)
{
	struct trans_logger_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static void trans_logger_ref_put(struct trans_logger_output *output, struct mars_ref_object *mref);

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
			 * Thus we must return that (smaller) unshadowed
			 * region.
			 */
			mref->ref_len = diff;
			trans_logger_ref_put(output, shadow);
			goto call_through;
		}
		/* Attach mref to the existing shadow ("slave shadow").
		 */
		restlen = shadow->ref_len + diff;
		if (mref->ref_len > restlen)
			mref->ref_len = restlen;
		mref->ref_data = shadow->ref_data - diff;
		mref->ref_flags = shadow->ref_flags;
		mref_a->shadow_ref = shadow_a;
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

	mref_a->output = output;
	mref_a->stamp = CURRENT_TIME;
	mref->ref_flags = MARS_REF_UPTODATE;
	mref_a->shadow_ref = mref_a; // cyclic self-reference
	atomic_set(&mref->ref_count, 1);
	return mref->ref_len;
}

static int trans_logger_ref_get(struct trans_logger_output *output, struct mars_ref_object *mref)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	unsigned int base_offset;

	CHECK_PTR(output, err);

	mref_a = trans_logger_mars_ref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	base_offset = ((unsigned int)mref->ref_pos) & (REGION_SIZE - 1);
	if (base_offset + mref->ref_len > REGION_SIZE)
		mref->ref_len = REGION_SIZE - base_offset;

	if (mref->ref_may_write == READ) {
		return _read_ref_get(output, mref_a);
	}
	return _write_ref_get(output, mref_a);

err:
	return -EINVAL;
}

static void trans_logger_ref_put(struct trans_logger_output *output, struct mars_ref_object *mref)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	struct trans_logger_mars_ref_aspect *shadow_a;
	struct trans_logger_input *input;

	CHECK_PTR(output, err);

	mref_a = trans_logger_mars_ref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	// are we a shadow?
	shadow_a = mref_a->shadow_ref;
	if (shadow_a) {
		if (shadow_a != mref_a) { // we are a slave shadow
			//MARS_INF("slave\n");
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			if (atomic_dec_and_test(&mref->ref_count)) {
				trans_logger_free_mars_ref(mref);
			}
		}
		// now put the master shadow
		if (hash_put(output->hash_table, shadow_a, &output->hash_count)) {
			struct mars_ref_object *shadow = shadow_a->object;
			kfree(shadow->ref_data);
			//MARS_INF("hm?\n");
			trans_logger_free_mars_ref(shadow);
		}
		return;
	}

	input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mars_ref_put, mref);
err: ;
}

static void trans_logger_ref_io(struct trans_logger_output *output, struct mars_ref_object *mref, int rw)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	struct trans_logger_input *input = output->brick->inputs[0];

	CHECK_ATOMIC(&mref->ref_count, 1);

	mref_a = trans_logger_mars_ref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);

	// is this a shadow buffer?
	if (mref_a->shadow_ref) {
		mref->ref_rw = rw;
		if (rw == READ) {
			// nothing to do: directly signal success.
			struct generic_callback *cb = mref->ref_cb;
			cb->cb_error = 0;
			mref->ref_flags |= MARS_REF_UPTODATE;
			cb->cb_fn(cb);
			// no touch of ref_count necessary
		} else {
#if 1
			if (unlikely(mref_a->shadow_ref != mref_a)) {
				MARS_ERR("something is wrong: %p != %p\n", mref_a->shadow_ref, mref_a);
			}
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			CHECK_HEAD_EMPTY(&mref_a->q_head);
			if (unlikely(mref->ref_flags & (MARS_REF_READING | MARS_REF_WRITING))) {
				MARS_ERR("bad flags %d\n", mref->ref_flags);
			}
#endif
			mref->ref_flags |= MARS_REF_WRITING;
			//MARS_INF("hashing %d at %lld\n", mref->ref_len, mref->ref_pos);
			hash_insert(output->hash_table, mref_a, &output->hash_count);
			q_insert(&output->q_phase1, mref_a);
			wake_up(&output->event);
		}
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(rw != READ)) {
		MARS_FAT("bad operation %d without shadow\n", rw);
	}

	GENERIC_INPUT_CALL(input, mars_ref_io, mref, rw);
err: ;
}

////////////////////////////// worker thread //////////////////////////////

/********************************************************************* 
 * Phase 1: write transaction log entry for the original write request.
 */

static void phase1_endio(struct generic_callback *cb)
{
	struct trans_logger_mars_ref_aspect *orig_mref_a;
	struct mars_ref_object *orig_mref;
	struct trans_logger_output *output;
	struct generic_callback *orig_cb;

	CHECK_PTR(cb, err);

	orig_mref_a = cb->cb_private;
	CHECK_PTR(orig_mref_a, err);

	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase1.q_flying);

	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);

	orig_cb = orig_mref->ref_cb;
	CHECK_PTR(orig_cb, err);

	// signal completion to the upper layer, as early as possible
	orig_cb->cb_error = cb->cb_error;
	if (likely(cb->cb_error >= 0)) {
		orig_mref->ref_flags &= ~MARS_REF_WRITING;
		orig_mref->ref_flags |= MARS_REF_UPTODATE;
	}

	CHECK_PTR(orig_cb->cb_fn, err);
	orig_cb->cb_fn(orig_cb);

	// queue up for the next phase
	q_insert(&output->q_phase2, orig_mref_a);
	wake_up(&output->event);
err: ;
}

static bool phase1_startio(struct trans_logger_mars_ref_aspect *orig_mref_a)
{
	struct mars_ref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_input *input;
	void *data;
	bool ok;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	CHECK_PTR(orig_mref->ref_cb, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	input = output->brick->inputs[1];
	CHECK_PTR(input, err);

	{
		struct log_header l = {
			.l_stamp = orig_mref_a->stamp,
			.l_pos = orig_mref->ref_pos,
			.l_len = orig_mref->ref_len,
			.l_code = CODE_WRITE_NEW,
		};
		data = log_reserve(input, &l);
	}
	if (unlikely(!data)) {
		goto err;
	}

	memcpy(data, orig_mref->ref_data, orig_mref->ref_len);

	ok = log_finalize(input, orig_mref->ref_len, phase1_endio, orig_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	atomic_inc(&output->q_phase1.q_flying);
	return true;

err:
	return false;
}

/********************************************************************* 
 * Phase 2: read original version of data.
 * This happens _after_ phase 1, deliberately.
 * We are explicitly dealing with old and new versions.
 * The new version is hashed in memory all the time (such that parallel
 * READs will see them), so we hvae plenty of time for getting the
 * old version from disk somewhen later, e.g. when IO contention is low.
 */

static void phase2_endio(struct generic_callback *cb)
{
	struct trans_logger_mars_ref_aspect *sub_mref_a;
	struct trans_logger_output *output;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase2.q_flying);

	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	// queue up for the next phase
	if (output->brick->log_reads) {
		q_insert(&output->q_phase3, sub_mref_a);
	} else {
		q_insert(&output->q_phase4, sub_mref_a);
	}
	wake_up(&output->event);
err: ;
}

static bool phase2_startio(struct trans_logger_mars_ref_aspect *orig_mref_a)
{
	struct mars_ref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_input *input;
	struct mars_ref_object *sub_mref;
	struct trans_logger_mars_ref_aspect *sub_mref_a;
	struct generic_callback *cb;
	loff_t pos;
	int len;
	int status;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	input = output->brick->inputs[0];
	CHECK_PTR(input, err);

	pos = orig_mref->ref_pos;
	len = orig_mref->ref_len;

	/* allocate internal sub_mref for further work
	 */
	while (len > 0) {
		sub_mref = trans_logger_alloc_mars_ref(&input->hidden_output, &input->ref_object_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot alloc sub_mref\n");
			goto err;
		}

		sub_mref->ref_pos = pos;
		sub_mref->ref_len = len;
		sub_mref->ref_may_write = WRITE;

		sub_mref_a = trans_logger_mars_ref_get_aspect(&input->hidden_output, sub_mref);
		CHECK_PTR(sub_mref_a, err);
		sub_mref_a->stamp = orig_mref_a->stamp;
		sub_mref_a->orig_mref_a = orig_mref_a;
		sub_mref_a->output = output;

		status = GENERIC_INPUT_CALL(input, mars_ref_get, sub_mref);
		if (unlikely(status <= 0)) {
			MARS_FAT("cannot get sub_ref\n");
			goto err;
		}
		pos += status;
		len -= status;

		/* Get a reference count for each sub_mref.
		 * Paired with trans_logger_ref_put() in phase4_endio().
		 */
		CHECK_ATOMIC(&orig_mref->ref_count, 1);
		atomic_inc(&orig_mref->ref_count);

		cb = &sub_mref_a->cb;
		cb->cb_fn = phase2_endio;
		cb->cb_private = sub_mref_a;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		sub_mref->ref_cb = cb;


		atomic_inc(&output->q_phase2.q_flying);
		GENERIC_INPUT_CALL(input, mars_ref_io, sub_mref, READ);
	}

	/* Finally, put the original reference (i.e. in essence
	 * _replace_ the original reference by the sub_mref counts
	 * from above).
	 */
	trans_logger_ref_put(output, orig_mref);
	return true;

err:
	return false;
}

/********************************************************************* 
 * Phase 3: log the old disk version.
 */

static void phase3_endio(struct generic_callback *cb)
{
	struct trans_logger_mars_ref_aspect *sub_mref_a;
	struct trans_logger_output *output;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase3.q_flying);

	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	// queue up for the next phase
	q_insert(&output->q_phase4, sub_mref_a);
	wake_up(&output->event);
err: ;
}

static bool phase3_startio(struct trans_logger_mars_ref_aspect *sub_mref_a)
{
	struct mars_ref_object *sub_mref;
	struct trans_logger_output *output;
	struct trans_logger_input *input;
	void *data;
	bool ok;

	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	input = output->brick->inputs[1];
	CHECK_PTR(input, err);

	{
		struct log_header l = {
			.l_stamp = sub_mref_a->stamp,
			.l_pos = sub_mref->ref_pos,
			.l_len = sub_mref->ref_len,
			.l_code = CODE_WRITE_OLD,
		};
		data = log_reserve(input, &l);
	}

	if (unlikely(!data)) {
		goto err;
	}

	memcpy(data, sub_mref->ref_data, sub_mref->ref_len);

	ok = log_finalize(input, sub_mref->ref_len, phase3_endio, sub_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	atomic_inc(&output->q_phase3.q_flying);
	return true;

err:
	return false;
}

/********************************************************************* 
 * Phase 4: overwrite old disk version with new version.
 */

static void phase4_endio(struct generic_callback *cb)
{
	struct trans_logger_mars_ref_aspect *sub_mref_a;
	struct trans_logger_mars_ref_aspect *orig_mref_a;
	struct mars_ref_object *orig_mref;
	struct trans_logger_output *output;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase4.q_flying);
	orig_mref_a = sub_mref_a->orig_mref_a;
	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);

	if (unlikely(cb->cb_error < 0)) {
		MARS_ERR("IO error %d\n", cb->cb_error);
		goto put;
	}

	// TODO: signal final completion.

put:
	//MARS_INF("put ORIGREF.\n");
	CHECK_ATOMIC(&orig_mref->ref_count, 1);
	trans_logger_ref_put(orig_mref_a->output, orig_mref);
err: ;
}

static bool phase4_startio(struct trans_logger_mars_ref_aspect *sub_mref_a)
{
	struct mars_ref_object *sub_mref;
	struct generic_callback *cb;
	struct trans_logger_output *output;
	struct trans_logger_input *input;
	struct trans_logger_mars_ref_aspect *orig_mref_a;
	struct mars_ref_object *orig_mref;

	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	input = output->brick->inputs[0];
	CHECK_PTR(input, err);
	orig_mref_a = sub_mref_a->orig_mref_a;
	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);

	memcpy(sub_mref->ref_data, orig_mref->ref_data, sub_mref->ref_len);

	cb = &sub_mref_a->cb;
	cb->cb_fn = phase4_endio;
	cb->cb_private = sub_mref_a;
	cb->cb_error = 0;
	cb->cb_prev = NULL;
	sub_mref->ref_cb = cb;

	atomic_inc(&output->q_phase4.q_flying);
	GENERIC_INPUT_CALL(input, mars_ref_io, sub_mref, WRITE);

	//MARS_INF("put SUBREF.\n");
	GENERIC_INPUT_CALL(input, mars_ref_put, sub_mref);
	return true;

err:
	return false;
}

/********************************************************************* 
 * The logger thread.
 * There is only a single instance, dealing with all requests in parallel.
 * So there is less need for locking (concept stolen from microkernel
 * architectures).
 */

static int run_queue(struct logger_queue *q, bool (*startio)(struct trans_logger_mars_ref_aspect *sub_mref_a), int max)
{
	struct trans_logger_mars_ref_aspect *mref_a;
	bool ok;

	while (max-- > 0) {
		if (q->q_max_flying > 0 && atomic_read(&q->q_flying) >= q->q_max_flying)
			break;

		mref_a = q_fetch(q);
		if (!mref_a)
			return -1;
	
		ok = startio(mref_a);
		if (unlikely(!ok)) {
			q_pushback(q, mref_a);
			return 1;
		}
	}
	return 0;
}

static int trans_logger_thread(void *data)
{
	struct trans_logger_output *output = data;
	struct trans_logger_brick *brick;
	struct trans_logger_input *input;
	long wait_jiffies = HZ;
	unsigned long last_jiffies = 0;
	bool check_q = true;

	brick = output->brick;
	input = brick->inputs[1];
	MARS_INF("logger has started.\n");

	while (!kthread_should_stop()) {
		int status;
		if (wait_jiffies < 5)
			wait_jiffies = 5; // prohibit high CPU load

		wait_event_interruptible_timeout(
			output->event,
			!list_empty(&output->q_phase1.q_anchor) ||
			(check_q &&
			 (!list_empty(&output->q_phase2.q_anchor) ||
			  !list_empty(&output->q_phase3.q_anchor) ||
			  !list_empty(&output->q_phase4.q_anchor))),
			wait_jiffies);
#if 1
		if (jiffies - last_jiffies >= HZ * 10) {
			last_jiffies = jiffies;
			MARS_INF("LOGGER: hash_count=%d phase1=%d/%d phase2=%d/%d phase3=%d/%d phase4=%d/%d\n", atomic_read(&output->hash_count), atomic_read(&output->q_phase1.q_queued), atomic_read(&output->q_phase1.q_flying), atomic_read(&output->q_phase2.q_queued), atomic_read(&output->q_phase2.q_flying), atomic_read(&output->q_phase3.q_queued), atomic_read(&output->q_phase3.q_flying), atomic_read(&output->q_phase4.q_queued), atomic_read(&output->q_phase4.q_flying));
		}
#endif

		status = run_queue(&output->q_phase1, phase1_startio, 1000);
		if (unlikely(status > 0)) {
			(void)run_queue(&output->q_phase3, phase3_startio, 1);
			log_skip(input);
			check_q = true;
			continue;
		}

		/* Run higher phases only when IO contention is "low".
		 */
		if (brick->max_queue <= 0 ||
		   atomic_read(&output->q_phase2.q_queued) + atomic_read(&output->q_phase4.q_queued) < brick->max_queue) {
			long rest = brick->allow_reads_after - (jiffies - output->q_phase1.q_last_action);
			if (brick->allow_reads_after > 0 && rest > 0) {
				wait_jiffies = rest;
				check_q = false;
				continue;
			}
			if (brick->limit_congest > 0 && atomic_read(&output->q_phase1.q_flying) >= brick->limit_congest) {
				wait_jiffies = HZ / 100;
				check_q = false;
				continue;
			}
			   
		}
		wait_jiffies = HZ;
		check_q = true;

		status = run_queue(&output->q_phase2, phase2_startio, 8);
		status = run_queue(&output->q_phase3, phase3_startio, 16);
		if (unlikely(status > 0)) {
			log_skip(input);
			continue;
		}
		status = run_queue(&output->q_phase4, phase4_startio, 8);
	}
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int trans_logger_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mars_ref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->q_head);
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
	static int index = 0;
	int i;
	for (i = 0; i < TRANS_HASH_MAX; i++) {
		struct hash_anchor *start = &output->hash_table[i];
		rwlock_init(&start->hash_lock);
		INIT_LIST_HEAD(&start->hash_anchor);
	}
	atomic_set(&output->hash_count, 0);
	init_waitqueue_head(&output->event);
	q_init(&output->q_phase1);
	q_init(&output->q_phase2);
	q_init(&output->q_phase3);
	q_init(&output->q_phase4);
	output->thread = kthread_create(trans_logger_thread, output, "mars_logger%d", index++);
	if (IS_ERR(output->thread)) {
		int error = PTR_ERR(output->thread);
		MARS_ERR("cannot create thread, status=%d\n", error);
		return error;
	}
	wake_up_process(output->thread);
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
