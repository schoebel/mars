// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

//#define USE_MEMCPY

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/kthread.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_trans_logger.h"

#if 1
#define inline __attribute__((__noinline__))
#endif

////////////////////////////////////////////////////////////////////

static inline bool q_cmp(struct pairing_heap_mref *_a, struct pairing_heap_mref *_b)
{
	struct trans_logger_mref_aspect *mref_a = container_of(_a, struct trans_logger_mref_aspect, ph);
	struct trans_logger_mref_aspect *mref_b = container_of(_b, struct trans_logger_mref_aspect, ph);
	struct mref_object *a = mref_a->object;
	struct mref_object *b = mref_b->object;
	return a->ref_pos < b->ref_pos;
}

_PAIRING_HEAP_FUNCTIONS(static,mref,q_cmp);

static inline void q_init(struct logger_queue *q)
{
	INIT_LIST_HEAD(&q->q_anchor);
	q->heap_low = NULL;
	q->heap_high = NULL;
	spin_lock_init(&q->q_lock);
	atomic_set(&q->q_queued, 0);
	atomic_set(&q->q_flying, 0);
}

static
bool q_is_ready(struct logger_queue *q, bool do_drain)
{
	int queued = atomic_read(&q->q_queued);
	int flying;
	bool res = false;

	if (queued <= 0)
		goto always_done;

	res = true;
	if (do_drain || queued > q->q_max_queued)
		goto done;

	if (q->q_max_jiffies > 0 &&
	   (long long)jiffies - q->q_last_action >= q->q_max_jiffies)
		goto done;

	res = false;
	goto always_done;

done:
	/* Limit the number of flying requests (parallelism)
	 */
	flying = atomic_read(&q->q_flying);
	if (q->q_max_flying > 0 && flying >= q->q_max_flying)
		res = false;

always_done:
	return res;
}

static inline void q_insert(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	if (q->q_ordering) {
		struct pairing_heap_mref **use = &q->heap_high;
		if (mref_a->object->ref_pos <= q->heap_border)
			use = &q->heap_low;
		ph_insert_mref(use, &mref_a->ph);
	} else {
		list_add_tail(&mref_a->q_head, &q->q_anchor);
	}
	atomic_inc(&q->q_queued);
	q->q_last_action = jiffies;

	traced_unlock(&q->q_lock, flags);
}

static inline void q_pushback(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	unsigned long flags;

	if (q->q_ordering) {
		q_insert(q, mref_a);
		return;
	}

	traced_lock(&q->q_lock, flags);

	list_add(&mref_a->q_head, &q->q_anchor);
	atomic_inc(&q->q_queued);
	q->q_last_action = jiffies;

	traced_unlock(&q->q_lock, flags);
}

static inline struct trans_logger_mref_aspect *q_fetch(struct logger_queue *q)
{
	struct trans_logger_mref_aspect *mref_a = NULL;
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	if (q->q_ordering) {
#if 0
		struct pairing_heap_mref **minpos = &q->heap_high;
		if (!*minpos) {
			*minpos = q->heap_low;
			q->heap_low = NULL;
			q->heap_border = 0;
		}
		if (*minpos) {
			mref_a = container_of(*minpos, struct trans_logger_mref_aspect, ph);
			q->heap_border = mref_a->object->ref_pos;
			ph_delete_min_mref(minpos);
			atomic_dec(&q->q_queued);
			//q->q_last_action = jiffies;
		}
#else
		if (!q->heap_high) {
			q->heap_high = q->heap_low;
			q->heap_low = NULL;
		}
		if (q->heap_high) {
			mref_a = container_of(q->heap_high, struct trans_logger_mref_aspect, ph);
			q->heap_border = mref_a->object->ref_pos;
			ph_delete_min_mref(&q->heap_high);
			atomic_dec(&q->q_queued);
			//q->q_last_action = jiffies;
		}
#endif
	} else if (!list_empty(&q->q_anchor)) {
		struct list_head *next = q->q_anchor.next;
		list_del_init(next);
		atomic_dec(&q->q_queued);
		//q->q_last_action = jiffies;
		mref_a = container_of(next, struct trans_logger_mref_aspect, q_head);
	}

	traced_unlock(&q->q_lock, flags);

	return mref_a;
}

///////////////////////// own helper functions ////////////////////////


static inline int hash_fn(loff_t base_index)
{
	// simple and stupid
	loff_t tmp;
	tmp = base_index ^ (base_index / TRANS_HASH_MAX);
	return ((unsigned)tmp) % TRANS_HASH_MAX;
}

static struct trans_logger_mref_aspect *hash_find(struct trans_logger_output *output, loff_t pos, int len)
{
	loff_t base_index = pos >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &output->hash_table[hash];
	struct list_head *tmp;
	struct trans_logger_mref_aspect *res = NULL;
	struct trans_logger_mref_aspect *test_a;
	struct mref_object *test;
	loff_t min_pos = -1;
	int count = 0;
	unsigned int flags;

	traced_readlock(&start->hash_lock, flags);

	/* The lists are always sorted according to age.
	 * Caution: there may be duplicates in the list, some of them
	 * overlapping with the search area in many different ways.
	 * Always find both the _newest_ and _lowest_ overlapping element.
	 */
	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
#if 1
		static int max = 0;
		if (++count > max) {
			max = count;
			if (!(max % 10)) {
				MARS_INF("hash maxlen=%d hash=%d base_index=%lld\n", max, hash, base_index);
			}
		}
#endif
		test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
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
		atomic_inc(&output->inner_balance_count);
	}

	traced_readunlock(&start->hash_lock, flags);

	return res;
}

static
void hash_insert(struct trans_logger_output *output, struct trans_logger_mref_aspect *elem_a)
{
        loff_t base_index = elem_a->object->ref_pos >> REGION_SIZE_BITS;
        int hash = hash_fn(base_index);
        struct hash_anchor *start = &output->hash_table[hash];
        unsigned int flags;

#if 1
	CHECK_HEAD_EMPTY(&elem_a->hash_head);
#endif

	atomic_inc(&elem_a->object->ref_count); // must be paired with hash_put()
	// only for statistics:
	atomic_inc(&output->inner_balance_count);
	atomic_inc(&output->hash_count);

        traced_writelock(&start->hash_lock, flags);

        list_add(&elem_a->hash_head, &start->hash_anchor);

        traced_writeunlock(&start->hash_lock, flags);
}

static inline bool hash_put(struct trans_logger_output *output, struct trans_logger_mref_aspect *elem_a)
{
	struct mref_object *elem = elem_a->object;
	loff_t base_index = elem->ref_pos >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &output->hash_table[hash];
	unsigned int flags;
	bool res;

	traced_writelock(&start->hash_lock, flags);

	CHECK_ATOMIC(&elem->ref_count, 1);
	res = atomic_dec_and_test(&elem->ref_count);
	atomic_dec(&output->inner_balance_count);

	if (res) {
		list_del_init(&elem_a->hash_head);
		atomic_dec(&output->hash_count);
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

static void _trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref);

static int _read_ref_get(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	struct trans_logger_input *input = output->brick->inputs[0];
	struct trans_logger_mref_aspect *shadow_a;

	/* Look if there is a newer version on the fly, shadowing
	 * the old one.
	 * When a shadow is found, use it as buffer for the mref.
	 */
	shadow_a = hash_find(output, mref->ref_pos, mref->ref_len);
	if (shadow_a) {
		struct mref_object *shadow = shadow_a->object;
		int diff = shadow->ref_pos - mref->ref_pos;
		int restlen;
#if 1 // xxx
		if (shadow_a == mref_a) {
			MARS_ERR("oops %p == %p\n", shadow_a, mref_a);
		}
#endif
		if (diff > 0) {
			/* Although the shadow is overlapping, the
			 * region before its start is _not_ shadowed.
			 * Thus we must return that (smaller) unshadowed
			 * region.
			 */
			mref->ref_len = diff;
			_trans_logger_ref_put(output, shadow);
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
		atomic_inc(&mref->ref_count);
		atomic_inc(&output->inner_balance_count);
		atomic_inc(&output->sshadow_count);
#ifdef USE_MEMCPY
		if (mref_a->orig_data) {
			memcpy(mref_a->orig_data, mref->ref_data, mref->ref_len);
		}
#endif
		return mref->ref_len;
	}

call_through:
	return GENERIC_INPUT_CALL(input, mref_get, mref);
}

static int _write_ref_get(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;

	// unconditionally create a new master shadow buffer
	mref->ref_data = kmalloc(mref->ref_len, GFP_MARS);
	if (unlikely(!mref->ref_data)) {
		return -ENOMEM;
	}
	atomic_inc(&output->mshadow_count);
#ifdef USE_MEMCPY
	if (mref_a->orig_data) {
		memcpy(mref->ref_data, mref_a->orig_data, mref->ref_len);
	}
#endif
	mref_a->output = output;
	mref->ref_flags = MREF_UPTODATE;
	mref_a->shadow_ref = mref_a; // cyclic self-reference => indicates master shadow
	atomic_inc(&mref->ref_count);
	atomic_inc(&output->inner_balance_count);
	get_lamport(&mref_a->stamp);
	return mref->ref_len;
}

static int trans_logger_ref_get(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;
	loff_t base_offset;

	CHECK_PTR(output, err);

	atomic_inc(&output->outer_balance_count);

	if (atomic_read(&mref->ref_count) > 0) { // setup already performed
		MARS_DBG("aha %d\n", atomic_read(&mref->ref_count));
		atomic_inc(&mref->ref_count);
		return mref->ref_len;
	}

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	mref_a->orig_data = mref->ref_data;

	base_offset = mref->ref_pos & (loff_t)(REGION_SIZE - 1);
	if (base_offset + mref->ref_len > REGION_SIZE)
		mref->ref_len = REGION_SIZE - base_offset;

	if (mref->ref_may_write == READ) {
		return _read_ref_get(output, mref_a);
	}

	/* FIXME: THIS IS PROVISIONARY (use event instead)
	 */
	while (unlikely(!output->brick->power.led_on)) {
		msleep(HZ);
	}

	return _write_ref_get(output, mref_a);

err:
	return -EINVAL;
}

static
void __trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_input *input;

restart:
	CHECK_ATOMIC(&mref->ref_count, 1);

	CHECK_PTR(output, err);

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	// are we a shadow?
	shadow_a = mref_a->shadow_ref;
	if (shadow_a) {
		bool finished;
		if (mref_a->is_hashed) {
			finished = hash_put(output, mref_a);
		} else {
			finished = atomic_dec_and_test(&mref->ref_count);
			atomic_dec(&output->inner_balance_count);
		}
		if (!finished) {
			return;
		}
		if (shadow_a != mref_a) { // we are a slave shadow
			//MARS_INF("slave\n");
			atomic_dec(&output->sshadow_count);
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			trans_logger_free_mref(mref);
			// now put the master shadow
			mref = shadow_a->object;
			goto restart;
		}
		// we are a master shadow
		CHECK_PTR(mref->ref_data, err);
		kfree(mref->ref_data);
		mref->ref_data = NULL;
		atomic_dec(&output->mshadow_count);
		trans_logger_free_mref(mref);
		return;
	}

	input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mref_put, mref);
	return;
err:
	MARS_FAT("oops\n");
}

static void trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	atomic_dec(&output->outer_balance_count);
	_trans_logger_ref_put(output, mref);
}

static void _trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	//atomic_dec(&output->inner_balance_count);
	__trans_logger_ref_put(output, mref);
}

static void _trans_logger_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_output *output;
	struct mref_object *mref;
	struct generic_callback *prev_cb;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	if (unlikely(&mref_a->cb != cb)) {
		MARS_FAT("bad callback -- hanging up\n");
		goto err;
	}

	output = mref_a->output;
	CHECK_PTR(output, err);

	prev_cb = cb->cb_prev;
	CHECK_PTR(prev_cb, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);

	mref->ref_cb = prev_cb;
	prev_cb->cb_fn(prev_cb);

	if (atomic_dec_and_test(&output->fly_count)) {
		wake_up_interruptible(&output->event);
	}

err: ;
}

static void trans_logger_ref_io(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_input *input = output->brick->inputs[0];
	struct generic_callback *cb;

	CHECK_ATOMIC(&mref->ref_count, 1);

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);

	// is this a shadow buffer?
	if (mref_a->shadow_ref) {
		if (mref->ref_rw == READ) {
			// nothing to do: directly signal success.
			struct generic_callback *cb = mref->ref_cb;
#ifdef USE_MEMCPY
			if (mref_a->orig_data) {
				memcpy(mref_a->orig_data, mref->ref_data, mref->ref_len);
			}
#endif
			cb->cb_error = 0;
			mref->ref_flags |= MREF_UPTODATE;
			cb->cb_fn(cb);
			// no touch of ref_count necessary
		} else { // WRITE
#if 1
			if (unlikely(mref_a->shadow_ref != mref_a)) {
				MARS_ERR("something is wrong: %p != %p\n", mref_a->shadow_ref, mref_a);
			}
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			CHECK_HEAD_EMPTY(&mref_a->q_head);
			if (unlikely(mref->ref_flags & (MREF_READING | MREF_WRITING))) {
				MARS_ERR("bad flags %d\n", mref->ref_flags);
			}
#endif
			mref->ref_flags |= MREF_WRITING;
			if (!mref_a->is_hashed) {
				mref_a->is_hashed = true;
				MARS_DBG("hashing %d at %lld\n", mref->ref_len, mref->ref_pos);
				hash_insert(output, mref_a);
			}
			q_insert(&output->q_phase1, mref_a);
			wake_up_interruptible(&output->event);
			//MARS_INF("PING %d\n", atomic_read(&output->q_phase1.q_queued));
		}
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(mref->ref_rw != READ)) {
		MARS_FAT("bad operation %d without shadow\n", mref->ref_rw);
	}

	atomic_inc(&output->fly_count);

	mref_a->output = output;
	cb = &mref_a->cb;
	cb->cb_fn = _trans_logger_endio;
	cb->cb_private = mref_a;
	cb->cb_error = 0;
	cb->cb_prev = mref->ref_cb;
	mref->ref_cb = cb;

	GENERIC_INPUT_CALL(input, mref_io, mref);
err: ;
}

////////////////////////////// worker thread //////////////////////////////

/********************************************************************* 
 * Phase 1: write transaction log entry for the original write request.
 */

static void phase1_endio(void *private, int error)
{
	struct trans_logger_mref_aspect *orig_mref_a;
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct generic_callback *orig_cb;

	orig_mref_a = private;
	CHECK_PTR(orig_mref_a, err);

	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase1.q_flying);

	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);

	orig_cb = orig_mref->ref_cb;
	CHECK_PTR(orig_cb, err);

	// signal completion to the upper layer, as early as possible
	if (error < 0)
		orig_cb->cb_error = error;
	if (likely(orig_cb->cb_error >= 0)) {
		orig_mref->ref_flags &= ~MREF_WRITING;
		orig_mref->ref_flags |= MREF_UPTODATE;
	}

	CHECK_PTR(orig_cb->cb_fn, err);
	orig_cb->cb_fn(orig_cb);

	// queue up for the next phase
	q_insert(&output->q_phase2, orig_mref_a);
	wake_up_interruptible(&output->event);
err: ;
}

static bool phase1_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	void *data;
	bool ok;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	CHECK_PTR(orig_mref->ref_cb, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	{
		struct log_header l = {
			.l_stamp = orig_mref_a->stamp,
			.l_pos = orig_mref->ref_pos,
			.l_len = orig_mref->ref_len,
			.l_code = CODE_WRITE_NEW,
		};
		data = log_reserve(&brick->logst, &l);
	}
	if (unlikely(!data)) {
		goto err;
	}

	memcpy(data, orig_mref->ref_data, orig_mref->ref_len);

	ok = log_finalize(&brick->logst, orig_mref->ref_len, phase1_endio, orig_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	atomic_inc(&output->q_phase1.q_flying);

	/* NYI Provisionary! this is wrong!
	 * All requests must be sorted according to pos,
	 * only the smallest _uncommitted_ write-back
	 * should be counting!
	 */
	brick->current_pos = brick->logst.log_pos;
	wake_up_interruptible(&output->event);
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
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_output *output;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase2.q_flying);

	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto done;
	}

	// queue up for the next phase
	if (output->brick->log_reads) {
		q_insert(&output->q_phase3, sub_mref_a);
	} else {
		q_insert(&output->q_phase4, sub_mref_a);
	}
done:
	wake_up_interruptible(&output->event);
err: ;
}

static bool phase2_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct mref_object *sub_mref;
	struct trans_logger_mref_aspect *sub_mref_a;
	struct generic_callback *cb;
	loff_t pos;
	int len;
	int status;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	pos = orig_mref->ref_pos;
	len = orig_mref->ref_len;

	/* allocate internal sub_mref for further work
	 */
	while (len > 0) {
		sub_mref = trans_logger_alloc_mref((void*)brick->logst.output, &brick->logst.ref_object_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot alloc sub_mref\n");
			goto err;
		}

		sub_mref->ref_pos = pos;
		sub_mref->ref_len = len;
		sub_mref->ref_may_write = WRITE;

		sub_mref_a = trans_logger_mref_get_aspect((struct trans_logger_output*)brick->logst.output, sub_mref);
		CHECK_PTR(sub_mref_a, err);
		sub_mref_a->stamp = orig_mref_a->stamp;
		sub_mref_a->orig_mref_a = orig_mref_a;
		sub_mref_a->output = output;

		status = GENERIC_INPUT_CALL(brick->logst.input, mref_get, sub_mref);
		if (unlikely(status < 0)) {
			MARS_FAT("cannot get sub_ref, status = %d\n", status);
			goto err;
		}
		atomic_inc(&output->sub_balance_count);
		pos += sub_mref->ref_len;
		len -= sub_mref->ref_len;

		/* Get a reference count for each sub_mref.
		 * Paired with trans_logger_ref_put() in phase4_endio().
		 */
		CHECK_ATOMIC(&orig_mref->ref_count, 1);
		atomic_inc(&orig_mref->ref_count);
		atomic_inc(&output->inner_balance_count);

		cb = &sub_mref_a->cb;
		cb->cb_fn = phase2_endio;
		cb->cb_private = sub_mref_a;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		sub_mref->ref_cb = cb;
		sub_mref->ref_rw = 0;
#if 1
		sub_mref->ref_prio = MARS_PRIO_LOW;
#endif

		atomic_inc(&output->q_phase2.q_flying);
		if (output->brick->log_reads) {
			GENERIC_INPUT_CALL(brick->logst.input, mref_io, sub_mref);
		} else { // shortcut
			phase2_endio(cb);
		}
	}

	/* Finally, put the original reference (i.e. in essence
	 * _replace_ the original reference by the sub_mref counts
	 * from above).
	 */
	_trans_logger_ref_put(output, orig_mref);
	wake_up_interruptible(&output->event);
	return true;

err:
	return false;
}

/********************************************************************* 
 * Phase 3: log the old disk version.
 */

static void phase3_endio(void *private, int error)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_output *output;

	sub_mref_a = private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	atomic_dec(&output->q_phase3.q_flying);

	if (unlikely(error < 0)) {
		MARS_FAT("IO error %d\n", error);
		goto err; // FIXME: this leads to hanging requests. do better.
	}

	// queue up for the next phase
	q_insert(&output->q_phase4, sub_mref_a);
	wake_up_interruptible(&output->event);
err: ;
}

static bool phase3_startio(struct trans_logger_mref_aspect *sub_mref_a)
{
	struct mref_object *sub_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	void *data;
	bool ok;

	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	{
		struct log_header l = {
			.l_stamp = sub_mref_a->stamp,
			.l_pos = sub_mref->ref_pos,
			.l_len = sub_mref->ref_len,
			.l_code = CODE_WRITE_OLD,
		};
		data = log_reserve(&brick->logst, &l);
	}

	if (unlikely(!data)) {
		goto err;
	}

	memcpy(data, sub_mref->ref_data, sub_mref->ref_len);

	ok = log_finalize(&brick->logst, sub_mref->ref_len, phase3_endio, sub_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	atomic_inc(&output->q_phase3.q_flying);
	wake_up_interruptible(&output->event);
	return true;

err:
	return false;
}

/********************************************************************* 
 * Phase 4: overwrite old disk version with new version.
 */

static void phase4_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_mref_aspect *orig_mref_a;
	struct mref_object *orig_mref;
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

	// TODO: save final completion status into the status input

put:
	//MARS_INF("put ORIGREF.\n");
	CHECK_ATOMIC(&orig_mref->ref_count, 1);
	_trans_logger_ref_put(orig_mref_a->output, orig_mref);
	wake_up_interruptible(&output->event);
err: ;
}

static bool phase4_startio(struct trans_logger_mref_aspect *sub_mref_a)
{
	struct mref_object *sub_mref = NULL;
	struct generic_callback *cb;
	struct trans_logger_output *output;
	struct trans_logger_input *input;
	struct trans_logger_mref_aspect *orig_mref_a;
	struct mref_object *orig_mref;

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
	sub_mref->ref_rw = 1;

	atomic_inc(&output->q_phase4.q_flying);
	GENERIC_INPUT_CALL(input, mref_io, sub_mref);

	//MARS_INF("put SUBREF.\n");
	GENERIC_INPUT_CALL(input, mref_put, sub_mref);
	atomic_dec(&output->sub_balance_count);
	wake_up_interruptible(&output->event);
	return true;

err:
	MARS_ERR("cannot start phase 4 IO %p\n", sub_mref);
	return false;
}

/********************************************************************* 
 * The logger thread.
 * There is only a single instance, dealing with all requests in parallel.
 */

static int run_queue(struct trans_logger_output *output, struct logger_queue *q, bool (*startio)(struct trans_logger_mref_aspect *sub_mref_a), int max)
{
	struct trans_logger_mref_aspect *mref_a;
	bool found = false;
	bool ok;
	int res;

	while (max-- > 0) {
		mref_a = q_fetch(q);
		res = -1;
		if (!mref_a)
			goto done;

		found = true;
		
		ok = startio(mref_a);
		if (unlikely(!ok)) {
			q_pushback(q, mref_a);
			res = 1;
			goto done;
		}
	}
	res = 0;

done:
	if (found) {
		wake_up_interruptible(&output->event);
	}
	return res;
}

static inline int _congested(struct trans_logger_output *output)
{
	return atomic_read(&output->q_phase1.q_queued)
		|| atomic_read(&output->q_phase1.q_flying)
		|| atomic_read(&output->q_phase2.q_queued)
		|| atomic_read(&output->q_phase2.q_flying)
		|| atomic_read(&output->q_phase3.q_queued)
		|| atomic_read(&output->q_phase3.q_flying)
		|| atomic_read(&output->q_phase4.q_queued)
		|| atomic_read(&output->q_phase4.q_flying);
}

#define DO_DRAIN(output)						\
	(/*(output)->old_fly_count + */ atomic_read(&(output)->fly_count) <= 0)

static
void trans_logger_log(struct trans_logger_output *output)
{
	struct trans_logger_brick *brick = output->brick;
	int wait_timeout = HZ;
	long long last_jiffies = jiffies;
	long long log_jiffies = jiffies;

	while (!kthread_should_stop() || _congested(output)) {
		int status;
		bool prev_queued = atomic_read(&output->q_phase1.q_queued) > 0;

		output->old_fly_count = atomic_read(&output->fly_count);
#if 1
		wait_timeout = 4;
#endif
		wait_event_interruptible_timeout(
			output->event,
			q_is_ready(&output->q_phase1, DO_DRAIN(output)) ||
			q_is_ready(&output->q_phase2, DO_DRAIN(output)) ||
			q_is_ready(&output->q_phase3, DO_DRAIN(output)) ||
			q_is_ready(&output->q_phase4, DO_DRAIN(output)) ||
			(kthread_should_stop() && !_congested(output)),
			wait_timeout);

		//MARS_INF("AHA %d\n", atomic_read(&output->q_phase1.q_queued));
#if 1
		if (((long long)jiffies) - last_jiffies >= HZ * 10 && brick->power.button) {
			last_jiffies = jiffies;
			MARS_INF("LOGGER: mshadow=%d sshadow=%d hash_count=%d balance=%d/%d/%d fly=%d phase1=%d+%d phase2=%d+%d phase3=%d+%d phase4=%d+%d\n", atomic_read(&output->mshadow_count), atomic_read(&output->sshadow_count), atomic_read(&output->hash_count), atomic_read(&output->sub_balance_count), atomic_read(&output->inner_balance_count), atomic_read(&output->outer_balance_count), atomic_read(&output->fly_count), atomic_read(&output->q_phase1.q_queued), atomic_read(&output->q_phase1.q_flying), atomic_read(&output->q_phase2.q_queued), atomic_read(&output->q_phase2.q_flying), atomic_read(&output->q_phase3.q_queued), atomic_read(&output->q_phase3.q_flying), atomic_read(&output->q_phase4.q_queued), atomic_read(&output->q_phase4.q_flying));
		}
#endif

		wait_timeout = 8 * HZ;
		if (atomic_read(&output->q_phase1.q_queued) > 0) {
			wait_timeout = brick->flush_delay + 1;
			if (!prev_queued) {
				log_jiffies = jiffies;
			}
		}

		status = run_queue(output, &output->q_phase1, phase1_startio, output->q_phase1.q_batchlen);
#if 0
		if (unlikely(status > 0)) {
			MARS_ERR("oops\n");
			//log_flush(&brick->logst);
			msleep(10);
			continue;
		}
#endif

		/* Strategy / performance:
		 * run higher phases only when IO contention is "low".
		 */
		if (q_is_ready(&output->q_phase2, DO_DRAIN(output))) {
			(void)run_queue(output, &output->q_phase2, phase2_startio, output->q_phase2.q_batchlen);
		}

		if (q_is_ready(&output->q_phase3, DO_DRAIN(output))) {
			status = run_queue(output, &output->q_phase3, phase3_startio, output->q_phase3.q_batchlen);
#if 0
			if (unlikely(status > 0)) {
				MARS_ERR("oops\n");
				//log_flush(&brick->logst);
				msleep(10);
				continue;
			}
#endif
		}
		
		if (atomic_read(&output->q_phase1.q_queued) <= 0 &&
		   (!brick->flush_delay || ((long long)jiffies) - log_jiffies >= brick->flush_delay)) {
			log_flush(&brick->logst, PAGE_SIZE);
		}

		if (q_is_ready(&output->q_phase4, DO_DRAIN(output))) {
			(void)run_queue(output, &output->q_phase4, phase4_startio, output->q_phase4.q_batchlen);
		}
	}
}

static
void trans_logger_replay(struct trans_logger_output *output)
{
	struct trans_logger_brick *brick = output->brick;

	MARS_INF("NYI simulating replay at %lld....\n", brick->current_pos);
	msleep(15 * 1000);
	MARS_INF("NYI simulated replay finished at %lld....\n", brick->end_pos);
	brick->current_pos = brick->end_pos;
	mars_trigger();

	while (!kthread_should_stop()) {
		msleep(1000);
	}
}

static
int trans_logger_thread(void *data)
{
	struct trans_logger_output *output = data;
	struct trans_logger_brick *brick = output->brick;

	MARS_INF("........... logger has started.\n");

	brick->current_pos = brick->start_pos;
	mars_power_led_on((void*)brick, true);

	brick->logst.align_size = brick->align_size;
	brick->logst.chunk_size = brick->chunk_size;

	if (brick->do_replay) {
		trans_logger_replay(output);
	} else {
		trans_logger_log(output);
	}

	MARS_INF("........... logger has stopped.\n");
	mars_power_led_off((void*)brick, true);
	return 0;
}

static
int trans_logger_switch(struct trans_logger_brick *brick)
{
	static int index = 0;
	struct trans_logger_output *output = brick->outputs[0];

	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		if (!output->thread) {
			output->thread = kthread_create(trans_logger_thread, output, "mars_logger%d", index++);
			if (IS_ERR(output->thread)) {
				int error = PTR_ERR(output->thread);
				MARS_ERR("cannot create thread, status=%d\n", error);
				output->thread = NULL;
				return error;
			}
			get_task_struct(output->thread);
			wake_up_process(output->thread);
		}
	} else {
		mars_power_led_on((void*)brick, false);
		if (output->thread) {
			kthread_stop(output->thread);
			put_task_struct(output->thread);
			output->thread = NULL;
		}
	}
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int trans_logger_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->q_head);
	return 0;
}

static void trans_logger_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->hash_head);
	CHECK_HEAD_EMPTY(&ini->q_head);
}

MARS_MAKE_STATICS(trans_logger);

////////////////////// brick constructors / destructors ////////////////////

static int trans_logger_brick_construct(struct trans_logger_brick *brick)
{
	init_logst(&brick->logst, (void*)brick->inputs[1], (void*)brick->outputs[0]);
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
	atomic_set(&output->hash_count, 0);
	init_waitqueue_head(&output->event);
	q_init(&output->q_phase1);
	q_init(&output->q_phase2);
	q_init(&output->q_phase3);
	q_init(&output->q_phase4);
	return 0;
}

static int trans_logger_input_construct(struct trans_logger_input *input)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct trans_logger_brick_ops trans_logger_brick_ops = {
	.brick_switch = trans_logger_switch,
};

static struct trans_logger_output_ops trans_logger_output_ops = {
	.make_object_layout = trans_logger_make_object_layout,
	.mars_get_info = trans_logger_get_info,
	.mref_get = trans_logger_ref_get,
	.mref_put = trans_logger_ref_put,
	.mref_io = trans_logger_ref_io,
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
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
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
	MARS_INF("init_trans_logger()\n");
	return trans_logger_register_brick_type();
}

static void __exit exit_trans_logger(void)
{
	MARS_INF("exit_trans_logger()\n");
	trans_logger_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS trans_logger brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_trans_logger);
module_exit(exit_trans_logger);
