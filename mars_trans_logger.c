// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING // here means: display full statistics

// variants
#define KEEP_UNIQUE
//#define WB_COPY
#define LATER

// changing this is dangerous for data integrity! use only for testing!
#define USE_MEMCPY
#define APPLY_DATA

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/kthread.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_trans_logger.h"

#if 1
#define inline noinline
#endif

static inline
int lh_cmp(loff_t *a, loff_t *b)
{
	if (*a < *b)
		return -1;
	if (*a > *b)
		return 1;
	return 0;
}

static inline
int tr_cmp(struct pairing_heap_logger *_a, struct pairing_heap_logger *_b)
{
	struct logger_head *a = container_of(_a, struct logger_head, ph);
	struct logger_head *b = container_of(_b, struct logger_head, ph);
	return lh_cmp(a->lh_pos, b->lh_pos);
}

_PAIRING_HEAP_FUNCTIONS(static,logger,tr_cmp);

static inline
loff_t *lh_get(struct logger_head *th)
{
	return th->lh_pos;
}

QUEUE_FUNCTIONS(logger,struct logger_head,lh_head,lh_get,lh_cmp,logger);

////////////////////////// logger queue handling ////////////////////////

static inline
void qq_init(struct logger_queue *q, struct trans_logger_brick *brick)
{
	q_logger_init(q);
	q->q_event = &brick->event;
	q->q_contention = &brick->fly_count;
	q->q_brick = brick;
}

static inline
void qq_inc_flying(struct logger_queue *q)
{
	q_logger_inc_flying(q);
}

static inline
void qq_dec_flying(struct logger_queue *q)
{
	q_logger_dec_flying(q);
}

static noinline
bool qq_is_ready(struct logger_queue *q)
{
	return q_logger_is_ready(q);
}

static inline
void qq_mref_insert(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	CHECK_ATOMIC(&mref->ref_count, 1);
	atomic_inc(&mref->ref_count); // must be paired with __trans_logger_ref_put()
	atomic_inc(&q->q_brick->inner_balance_count);

	mars_trace(mref, q->q_insert_info);

	q_logger_insert(q, &mref_a->lh);
}

static inline
void qq_wb_insert(struct logger_queue *q, struct writeback_info *wb)
{
	q_logger_insert(q, &wb->w_lh);
}

static inline
void qq_mref_pushback(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	CHECK_ATOMIC(&mref_a->object->ref_count, 1);

	mars_trace(mref_a->object, q->q_pushback_info);

	q_logger_pushback(q, &mref_a->lh);
}

static inline
void qq_wb_pushback(struct logger_queue *q, struct writeback_info *wb)
{
	q_logger_pushback(q, &wb->w_lh);
}

static inline
struct trans_logger_mref_aspect *qq_mref_fetch(struct logger_queue *q)
{
	struct logger_head *test;
	struct trans_logger_mref_aspect *mref_a = NULL;

	test = q_logger_fetch(q);

	if (test) {
		mref_a = container_of(test, struct trans_logger_mref_aspect, lh);
		CHECK_ATOMIC(&mref_a->object->ref_count, 1);
		mars_trace(mref_a->object, q->q_fetch_info);
	}
	return mref_a;
}

static inline
struct writeback_info *qq_wb_fetch(struct logger_queue *q)
{
	struct logger_head *test;
	struct writeback_info *res = NULL;

	test = q_logger_fetch(q);

	if (test) {
		res = container_of(test, struct writeback_info, w_lh);
	}
	return res;
}

///////////////////////// own helper functions ////////////////////////


static inline
int hash_fn(loff_t pos)
{
	// simple and stupid
	loff_t base_index = pos >> REGION_SIZE_BITS;
	return base_index % TRANS_HASH_MAX;
}

static inline
struct trans_logger_mref_aspect *_hash_find(struct list_head *start, loff_t pos, int *max_len, bool use_collect_head)
{
	struct list_head *tmp;
	struct trans_logger_mref_aspect *res = NULL;
	int len = *max_len;
#ifdef STAT_DEBUGGING
	int count = 0;
#endif
	
	/* The lists are always sorted according to age (newest first).
	 * Caution: there may be duplicates in the list, some of them
	 * overlapping with the search area in many different ways.
	 */
	for (tmp = start->next; tmp != start; tmp = tmp->next) {
		struct trans_logger_mref_aspect *test_a;
		struct mref_object *test;
		int diff;
#ifdef STAT_DEBUGGING
		static int max = 0;
		if (++count > max) {
			max = count;
			if (!(max % 10)) {
				MARS_DBG("hash max=%d hash=%d\n", max, hash);
			}
		}
#endif
		if (use_collect_head) {
			test_a = container_of(tmp, struct trans_logger_mref_aspect, collect_head);
		} else {
			test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
		}
		test = test_a->object;
		
		CHECK_ATOMIC(&test->ref_count, 1);

		// are the regions overlapping?
		if (pos >= test->ref_pos + test->ref_len || pos + len <= test->ref_pos) {
			continue; // not relevant
		}
		
		diff = test->ref_pos - pos;
		if (diff <= 0) {
			int restlen = test->ref_len + diff;
			res = test_a;
			if (restlen < len) {
				len = restlen;
			}
			break;
		}
		if (diff < len) {
			len = diff;
		}
	}

	*max_len = len;
	return res;
}

static noinline
struct trans_logger_mref_aspect *hash_find(struct trans_logger_brick *brick, loff_t pos, int *max_len)
{
	
	int hash = hash_fn(pos);
	struct hash_anchor *start = &brick->hash_table[hash];
	struct trans_logger_mref_aspect *res;
	unsigned int flags;

	traced_readlock(&start->hash_lock, flags);

	res = _hash_find(&start->hash_anchor, pos, max_len, false);

	traced_readunlock(&start->hash_lock, flags);

	return res;
}

static noinline
void hash_insert(struct trans_logger_brick *brick, struct trans_logger_mref_aspect *elem_a)
{
        int hash = hash_fn(elem_a->object->ref_pos);
        struct hash_anchor *start = &brick->hash_table[hash];
        unsigned int flags;

#if 1
	CHECK_HEAD_EMPTY(&elem_a->hash_head);
	CHECK_ATOMIC(&elem_a->object->ref_count, 1);
#endif

	// only for statistics:
	atomic_inc(&brick->hash_count);

        traced_writelock(&start->hash_lock, flags);

        list_add(&elem_a->hash_head, &start->hash_anchor);
	elem_a->is_hashed = true;

        traced_writeunlock(&start->hash_lock, flags);
}

/* Find the transitive closure of overlapping requests
 * and collect them into a list.
 */
static noinline
void hash_extend(struct trans_logger_brick *brick, loff_t *_pos, int *_len, struct list_head *collect_list)
{
	loff_t pos = *_pos;
	int len = *_len;
        int hash = hash_fn(pos);
        struct hash_anchor *start = &brick->hash_table[hash];
	struct list_head *tmp;
	bool extended;
        unsigned int flags;

	if (collect_list) {
		CHECK_HEAD_EMPTY(collect_list);
	}

        traced_readlock(&start->hash_lock, flags);

	do {
		extended = false;

		for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
			struct trans_logger_mref_aspect *test_a;
			struct mref_object *test;
			loff_t diff;
			
			test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
			test = test_a->object;
			
			CHECK_ATOMIC(&test->ref_count, 1);

			// are the regions overlapping?
			if (test_a->is_collected || pos >= test->ref_pos + test->ref_len || pos + len <= test->ref_pos) {
				continue; // not relevant
			}

			// extend the search region when necessary
			diff = pos - test->ref_pos;
			if (diff > 0) {
				len += diff;
				pos = test->ref_pos;
				extended = true;
			}
			diff = (test->ref_pos + test->ref_len)  - (pos + len);
			if (diff > 0) {
				len += diff;
				extended = true;
			}
		}
	} while (extended); // start over for transitive closure

	*_pos = pos;
	*_len = len;

	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
		struct trans_logger_mref_aspect *test_a;
		struct mref_object *test;
		
		test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
		test = test_a->object;
		
		// are the regions overlapping?
		if (test_a->is_collected || pos >= test->ref_pos + test->ref_len || pos + len <= test->ref_pos) {
			continue; // not relevant
		}
		
		// collect
		CHECK_HEAD_EMPTY(&test_a->collect_head);
		test_a->is_collected = true;
		CHECK_ATOMIC(&test->ref_count, 1);
		list_add_tail(&test_a->collect_head, collect_list);
	}

        traced_readunlock(&start->hash_lock, flags);
}

/* Atomically put all elements from the list.
 * All elements must reside in the same collision list.
 */
static inline
void hash_put_all(struct trans_logger_brick *brick, struct list_head *list)
{
	struct list_head *tmp;
	struct hash_anchor *start = NULL;
	int first_hash = -1;
	unsigned int flags;

	for (tmp = list->next; tmp != list; tmp = tmp->next) {
		struct trans_logger_mref_aspect *elem_a;
		struct mref_object *elem;
		int hash;

		elem_a = container_of(tmp, struct trans_logger_mref_aspect, collect_head);
		elem = elem_a->object;

		CHECK_ATOMIC(&elem->ref_count, 1);

		hash = hash_fn(elem->ref_pos);
		if (!start) {
			first_hash = hash;
			start = &brick->hash_table[hash];
			traced_writelock(&start->hash_lock, flags);
		} else if (unlikely(hash != first_hash)) {
			MARS_ERR("oops, different hashes: %d != %d\n", hash, first_hash);
		}
		
		if (!elem_a->is_hashed) {
			continue;
		}

		list_del_init(&elem_a->hash_head);
		elem_a->is_hashed = false;
		atomic_dec(&brick->hash_count);
	}
	
	if (start) {
		traced_writeunlock(&start->hash_lock, flags);
	}
}

////////////////// own brick / input / output operations //////////////////

static atomic_t global_mshadow_count = ATOMIC_INIT(0);

static noinline
int trans_logger_get_info(struct trans_logger_output *output, struct mars_info *info)
{
	struct trans_logger_input *input = output->brick->inputs[TL_INPUT_READ];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static noinline
int _make_sshadow(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a, struct trans_logger_mref_aspect *mshadow_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct mref_object *mref = mref_a->object;
	struct mref_object *mshadow;
	int diff;

	mshadow = mshadow_a->object;
#if 1
	if (unlikely(mref->ref_len > mshadow->ref_len)) {
		MARS_ERR("oops %d -> %d\n", mref->ref_len, mshadow->ref_len);
		mref->ref_len = mshadow->ref_len;
	}
	if (unlikely(mshadow_a == mref_a)) {
		MARS_ERR("oops %p == %p\n", mshadow_a, mref_a);
		return -EINVAL;
	}
#endif

	diff = mref->ref_pos - mshadow->ref_pos;
#if 1
	if (unlikely(diff < 0)) {
		MARS_ERR("oops diff = %d\n", diff);
		return -EINVAL;
	}
#endif
	/* Attach mref to the existing shadow ("slave shadow").
	 */
	mref_a->shadow_data = mshadow_a->shadow_data + diff;
	mref_a->do_dealloc = false;
	if (!mref->ref_data) { // buffered IO
		mref->ref_data = mref_a->shadow_data;
		mref_a->do_buffered = true;
	}
	mref->ref_flags = mshadow->ref_flags;
	mref_a->shadow_ref = mshadow_a;
	mref_a->my_output = output;

	/* Get an ordinary internal reference
	 */
	atomic_inc(&mref->ref_count); // must be paired with __trans_logger_ref_put()
	atomic_inc(&brick->inner_balance_count);

	/* Get an additional internal reference from slave to master,
	 * such that the master cannot go away before the slave.
	 */
	atomic_inc(&mshadow->ref_count);  // is compensated by master transition in __trans_logger_ref_put()
	atomic_inc(&brick->inner_balance_count);

	atomic_inc(&brick->sshadow_count);
	atomic_inc(&brick->total_sshadow_count);
#if 1
	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("oops, len = %d\n", mref->ref_len);
		return -EINVAL;
	}
#endif
	return mref->ref_len;
}

static noinline
int _read_ref_get(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct mref_object *mref = mref_a->object;
	struct trans_logger_input *input = brick->inputs[TL_INPUT_READ];
	struct trans_logger_mref_aspect *mshadow_a;

	/* Look if there is a newer version on the fly, shadowing
	 * the old one.
	 * When a shadow is found, use it as buffer for the mref.
	 */
	mshadow_a = hash_find(brick, mref->ref_pos, &mref->ref_len);
	if (!mshadow_a) {
		return GENERIC_INPUT_CALL(input, mref_get, mref);
	}

	return _make_sshadow(output, mref_a, mshadow_a);
}	

static noinline
int _write_ref_get(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct mref_object *mref = mref_a->object;
	void *data;

#ifdef KEEP_UNIQUE
	struct trans_logger_mref_aspect *mshadow_a;
	mshadow_a = hash_find(brick, mref->ref_pos, &mref->ref_len);
	if (mshadow_a) {
		return _make_sshadow(output, mref_a, mshadow_a);
	}
#endif

	// create a new master shadow
	data = mars_vmalloc(mref->ref_pos, mref->ref_len);
	if (unlikely(!data)) {
		return -ENOMEM;
	}
#ifdef CONFIG_DEBUG_KERNEL
	memset(data, 0x11, mref->ref_len);
#endif
	mref_a->shadow_data = data;
	mref_a->do_dealloc = true;
	if (!mref->ref_data) {
		mref->ref_data = data;
		mref_a->do_buffered = true;
	}
	mref_a->my_output = output;
	mref->ref_flags = 0;
	mref_a->shadow_ref = mref_a; // cyclic self-reference => indicates master shadow

	get_lamport(&mref_a->stamp);
#if 1
	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("oops, len = %d\n", mref->ref_len);
		return -EINVAL;
	}
#endif

	atomic_inc(&mref->ref_count); // must be paired with __trans_logger_ref_put()
	atomic_inc(&brick->inner_balance_count);

	atomic_inc(&brick->mshadow_count);
	atomic_inc(&brick->total_mshadow_count);
	atomic_inc(&global_mshadow_count);

	return mref->ref_len;
}

static noinline
int trans_logger_ref_get(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_mref_aspect *mref_a;
	loff_t base_offset;

	CHECK_PTR(output, err);

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

	atomic_inc(&brick->outer_balance_count);

	if (atomic_read(&mref->ref_count) > 0) { // setup already performed
		MARS_IO("again %d\n", atomic_read(&mref->ref_count));
		atomic_inc(&mref->ref_count);
		return mref->ref_len;
	}

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	// ensure that REGION_SIZE boundaries are obeyed by hashing
	base_offset = mref->ref_pos & (loff_t)(REGION_SIZE - 1);
	if (mref->ref_len > REGION_SIZE - base_offset) {
		mref->ref_len = REGION_SIZE - base_offset;
	}

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

static noinline
void __trans_logger_ref_put(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct mref_object *mref;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_input *input;

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

restart:
	mref = mref_a->object;
	CHECK_ATOMIC(&mref->ref_count, 1);

	CHECK_PTR(output, err);

	// are we a shadow (whether master or slave)?
	shadow_a = mref_a->shadow_ref;
	if (shadow_a) {
		bool finished;

		CHECK_ATOMIC(&mref->ref_count, 1);
		finished = atomic_dec_and_test(&mref->ref_count);
		atomic_dec(&brick->inner_balance_count);
		if (unlikely(finished && mref_a->is_hashed)) {
			   MARS_ERR("trying to put a hashed mref, pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);
			   finished = false; // leaves a memleak
		}

		if (!finished) {
			return;
		}

		CHECK_HEAD_EMPTY(&mref_a->lh.lh_head);
		CHECK_HEAD_EMPTY(&mref_a->hash_head);
		CHECK_HEAD_EMPTY(&mref_a->replay_head);
		CHECK_HEAD_EMPTY(&mref_a->collect_head);
		CHECK_HEAD_EMPTY(&mref_a->sub_list);
		CHECK_HEAD_EMPTY(&mref_a->sub_head);
		CHECK_HEAD_EMPTY(&mref_a->pos_head);

		if (shadow_a != mref_a) { // we are a slave shadow
			//MARS_DBG("slave\n");
			atomic_dec(&brick->sshadow_count);
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			trans_logger_free_mref(mref);
			// now put the master shadow
			mref_a = shadow_a;
			goto restart;
		}
		// we are a master shadow
		CHECK_PTR(mref_a->shadow_data, err);
		if (mref_a->do_dealloc) {
			mars_vfree(mref_a->shadow_data);
			mref_a->shadow_data = NULL;
			mref_a->do_dealloc = false;
		}
		if (mref_a->do_buffered) {
			mref->ref_data = NULL;
		}
		atomic_dec(&brick->mshadow_count);
		atomic_dec(&global_mshadow_count);
		trans_logger_free_mref(mref);
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(mref->ref_rw != READ)) {
		MARS_FAT("bad operation %d on non-shadow\n", mref->ref_rw);
	}

	// no shadow => call through

	input = brick->inputs[TL_INPUT_READ];
	GENERIC_INPUT_CALL(input, mref_put, mref);
	return;
err:
	MARS_FAT("oops\n");
}

static noinline
void _trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);

	__trans_logger_ref_put(output, mref_a);
	return;

err:
	MARS_FAT("giving up...\n");
}

static noinline
void trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_brick *brick = output->brick;
	atomic_dec(&brick->outer_balance_count);
	_trans_logger_ref_put(output, mref);
}

static noinline
void _trans_logger_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct mref_object *mref;
	struct generic_callback *prev_cb;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	if (unlikely(&mref_a->cb != cb)) {
		MARS_FAT("bad callback -- hanging up\n");
		goto err;
	}
	output = mref_a->my_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	prev_cb = cb->cb_prev;
	CHECK_PTR(prev_cb, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);

	mref->ref_cb = prev_cb;
	prev_cb->cb_fn(prev_cb);

	atomic_dec(&brick->fly_count);
	atomic_inc(&brick->total_cb_count);
	wake_up_interruptible(&brick->event);
	return;

err: 
	MARS_FAT("cannot handle callback\n");
}

static noinline
void trans_logger_ref_io(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_input *input;
	struct generic_callback *cb;

	CHECK_ATOMIC(&mref->ref_count, 1);

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

	// statistics
	if (mref->ref_rw) {
		atomic_inc(&brick->total_write_count);
	} else {
		atomic_inc(&brick->total_read_count);
	}

	// is this a shadow buffer?
	shadow_a = mref_a->shadow_ref;
	if (shadow_a) {
#if 1
		CHECK_HEAD_EMPTY(&mref_a->lh.lh_head);
		CHECK_HEAD_EMPTY(&mref_a->hash_head);
		CHECK_HEAD_EMPTY(&mref_a->pos_head);
#endif
		atomic_inc(&mref->ref_count); // must be paired with __trans_logger_ref_put()
		atomic_inc(&brick->inner_balance_count);

		qq_mref_insert(&brick->q_phase1, mref_a);
		//wake_up_interruptible(&brick->event);
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(mref->ref_rw != READ)) {
		MARS_FAT("bad operation %d on non-shadow\n", mref->ref_rw);
	}

	atomic_inc(&brick->fly_count);

	mref_a->my_output = output;
	cb = &mref_a->cb;
	cb->cb_fn = _trans_logger_endio;
	cb->cb_private = mref_a;
	cb->cb_error = 0;
	cb->cb_prev = mref->ref_cb;
	mref->ref_cb = cb;

	input = output->brick->inputs[TL_INPUT_READ];

	GENERIC_INPUT_CALL(input, mref_io, mref);
	return;
err:
	MARS_FAT("cannot handle IO\n");
}

////////////////////////////// writeback info //////////////////////////////

static noinline
void pos_complete(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_output *output = orig_mref_a->my_output;
	struct trans_logger_brick *brick = output->brick;
	struct list_head *tmp;
	unsigned long flags;

	// save final completion status
	traced_lock(&brick->pos_lock, flags);
	tmp = &orig_mref_a->pos_head;
	if (tmp == brick->pos_list.next) {
		loff_t finished = orig_mref_a->log_pos;
		if (finished <= brick->replay_pos) {
			MARS_ERR("backskip in log replay: %lld -> %lld\n", brick->replay_pos, orig_mref_a->log_pos);
		}
		brick->replay_pos = finished;
	}
	list_del_init(tmp);
	traced_unlock(&brick->pos_lock, flags);
}

static inline
void _free_one(struct list_head *tmp)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	
	list_del_init(tmp);
	
	sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
	sub_mref = sub_mref_a->object;
	
	trans_logger_free_mref(sub_mref);
}

static noinline
void free_writeback(struct writeback_info *wb)
{
	struct list_head *tmp;

	if (unlikely(wb->w_error < 0)) {
		MARS_ERR("writeback error = %d at pos = %lld len = %d, writeback is incomplete\n", wb->w_error, wb->w_pos, wb->w_len);
	}

	/* The sub_read and sub_write lists are usually empty here.
	 * This code is only for cleanup in case of errors.
	 */
	while (unlikely((tmp = wb->w_sub_read_list.next) != &wb->w_sub_read_list)) {
		_free_one(tmp);
	}
	while (unlikely((tmp = wb->w_sub_write_list.next) != &wb->w_sub_write_list)) {
		_free_one(tmp);
	}

	/* Now complete the original requests.
	 */
	while ((tmp = wb->w_collect_list.next) != &wb->w_collect_list) {
		struct trans_logger_mref_aspect *orig_mref_a;
		struct mref_object *orig_mref;
		
		list_del_init(tmp);
		
		orig_mref_a = container_of(tmp, struct trans_logger_mref_aspect, collect_head);
		orig_mref = orig_mref_a->object;
		
		CHECK_ATOMIC(&orig_mref->ref_count, 1);

		if (likely(wb->w_error >= 0)) {
			pos_complete(orig_mref_a);
		}

		__trans_logger_ref_put(orig_mref_a->my_output, orig_mref_a);
	}

	kfree(wb);
}

/* Generic endio() for writeback_info
 */
static noinline
void wb_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;
	int rw;
	atomic_t *dec;
	void (*endio)(struct generic_callback *cb);

	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	atomic_dec(&brick->wb_balance_count);

	if (cb->cb_error < 0) {
		wb->w_error = cb->cb_error;
	}

	rw = sub_mref->ref_rw;
	dec = rw ? &wb->w_sub_write_count : &wb->w_sub_read_count;
	CHECK_ATOMIC(dec, 1);
	if (!atomic_dec_and_test(dec)) {
		return;
	}

	endio = rw ? wb->write_endio : wb->read_endio;
	if (likely(endio)) {
		endio(cb);
	}
	return;

err: 
	MARS_FAT("hanging up....\n");
}

/* Atomically create writeback info, based on "snapshot" of current hash
 * state.
 * Notice that the hash can change during writeback IO, thus we need
 * struct writeback_info to precisely catch that information at a single
 * point in time.
 */
static noinline
struct writeback_info *make_writeback(struct trans_logger_output *output, loff_t pos, int len)
{
	struct trans_logger_brick *brick = output->brick;
	struct writeback_info *wb = kzalloc(sizeof(struct writeback_info), GFP_MARS);
	struct trans_logger_input *read_input;
	struct trans_logger_input *write_input;
	int write_input_nr;

	if (!wb) {
		goto err;
	}
	if (unlikely(len < 0)) {
		MARS_ERR("len = %d\n", len);
	}

	wb->w_output = output;
	wb->w_pos = pos;
	wb->w_len = len;
	wb->w_lh.lh_pos = &wb->w_pos;
	INIT_LIST_HEAD(&wb->w_lh.lh_head);
	INIT_LIST_HEAD(&wb->w_collect_list);
	INIT_LIST_HEAD(&wb->w_sub_read_list);
	INIT_LIST_HEAD(&wb->w_sub_write_list);

	/* Atomically fetch transitive closure on all requests
	 * overlapping with the current search region.
	 */
	hash_extend(brick, &wb->w_pos, &wb->w_len, &wb->w_collect_list);

	pos = wb->w_pos;
	len = wb->w_len;

	if (unlikely(len < 0)) {
		MARS_ERR("len = %d\n", len);
	}

	read_input = brick->inputs[TL_INPUT_READ];
	write_input_nr = TL_INPUT_WRITEBACK;
	write_input = brick->inputs[write_input_nr];
	if (!write_input->connect) {
		write_input_nr = TL_INPUT_READ;
		write_input = read_input;
	}

	/* Create sub_mrefs for read of old disk version (phase2)
	 */
	if (brick->log_reads) {
		while (len > 0) {
			struct trans_logger_mref_aspect *sub_mref_a;
			struct mref_object *sub_mref;
			int this_len;
			int status;

			sub_mref = trans_logger_alloc_mref(&read_input->hidden_output, &read_input->sub_layout);
			if (unlikely(!sub_mref)) {
				MARS_FAT("cannot alloc sub_mref\n");
				goto err;
			}

			sub_mref->ref_pos = pos;
			sub_mref->ref_len = len;
			sub_mref->ref_may_write = READ;
			sub_mref->ref_rw = READ;
			sub_mref->ref_data = NULL;

			sub_mref_a = trans_logger_mref_get_aspect(&read_input->hidden_output, sub_mref);
			CHECK_PTR(sub_mref_a, err);

			sub_mref_a->my_input = read_input;
			sub_mref_a->my_output = &read_input->hidden_output;
			sub_mref_a->wb = wb;

			status = GENERIC_INPUT_CALL(read_input, mref_get, sub_mref);
			if (unlikely(status < 0)) {
				MARS_FAT("cannot get sub_ref, status = %d\n", status);
				goto err;
			}
			
			list_add_tail(&sub_mref_a->sub_head, &wb->w_sub_read_list);
			atomic_inc(&wb->w_sub_read_count);
			atomic_inc(&brick->wb_balance_count);
		
			this_len = sub_mref->ref_len;
			pos += this_len;
			len -= this_len;
		}
		/* Re-init for startover
		 */
		pos = wb->w_pos;
		len = wb->w_len;
	}

	/* Create sub_mrefs for writeback (phase4)
	 */
	while (len > 0) {
		struct trans_logger_mref_aspect *sub_mref_a;
		struct mref_object *sub_mref;
		struct trans_logger_mref_aspect *base_mref_a;
		struct mref_object *base_mref;
		void *data;
		int this_len = len;
		int diff;
		int status;

		base_mref_a = _hash_find(&wb->w_collect_list, pos, &this_len, true);
		if (unlikely(!base_mref_a)) {
			MARS_FAT("could not find data\n");
			goto err;
		}
		base_mref = base_mref_a->object;
		diff = pos - base_mref->ref_pos;
		if (unlikely(diff < 0)) {
			MARS_FAT("bad diff %d\n", diff);
			goto err;
		}
		data = base_mref_a->shadow_data + diff;

		sub_mref = trans_logger_alloc_mref(&write_input->hidden_output, &write_input->sub_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot alloc sub_mref\n");
			goto err;
		}

		sub_mref->ref_pos = pos;
		sub_mref->ref_len = this_len;
		sub_mref->ref_may_write = WRITE;
		sub_mref->ref_rw = WRITE;
#ifdef WB_COPY
		sub_mref->ref_data = NULL;
#else
		sub_mref->ref_data = data;
#endif

		sub_mref_a = trans_logger_mref_get_aspect(&write_input->hidden_output, sub_mref);
		CHECK_PTR(sub_mref_a, err);

		sub_mref_a->my_input = write_input;
		sub_mref_a->my_output = &write_input->hidden_output;
		sub_mref_a->wb = wb;

		status = GENERIC_INPUT_CALL(write_input, mref_get, sub_mref);
		if (unlikely(status < 0)) {
			MARS_FAT("cannot get sub_ref, status = %d\n", status);
			goto err;
		}
#ifdef WB_COPY
		memcpy(sub_mref->ref_data, data, sub_mref->ref_len);
#endif
		
		list_add_tail(&sub_mref_a->sub_head, &wb->w_sub_write_list);
		atomic_inc(&wb->w_sub_write_count);
		atomic_inc(&brick->wb_balance_count);
		
		this_len = sub_mref->ref_len;
		pos += this_len;
		len -= this_len;
	}

	return wb;

 err:
	MARS_ERR("cleaning up...\n");
	if (wb) {
		free_writeback(wb);
	}
	return NULL;
}

static inline
void _fire_one(struct list_head *tmp, bool do_put)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	struct trans_logger_input *sub_input;
	struct generic_callback *cb;
	
	sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
	sub_mref = sub_mref_a->object;

	cb = &sub_mref_a->cb;
	cb->cb_fn = wb_endio;
	cb->cb_private = sub_mref_a;
	cb->cb_error = 0;
	cb->cb_prev = NULL;
	sub_mref->ref_cb = cb;

	sub_input = sub_mref_a->my_input;

	GENERIC_INPUT_CALL(sub_input, mref_io, sub_mref);
	if (do_put) {
		GENERIC_INPUT_CALL(sub_input, mref_put, sub_mref);
	}
}

static inline
void fire_writeback(struct writeback_info *wb, struct list_head *start, bool do_remove)
{
	struct list_head *tmp;

	if (do_remove) {
		while ((tmp = start->next) != start) {
			list_del_init(tmp);
			_fire_one(tmp, true);
		}
	} else {
		for (tmp = start->next; tmp != start; tmp = tmp->next) {
			_fire_one(tmp, false);
		}
	}
}


////////////////////////////// worker thread //////////////////////////////

/********************************************************************* 
 * Phase 1: write transaction log entry for the original write request.
 */
static noinline
void phase1_endio(void *private, int error)
{
	struct trans_logger_mref_aspect *orig_mref_a;
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct generic_callback *orig_cb;

	orig_mref_a = private;
	CHECK_PTR(orig_mref_a, err);
	output = orig_mref_a->my_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	orig_cb = orig_mref->ref_cb;
	CHECK_PTR(orig_cb, err);

	qq_dec_flying(&brick->q_phase1);

	// error handling
	if (error < 0) {
		orig_cb->cb_error = error;
	}

	// signal completion to the upper layer, as early as possible
	if (likely(orig_cb->cb_error >= 0)) {
		orig_mref->ref_flags &= ~MREF_WRITING;
		orig_mref->ref_flags |= MREF_UPTODATE;
	}

	CHECK_PTR(orig_cb->cb_fn, err);
	orig_cb->cb_fn(orig_cb);

	// queue up for the next phase
	qq_mref_insert(&brick->q_phase2, orig_mref_a);
	//wake_up_interruptible(&brick->event);
	return;
err: 
	MARS_ERR("giving up...\n");
}

static noinline
bool phase1_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct log_status *logst;
	void *data;
	unsigned long flags;
	bool ok;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	CHECK_PTR(orig_mref->ref_cb, err);
	output = orig_mref_a->my_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);
	logst = &brick->inputs[TL_INPUT_FW_LOG1]->logst;

	{
		struct log_header l = {
			.l_stamp = orig_mref_a->stamp,
			.l_pos = orig_mref->ref_pos,
			.l_len = orig_mref->ref_len,
			.l_code = CODE_WRITE_NEW,
		};
		data = log_reserve(logst, &l);
	}
	if (unlikely(!data)) {
		goto err;
	}

	memcpy(data, orig_mref_a->shadow_data, orig_mref->ref_len);

	ok = log_finalize(logst, orig_mref->ref_len, phase1_endio, orig_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	orig_mref_a->log_pos = logst->log_pos + logst->offset;

	traced_lock(&brick->pos_lock, flags);
	list_add_tail(&orig_mref_a->pos_head, &brick->pos_list);
	traced_unlock(&brick->pos_lock, flags);

	qq_inc_flying(&brick->q_phase1);
	return true;

err:
	return false;
}

static noinline
bool phase0_startio(struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;

	CHECK_PTR(mref, err);
	shadow_a = mref_a->shadow_ref;
	CHECK_PTR(shadow_a, err);
	output = mref_a->my_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	MARS_IO("pos = %lld len = %d rw = %d\n", mref->ref_pos, mref->ref_len, mref->ref_rw);

	if (mref->ref_rw == READ) {
		// nothing to do: directly signal success.
		struct generic_callback *cb = mref->ref_cb;
		struct mref_object *shadow = shadow_a->object;
		if (unlikely(shadow == mref)) {
			MARS_ERR("oops, we should be a slave shadow, but are a master one\n");
		}
#ifdef USE_MEMCPY
		if (mref_a->shadow_data != mref->ref_data) {
			if (unlikely(mref->ref_len <= 0 || mref->ref_len > PAGE_SIZE)) {
				MARS_ERR("implausible ref_len = %d\n", mref->ref_len);
			}
			MARS_IO("read memcpy to = %p from = %p len = %d\n", mref->ref_data, mref_a->shadow_data, mref->ref_len);
			memcpy(mref->ref_data, mref_a->shadow_data, mref->ref_len);
		}
#endif
		cb->cb_error = 0;
		mref->ref_flags |= MREF_UPTODATE;
		cb->cb_fn(cb);

		__trans_logger_ref_put(output, mref_a);

		return true;
	} 
	// else WRITE
#if 1
	CHECK_HEAD_EMPTY(&mref_a->lh.lh_head);
	CHECK_HEAD_EMPTY(&mref_a->hash_head);
	if (unlikely(mref->ref_flags & (MREF_READING | MREF_WRITING))) {
		MARS_ERR("bad flags %d\n", mref->ref_flags);
	}
#endif
	/* In case of non-buffered IO, the buffer is
	 * under control of the user. In particular, he
	 * may change it without telling us.
	 * Therefore we make a copy (or "snapshot") here.
	 */
	mref->ref_flags |= MREF_WRITING;
#ifdef USE_MEMCPY
	if (mref_a->shadow_data != mref->ref_data) {
		if (unlikely(mref->ref_len <= 0 || mref->ref_len > PAGE_SIZE)) {
			MARS_ERR("implausible ref_len = %d\n", mref->ref_len);
		}
		MARS_IO("write memcpy to = %p from = %p len = %d\n", mref_a->shadow_data, mref->ref_data, mref->ref_len);
		memcpy(mref_a->shadow_data, mref->ref_data, mref->ref_len);
	}
#endif
	mref_a->is_dirty = true;
	mref_a->shadow_ref->is_dirty = true;
#ifndef KEEP_UNIQUE
	if (unlikely(mref_a->shadow_ref != mref_a)) {
		MARS_ERR("something is wrong: %p != %p\n", mref_a->shadow_ref, mref_a);
	}
#endif
	if (!mref_a->is_hashed) {
		MARS_DBG("hashing %d at %lld\n", mref->ref_len, mref->ref_pos);
		hash_insert(brick, mref_a);
	}
	return phase1_startio(mref_a);

err:
	MARS_ERR("cannot work\n");
	msleep(1000);
	return false;
}

/********************************************************************* 
 * Phase 2: read original version of data.
 * This happens _after_ phase 1, deliberately.
 * We are explicitly dealing with old and new versions.
 * The new version is hashed in memory all the time (such that parallel
 * READs will see them), so we have plenty of time for getting the
 * old version from disk somewhen later, e.g. when IO contention is low.
 */

static noinline
void phase2_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct writeback_info *wb;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	qq_dec_flying(&brick->q_phase2);

	// queue up for the next phase
	qq_wb_insert(&brick->q_phase3, wb);
	//wake_up_interruptible(&brick->event);
	return;

err: 
	MARS_FAT("hanging up....\n");
}

static noinline
void phase4_endio(struct generic_callback *cb);
static noinline
bool phase4_startio(struct writeback_info *wb);

static noinline
bool phase2_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	output = orig_mref_a->my_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	if (orig_mref_a->is_collected) {
		MARS_IO("already collected, pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len);
		goto done;
	}
	if (!orig_mref_a->is_hashed) {
		MARS_IO("AHA not hashed, pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len);
		goto done;
	}
	wb = make_writeback(output, orig_mref->ref_pos, orig_mref->ref_len);
	if (unlikely(!wb)) {
		goto err;
	}

	if (unlikely(list_empty(&wb->w_collect_list))) {
		MARS_ERR("collection list is empty, orig pos = %lld len = %d (collected=%d), extended pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len, (int)orig_mref_a->is_collected, wb->w_pos, wb->w_len);
		free_writeback(wb);
		goto done;
	}
	if (unlikely(list_empty(&wb->w_sub_write_list))) {
		MARS_ERR("hmmm.... this should not happen\n");
		free_writeback(wb);	
		goto done;
	}

	wb->read_endio = phase2_endio;
	wb->write_endio = phase4_endio;
	atomic_set(&wb->w_sub_log_count, atomic_read(&wb->w_sub_read_count));

	if (output->brick->log_reads) {
		qq_inc_flying(&brick->q_phase2);
		fire_writeback(wb, &wb->w_sub_read_list, false);
	} else { // shortcut
#ifdef LATER
		qq_wb_insert(&brick->q_phase4, wb);
		//wake_up_interruptible(&brick->event);
#else
		return phase4_startio(wb);
#endif
	}

 done:
	return true;
	
 err:
	return false;
}


/********************************************************************* 
 * Phase 3: log the old disk version.
 */

static inline
void _phase3_endio(struct writeback_info *wb)
{
	struct trans_logger_output *output = wb->w_output;
	struct trans_logger_brick *brick = output->brick;
	
	// queue up for the next phase
	qq_wb_insert(&brick->q_phase4, wb);
	//wake_up_interruptible(&brick->event);
	return;
}

static noinline
void phase3_endio(void *private, int error)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;

	sub_mref_a = private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	qq_dec_flying(&brick->q_phase3);

	if (unlikely(error < 0)) {
		MARS_FAT("IO error %d\n", error);
		goto err; // FIXME: this leads to hanging requests. do better.
	}

	CHECK_ATOMIC(&wb->w_sub_log_count, 1);
	if (atomic_dec_and_test(&wb->w_sub_log_count)) {
		_phase3_endio(wb);
	}
	return;

err:
	MARS_FAT("hanging up....\n");
}

static noinline
bool _phase3_startio(struct trans_logger_mref_aspect *sub_mref_a)
{
	struct mref_object *sub_mref = NULL;
	struct writeback_info *wb;
	struct trans_logger_input *input;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct log_status *logst;
	void *data;
	bool ok;

	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);
	input = brick->inputs[TL_INPUT_BW_LOG1];
	if (!input || !input->connect) {
		input = brick->inputs[TL_INPUT_FW_LOG1];
	}
	logst = &input->logst;

	{
		struct log_header l = {
			.l_stamp = sub_mref_a->stamp,
			.l_pos = sub_mref->ref_pos,
			.l_len = sub_mref->ref_len,
			.l_code = CODE_WRITE_OLD,
		};
		data = log_reserve(logst, &l);
	}

	if (unlikely(!data)) {
		goto err;
	}

	memcpy(data, sub_mref->ref_data, sub_mref->ref_len);

	ok = log_finalize(logst, sub_mref->ref_len, phase3_endio, sub_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}

	qq_inc_flying(&brick->q_phase3);

	return true;

err:
	MARS_FAT("cannot log old data, pos = %lld len = %d\n", sub_mref ? sub_mref->ref_pos : 0, sub_mref ? sub_mref->ref_len : 0);
	return false;
}

static noinline
bool phase3_startio(struct writeback_info *wb)
{
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	bool ok = true;

	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	if (brick->log_reads && atomic_read(&wb->w_sub_log_count) > 0) {
		struct list_head *start;
		struct list_head *tmp;

		start = &wb->w_sub_read_list;
		for (tmp = start->next; tmp != start; tmp = tmp->next) {
			struct trans_logger_mref_aspect *sub_mref_a;
			struct mref_object *sub_mref;

			sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
			sub_mref = sub_mref_a->object;

			mars_trace(sub_mref, "sub_log");

			if (!_phase3_startio(sub_mref_a)) {
				ok = false;
			}
		}
		wake_up_interruptible(&brick->event);
	} else {
		_phase3_endio(wb);
	}
	return ok;
err:
	return false;
}

/********************************************************************* 
 * Phase 4: overwrite old disk version with new version.
 */

static noinline
void phase4_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct writeback_info *wb;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	hash_put_all(brick, &wb->w_collect_list);

	qq_dec_flying(&brick->q_phase4);

	free_writeback(wb);

	//wake_up_interruptible(&brick->event);

	return;

err: 
	MARS_FAT("hanging up....\n");
}


static noinline
bool phase4_startio(struct writeback_info *wb)
{
	struct list_head *start = &wb->w_sub_read_list;
	struct list_head *tmp;

	/* Cleanup read requests (if they exist from previous phases)
	 */
	while ((tmp = start->next) != start) {
		struct trans_logger_mref_aspect *sub_mref_a;
		struct mref_object *sub_mref;
		struct trans_logger_input *sub_input;

		list_del_init(tmp);

		sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
		sub_mref = sub_mref_a->object;
		sub_input = sub_mref_a->my_input;

		GENERIC_INPUT_CALL(sub_input, mref_put, sub_mref);
	}

	/* Start writeback IO
	 */
	qq_inc_flying(&wb->w_output->brick->q_phase4);
	fire_writeback(wb, &wb->w_sub_write_list, true);
	return true;
}

/********************************************************************* 
 * The logger thread.
 * There is only a single instance, dealing with all requests in parallel.
 */

static noinline
int run_mref_queue(struct logger_queue *q, bool (*startio)(struct trans_logger_mref_aspect *sub_mref_a), int max)
{
	struct trans_logger_brick *brick = q->q_brick;
	bool found = false;
	bool ok;
	int res;

	do {
		struct trans_logger_mref_aspect *mref_a;
		mref_a = qq_mref_fetch(q);
		res = -1;
		if (!mref_a)
			goto done;

		ok = startio(mref_a);
		if (unlikely(!ok)) {
			qq_mref_pushback(q, mref_a);
			brick->did_pushback = true;
			res = 1;
			goto done;
		}
		brick->did_work = true;
		found = true;
		__trans_logger_ref_put(mref_a->my_output, mref_a);
	} while (--max > 0);
	res = 0;

done:
	if (found) {
		wake_up_interruptible(&brick->event);
	}
	return res;
}

static noinline
int run_wb_queue(struct logger_queue *q, bool (*startio)(struct writeback_info *wb), int max)
{
	struct trans_logger_brick *brick = q->q_brick;
	bool found = false;
	bool ok;
	int res;

	do {
		struct writeback_info *wb;
		wb = qq_wb_fetch(q);
		res = -1;
		if (!wb)
			goto done;

		ok = startio(wb);
		if (unlikely(!ok)) {
			qq_wb_pushback(q, wb);
			brick->did_pushback = true;
			res = 1;
			goto done;
		}
		brick->did_work = true;
		found = true;
	} while (--max > 0);
	res = 0;

done:
	if (found) {
		wake_up_interruptible(&brick->event);
	}
	return res;
}

static inline 
int _congested(struct trans_logger_brick *brick)
{
	return atomic_read(&brick->q_phase1.q_queued)
		|| atomic_read(&brick->q_phase1.q_flying)
		|| atomic_read(&brick->q_phase2.q_queued)
		|| atomic_read(&brick->q_phase2.q_flying)
		|| atomic_read(&brick->q_phase3.q_queued)
		|| atomic_read(&brick->q_phase3.q_flying)
		|| atomic_read(&brick->q_phase4.q_queued)
		|| atomic_read(&brick->q_phase4.q_flying);
}

/* The readyness of the queues is volatile (may change underneath due
 * to interrupts etc).
 * In order to get consistency during one round of the loop in
 * trans_logger_log(), we capture the status exactly once and
 * use the captured status during processing.
 */
struct condition_status {
	bool q1_ready;
	bool q2_ready;
	bool q3_ready;
	bool q4_ready;
	bool extra_ready;
};

static noinline
bool _condition(struct condition_status *st, struct trans_logger_brick *brick)
{
	st->q1_ready = atomic_read(&brick->q_phase1.q_queued) > 0;
	st->q2_ready = qq_is_ready(&brick->q_phase2);
	st->q3_ready = qq_is_ready(&brick->q_phase3);
	st->q4_ready = qq_is_ready(&brick->q_phase4);
	st->extra_ready = (kthread_should_stop() && !_congested(brick));
	return st->q1_ready | st->q2_ready | st->q3_ready | st->q4_ready | st->extra_ready;
}

static noinline
void trans_logger_log(struct trans_logger_output *output)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_input *fw_input;
	struct trans_logger_input *bw_input;
	struct log_status *fw_logst;
	struct log_status *bw_logst;
	long wait_timeout = HZ;
#ifdef  STAT_DEBUGGING
	long long last_jiffies = jiffies;
#endif
#if 1
	int max_delta = 0;
#endif

	fw_input = brick->inputs[TL_INPUT_FW_LOG1];
	fw_logst = &fw_input->logst;
	fw_logst->align_size = brick->align_size;
	fw_logst->chunk_size = brick->chunk_size;
	init_logst(fw_logst, (void*)fw_input, (void*)&fw_input->hidden_output, 0);


	bw_input = brick->inputs[TL_INPUT_BW_LOG1];
	bw_logst = &bw_input->logst;
	if (!bw_input || !bw_input->connect) {
		bw_input = fw_input;
		bw_logst = fw_logst;
	} else if (bw_input != fw_input) {
		bw_logst->align_size = brick->align_size;
		bw_logst->chunk_size = brick->chunk_size;
		init_logst(bw_logst, (void*)bw_input, (void*)&bw_input->hidden_output, 0);
	}

	brick->replay_pos = brick->current_pos = brick->log_start_pos;
	fw_logst->log_pos = brick->current_pos;

	mars_power_led_on((void*)brick, true);

	while (!kthread_should_stop() || _congested(brick)) {
		long long old_jiffies = jiffies;
		struct condition_status st = {};
#if 1
		long long j0;
		long long j1;
		long long j2;
		long long j3;
		long long j4;
		bool orig;
#endif

		MARS_IO("waiting for request\n");

		__wait_event_interruptible_timeout(
			brick->event,
			_condition(&st, brick),
			wait_timeout);

#if 1
		j0 = jiffies;
		orig = st.q1_ready | st.q2_ready | st.q3_ready | st.q4_ready | st.extra_ready;
#endif

		//MARS_DBG("AHA %d\n", atomic_read(&brick->q_phase1.q_queued));

#ifdef STAT_DEBUGGING
		if (((long long)jiffies) - last_jiffies >= HZ * 5 && brick->power.button) {
			char *txt;
			last_jiffies = jiffies;
			txt = brick->ops->brick_statistics(brick, 0);
			if (txt) {
				MARS_INF("%s", txt);
				kfree(txt);
			}
		}
#endif
		brick->did_pushback = false;
		brick->did_work = false;

		/* This is highest priority, do it first.
		 */
		run_mref_queue(&brick->q_phase1, phase0_startio, brick->q_phase1.q_batchlen);
		j1 = jiffies;

		/* In order to speed up draining, check the other queues
		 * in backward direction.
		 */
		if (st.q4_ready) {
			run_wb_queue(&brick->q_phase4, phase4_startio, brick->q_phase4.q_batchlen);
		}
		j2 = jiffies;

		if (st.q3_ready) {
			run_wb_queue(&brick->q_phase3, phase3_startio, brick->q_phase3.q_batchlen);
		}
		j3 = jiffies;

		if (st.q2_ready) {
			run_mref_queue(&brick->q_phase2, phase2_startio, brick->q_phase2.q_batchlen);
		}
		j4 = jiffies;

		/* A kind of delayed plugging mechanism
		 */
		wait_timeout = HZ / 10; // 100ms before flushing
#ifdef CONFIG_DEBUG_KERNEL // debug override for catching long blocks
		wait_timeout = 16 * HZ;
#endif
		wait_timeout = 1;
		if (brick->did_work) {
			wait_timeout = 0; // start over immediately
		} else if (brick->minimize_latency || (long long)jiffies - old_jiffies >= wait_timeout) {
			/* Calling log_flush() too often may result in
			 * increased overhead (and thus in lower throughput).
			 * OTOH, calling it too seldom may hold back
			 * IO completion for the end user for some time.
			 * Play around with wait_timeout to optimize this.
			 */
			log_flush(fw_logst);
			if (bw_logst != fw_logst) {
				log_flush(bw_logst);
			}
		}
#if 1
		log_flush(fw_logst);
#endif
#if 1
		{
			int delta = (long long)jiffies - j0;
			int delta1 = (long long)j1 - j0;
			int delta2 = (long long)j2 - j0;
			int delta3 = (long long)j3 - j0;
			int delta4 = (long long)j4 - j0;
			if (delta > max_delta) {
				max_delta = delta;
				MARS_INF("delta = %d %d %d %d %d\n", delta, delta1, delta2, delta3, delta4);
			}
		}

		if (orig && !brick->did_work) {
			char *txt;
			txt = brick->ops->brick_statistics(brick, 0);
			MARS_ERR("inconsistent work, pushback = %d q1 = %d q2 = %d q3 = %d q4 = %d extra = %d ====> %s\n", brick->did_pushback, st.q1_ready, st.q2_ready, st.q3_ready, st.q4_ready, st.extra_ready, txt ? txt : "(ERROR)");
			if (txt) {
				kfree(txt);
			}
		}
#endif
	}
}

////////////////////////////// log replay //////////////////////////////

static noinline
void replay_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *mref_a = cb->cb_private;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	unsigned long flags;

	CHECK_PTR(mref_a, err);
	output = mref_a->my_output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	traced_lock(&brick->replay_lock, flags);
	list_del_init(&mref_a->replay_head);
	traced_unlock(&brick->replay_lock, flags);

	atomic_dec(&brick->replay_count);
	wake_up_interruptible(&brick->event);
	return;
 err:
	MARS_FAT("cannot handle replay IO\n");
}

static noinline
bool _has_conflict(struct trans_logger_brick *brick, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	struct list_head *tmp;
	bool res = false;
	unsigned long flags;

	// NOTE: replacing this by rwlock_t will not gain anything, because there exists at most 1 reader at any time

	traced_lock(&brick->replay_lock, flags);

	for (tmp = brick->replay_list.next; tmp != &brick->replay_list; tmp = tmp->next) {
		struct trans_logger_mref_aspect *tmp_a;
		struct mref_object *tmp_mref;

		tmp_a = container_of(tmp, struct trans_logger_mref_aspect, replay_head);
		tmp_mref = tmp_a->object;
		if (tmp_mref->ref_pos + tmp_mref->ref_len > mref->ref_len && tmp_mref->ref_pos < mref->ref_pos + mref->ref_len) {
			res = true;
			break;
		}
	}

	traced_unlock(&brick->replay_lock, flags);
	return res;
}

static noinline
void wait_replay(struct trans_logger_brick *brick, struct trans_logger_mref_aspect *mref_a)
{
	int max = 1024 * 2; // limit parallelism somewhat
	unsigned long flags;

	wait_event_interruptible_timeout(brick->event,
					 atomic_read(&brick->replay_count) <= max
					 && !_has_conflict(brick, mref_a),
					 60 * HZ);

	atomic_inc(&brick->replay_count);
	traced_lock(&brick->replay_lock, flags);
	list_add(&mref_a->replay_head, &brick->replay_list);
	traced_unlock(&brick->replay_lock, flags);
}

static noinline
int apply_data(struct trans_logger_brick *brick, loff_t pos, void *buf, int len)
{
	struct trans_logger_input *input = brick->inputs[TL_INPUT_WRITEBACK];
	int status;

	MARS_IO("got data, pos = %lld, len = %d\n", pos, len);

	if (!input->connect) {
		input = brick->inputs[TL_INPUT_READ];
	}

	/* TODO for better efficiency:
	 * Instead of starting IO here, just put the data into the hashes
	 * and queues such that ordinary IO will be corrected.
	 * Writeback will be lazy then.
	 * The switch infrastructure must be changed before this
	 * becomes possible.
	 */
#ifdef APPLY_DATA
	while (len > 0) {
		struct mref_object *mref;
		struct trans_logger_mref_aspect *mref_a;
		struct generic_callback *cb;
		
		status = -ENOMEM;
		mref = trans_logger_alloc_mref(&input->hidden_output, &input->sub_layout);
		if (unlikely(!mref)) {
			MARS_ERR("no memory\n");
			goto done;
		}
		mref_a = trans_logger_mref_get_aspect(&input->hidden_output, mref);
		CHECK_PTR(mref_a, done);
		
		mref->ref_pos = pos;
		mref->ref_data = NULL;
		mref->ref_len = len;
		mref->ref_may_write = WRITE;
		mref->ref_rw = WRITE;
		
		status = GENERIC_INPUT_CALL(input, mref_get, mref);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot get mref, status = %d\n", status);
			goto done;
		}
		if (unlikely(!mref->ref_data)) {
			status = -ENOMEM;
			MARS_ERR("cannot get mref, status = %d\n", status);
			goto done;
		}
		if (unlikely(mref->ref_len <= 0 || mref->ref_len > len)) {
			status = -EINVAL;
			MARS_ERR("bad ref len = %d (requested = %d)\n", mref->ref_len, len);
			goto done;
		}
		
		mars_trace(mref, "replay_start");

		wait_replay(brick, mref_a);

		mars_trace(mref, "replay_io");

		memcpy(mref->ref_data, buf, mref->ref_len);

		cb = &mref_a->cb;
		cb->cb_fn = replay_endio;
		cb->cb_private = mref_a;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		mref->ref_cb = cb;
		mref_a->my_output = &input->hidden_output;
		
		GENERIC_INPUT_CALL(input, mref_io, mref);

		if (unlikely(mref->ref_len <= 0)) {
			status = -EINVAL;
			MARS_ERR("bad ref len = %d (requested = %d)\n", mref->ref_len, len);
			goto done;
		}

		pos += mref->ref_len;
		buf += mref->ref_len;
		len -= mref->ref_len;

		GENERIC_INPUT_CALL(input, mref_put, mref);
	}
#endif
	status = 0;
 done:
	return status;
}

static noinline
void trans_logger_replay(struct trans_logger_output *output)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_input *input = brick->inputs[TL_INPUT_FW_LOG1];
	bool has_triggered = false;

	brick->replay_code = -EAGAIN; // indicates "running"

	MARS_INF("starting replay from %lld to %lld\n", brick->replay_start_pos, brick->replay_end_pos);
	
	input->logst.align_size = brick->align_size;
	input->logst.chunk_size = brick->chunk_size;
	init_logst(&input->logst, (void*)input, (void*)&input->hidden_output, brick->replay_start_pos);

	brick->replay_pos = brick->current_pos = input->logst.log_pos;
	mars_power_led_on((void*)brick, true);

	for (;;) {
		struct log_header lh = {};
		void *buf = NULL;
		int len = 0;
		int status;

		if (kthread_should_stop()) {
			break;
		}

		status = log_read(&input->logst, &lh, &buf, &len);
		if (unlikely(status < 0)) {
			brick->replay_code = status;
			MARS_ERR("cannot read logfile data, status = %d\n", status);
			break;
		}
		if (!status) { // EOF -> wait until kthread_should_stop()
			MARS_DBG("got EOF\n");
			if (!brick->do_continuous_replay) {
				break;
			}
			msleep(1000);
		}

		if (lh.l_code != CODE_WRITE_NEW) {
			MARS_IO("ignoring pos = %lld len = %d code = %d\n", lh.l_pos, lh.l_len, lh.l_code);
			continue;
		}

		if (likely(buf && len)) {
			status = apply_data(brick, lh.l_pos, buf, len);
			if (unlikely(status < 0)) {
				brick->replay_code = status;
				MARS_ERR("cannot apply data, len = %d, status = %d\n", len, status);
				break;
			}
		}

		// do this _after_ any opportunities for errors...
		if (atomic_read(&brick->replay_count) <= 0) {
			brick->replay_pos = brick->current_pos = input->logst.log_pos + input->logst.offset;
		}
	}

	wait_event_interruptible_timeout(brick->event, atomic_read(&brick->replay_count) <= 0, 60 * HZ);

	brick->replay_pos = brick->current_pos = input->logst.log_pos + input->logst.offset;

	if (brick->replay_pos == brick->replay_end_pos) {
		MARS_INF("replay finished at %lld\n", brick->replay_pos);
		brick->replay_code = 0;
	} else {
		MARS_INF("replay stopped prematurely at %lld (of %lld)\n", brick->replay_pos, brick->replay_end_pos);
		if (brick->replay_code == -EAGAIN)
			brick->replay_code = -EIO;
	}

	while (!kthread_should_stop()) {
		if (!has_triggered) {
			mars_trigger();
			has_triggered = true;
		}
		msleep(500);
	}
}

///////////////////////// logger thread / switching /////////////////////////

static noinline
int trans_logger_thread(void *data)
{
	struct trans_logger_output *output = data;
	struct trans_logger_brick *brick = output->brick;

	MARS_INF("........... logger has started.\n");

	if (brick->do_replay) {
		trans_logger_replay(output);
	} else {
		trans_logger_log(output);
	}

	MARS_INF("........... logger has stopped.\n");
	mars_power_led_on((void*)brick, false);
	mars_power_led_off((void*)brick, true);
	return 0;
}

static noinline
int trans_logger_switch(struct trans_logger_brick *brick)
{
	static int index = 0;
	struct trans_logger_output *output = brick->outputs[0];

	if (brick->power.button) {
		if (!brick->thread && brick->power.led_off) {
			mars_power_led_off((void*)brick, false);

			brick->thread = kthread_create(trans_logger_thread, output, "mars_logger%d", index++);
			if (IS_ERR(brick->thread)) {
				int error = PTR_ERR(brick->thread);
				MARS_ERR("cannot create thread, status=%d\n", error);
				brick->thread = NULL;
				return error;
			}
			get_task_struct(brick->thread);
			wake_up_process(brick->thread);
		}
	} else {
		mars_power_led_on((void*)brick, false);
		if (brick->thread) {
			kthread_stop(brick->thread);
			put_task_struct(brick->thread);
			brick->thread = NULL;
		}
	}
	return 0;
}

//////////////// informational / statistics ///////////////

static noinline
char *trans_logger_statistics(struct trans_logger_brick *brick, int verbose)
{
	char *res = kmalloc(512, GFP_MARS);
	if (!res)
		return NULL;

	// FIXME: check for allocation overflows

	sprintf(res, "total callbacks = %d reads=%d writes=%d writeback=%d shortcut=%d (%d%%) mshadow=%d sshadow=%d phase1=%d phase2=%d phase3=%d phase4=%d | mshadow=%d sshadow=%d hash_count=%d balance=%d/%d/%d/%d fly=%d phase1=%d+%d phase2=%d+%d phase3=%d+%d phase4=%d+%d\n",
		atomic_read(&brick->total_cb_count), atomic_read(&brick->total_read_count), atomic_read(&brick->total_write_count), atomic_read(&brick->total_writeback_count), atomic_read(&brick->total_shortcut_count), atomic_read(&brick->total_writeback_count) ? atomic_read(&brick->total_shortcut_count) * 100 / atomic_read(&brick->total_writeback_count) : 0, atomic_read(&brick->total_mshadow_count), atomic_read(&brick->total_sshadow_count), atomic_read(&brick->q_phase1.q_total), atomic_read(&brick->q_phase2.q_total), atomic_read(&brick->q_phase3.q_total), atomic_read(&brick->q_phase4.q_total),
		atomic_read(&brick->mshadow_count), atomic_read(&brick->sshadow_count), atomic_read(&brick->hash_count), atomic_read(&brick->sub_balance_count), atomic_read(&brick->inner_balance_count), atomic_read(&brick->outer_balance_count), atomic_read(&brick->wb_balance_count), atomic_read(&brick->fly_count), atomic_read(&brick->q_phase1.q_queued), atomic_read(&brick->q_phase1.q_flying), atomic_read(&brick->q_phase2.q_queued), atomic_read(&brick->q_phase2.q_flying), atomic_read(&brick->q_phase3.q_queued), atomic_read(&brick->q_phase3.q_flying), atomic_read(&brick->q_phase4.q_queued), atomic_read(&brick->q_phase4.q_flying));
	return res;
}

static noinline
void trans_logger_reset_statistics(struct trans_logger_brick *brick)
{
	atomic_set(&brick->total_cb_count, 0);
	atomic_set(&brick->total_read_count, 0);
	atomic_set(&brick->total_write_count, 0);
	atomic_set(&brick->total_writeback_count, 0);
	atomic_set(&brick->total_shortcut_count, 0);
	atomic_set(&brick->total_mshadow_count, 0);
	atomic_set(&brick->total_sshadow_count, 0);
}


//////////////// object / aspect constructors / destructors ///////////////

static noinline
int trans_logger_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mref_aspect *ini = (void*)_ini;
	ini->lh.lh_pos = &ini->object->ref_pos;
	INIT_LIST_HEAD(&ini->lh.lh_head);
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->pos_head);
	INIT_LIST_HEAD(&ini->replay_head);
	INIT_LIST_HEAD(&ini->collect_head);
	INIT_LIST_HEAD(&ini->sub_list);
	INIT_LIST_HEAD(&ini->sub_head);
	return 0;
}

static noinline
void trans_logger_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct trans_logger_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->lh.lh_head);
	CHECK_HEAD_EMPTY(&ini->hash_head);
	CHECK_HEAD_EMPTY(&ini->pos_head);
	CHECK_HEAD_EMPTY(&ini->replay_head);
	CHECK_HEAD_EMPTY(&ini->collect_head);
	CHECK_HEAD_EMPTY(&ini->sub_list);
	CHECK_HEAD_EMPTY(&ini->sub_head);
}

MARS_MAKE_STATICS(trans_logger);

////////////////////// brick constructors / destructors ////////////////////

static noinline
int trans_logger_brick_construct(struct trans_logger_brick *brick)
{
	int i;
	for (i = 0; i < TRANS_HASH_MAX; i++) {
		struct hash_anchor *start = &brick->hash_table[i];
		rwlock_init(&start->hash_lock);
		INIT_LIST_HEAD(&start->hash_anchor);
	}
	atomic_set(&brick->hash_count, 0);
	spin_lock_init(&brick->pos_lock);
	INIT_LIST_HEAD(&brick->pos_list);
	spin_lock_init(&brick->replay_lock);
	INIT_LIST_HEAD(&brick->replay_list);
	init_waitqueue_head(&brick->event);
	qq_init(&brick->q_phase1, brick);
	qq_init(&brick->q_phase2, brick);
	qq_init(&brick->q_phase3, brick);
	qq_init(&brick->q_phase4, brick);
#if 1
	brick->q_phase2.q_dep = &brick->q_phase4;
	brick->q_phase4.q_dep = &brick->q_phase1;

#endif
	brick->q_phase1.q_insert_info   = "q1_ins";
	brick->q_phase1.q_pushback_info = "q1_push";
	brick->q_phase1.q_fetch_info    = "q1_fetch";
	brick->q_phase2.q_insert_info   = "q2_ins";
	brick->q_phase2.q_pushback_info = "q2_push";
	brick->q_phase2.q_fetch_info    = "q2_fetch";
	brick->q_phase3.q_insert_info   = "q3_ins";
	brick->q_phase3.q_pushback_info = "q3_push";
	brick->q_phase3.q_fetch_info    = "q3_fetch";
	brick->q_phase4.q_insert_info   = "q4_ins";
	brick->q_phase4.q_pushback_info = "q4_push";
	brick->q_phase4.q_fetch_info    = "q4_fetch";
	return 0;
}

static noinline
int trans_logger_output_construct(struct trans_logger_output *output)
{
	return 0;
}

static noinline
int trans_logger_input_construct(struct trans_logger_input *input)
{
	struct trans_logger_output *hidden = &input->hidden_output;
	_trans_logger_output_init(input->brick, hidden, "internal");
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct trans_logger_brick_ops trans_logger_brick_ops = {
	.brick_switch = trans_logger_switch,
	.brick_statistics = trans_logger_statistics,
	.reset_statistics = trans_logger_reset_statistics,
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
