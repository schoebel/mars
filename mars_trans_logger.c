// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define REPLAY_DEBUGGING
//#define STAT_DEBUGGING // here means: display full statistics
//#define HASH_DEBUGGING

// variants
#define KEEP_UNIQUE
#define LATER
#define DELAY_CALLERS // this is _needed_
//#define WB_COPY // unnecessary (only costs performance)
//#define LATE_COMPLETE // unnecessary (only costs performance)
//#define EARLY_COMPLETION
//#define OLD_POSCOMPLETE

// commenting this out is dangerous for data integrity! use only for testing!
#define USE_MEMCPY
#define DO_WRITEBACK // otherwise FAKE IO
#define APPLY_DATA

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/kthread.h>

#include "mars.h"

#ifdef REPLAY_DEBUGGING
#define MARS_RPL(_fmt, _args...)  _MARS_MSG(false, "REPLAY ", _fmt, ##_args)
#else
#define MARS_RPL(_args...) /*empty*/
#endif


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
	q->q_event = &brick->worker_event;
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
	long base_index = (long)pos >> REGION_SIZE_BITS;
	base_index += base_index / TRANS_HASH_MAX / 7;
	return base_index % TRANS_HASH_MAX;
}

static inline
struct trans_logger_mref_aspect *_hash_find(struct list_head *start, loff_t pos, int *max_len, struct timespec *elder, bool use_collect_head)
{
	struct list_head *tmp;
	struct trans_logger_mref_aspect *res = NULL;
	int len = *max_len;
#ifdef HASH_DEBUGGING
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
#ifdef HASH_DEBUGGING
		static int max = 0;
		if (++count > max) {
			max = count;
			if (!(max % 100)) {
				MARS_INF("hash max=%d hash=%d (pos=%lld)\n", max, hash_fn(pos), pos);
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

		// timestamp handling
		if (elder && timespec_compare(&test_a->stamp, elder) > 0) {
			continue; // not relevant
		}

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
	//unsigned int flags;

	atomic_inc(&brick->total_hash_find_count);

	down_read(&start->hash_mutex);

	res = _hash_find(&start->hash_anchor, pos, max_len, NULL, false);

	up_read(&start->hash_mutex);

	return res;
}

static noinline
void hash_insert(struct trans_logger_brick *brick, struct trans_logger_mref_aspect *elem_a)
{
        int hash = hash_fn(elem_a->object->ref_pos);
        struct hash_anchor *start = &brick->hash_table[hash];
        //unsigned int flags;

#if 1
	CHECK_HEAD_EMPTY(&elem_a->hash_head);
	CHECK_ATOMIC(&elem_a->object->ref_count, 1);
#endif

	// only for statistics:
	atomic_inc(&brick->hash_count);
	atomic_inc(&brick->total_hash_insert_count);

	down_write(&start->hash_mutex);

        list_add(&elem_a->hash_head, &start->hash_anchor);
	elem_a->is_hashed = true;

	up_write(&start->hash_mutex);
}

/* Find the transitive closure of overlapping requests
 * and collect them into a list.
 */
static noinline
void hash_extend(struct trans_logger_brick *brick, loff_t *_pos, int *_len, struct timespec *elder, struct list_head *collect_list)
{
	loff_t pos = *_pos;
	int len = *_len;
        int hash = hash_fn(pos);
        struct hash_anchor *start = &brick->hash_table[hash];
	struct list_head *tmp;
	bool extended;
        //unsigned int flags;
#ifdef HASH_DEBUGGING
	int count = 0;
	static int max = 0;
#endif
	if (collect_list) {
		CHECK_HEAD_EMPTY(collect_list);
	}

	atomic_inc(&brick->total_hash_extend_count);

	down_read(&start->hash_mutex);

	do {
		extended = false;

		for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
			struct trans_logger_mref_aspect *test_a;
			struct mref_object *test;
			loff_t diff;
#ifdef HASH_DEBUGGING
			count++;
#endif
			
			test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
			test = test_a->object;
			
			CHECK_ATOMIC(&test->ref_count, 1);

			// timestamp handling
			if (elder && timespec_compare(&test_a->stamp, elder) > 0) {
				continue; // not relevant
			}

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

#ifdef HASH_DEBUGGING
	if (count > max + 100) {
		int i = 0;
		max = count;
		MARS_INF("iterations max=%d hash=%d (pos=%lld len=%d)\n", max, hash, pos, len);
		for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
			struct trans_logger_mref_aspect *test_a;
			struct mref_object *test;
			test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
			test = test_a->object;
			MARS_INF("%03d   pos = %lld len = %d collected = %d\n", i++, test->ref_pos, test->ref_len, test_a->is_collected);
		}
		MARS_INF("----------------\n");
	}
#endif

	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
		struct trans_logger_mref_aspect *test_a;
		struct mref_object *test;
		
		test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
		test = test_a->object;
		
		// timestamp handling
		if (elder && timespec_compare(&test_a->stamp, elder) > 0) {
			continue; // not relevant
		}

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

	up_read(&start->hash_mutex);
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
	//unsigned int flags;

	for (tmp = list->next; tmp != list; tmp = tmp->next) {
		struct trans_logger_mref_aspect *elem_a;
		struct mref_object *elem;
		int hash;

		elem_a = container_of(tmp, struct trans_logger_mref_aspect, collect_head);
		elem = elem_a->object;
		CHECK_PTR(elem, err);
		CHECK_ATOMIC(&elem->ref_count, 1);

		hash = hash_fn(elem->ref_pos);
		if (!start) {
			first_hash = hash;
			start = &brick->hash_table[hash];
			down_write(&start->hash_mutex);
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

err:	
	if (start) {
		up_write(&start->hash_mutex);
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
		atomic_inc(&brick->total_sshadow_buffered_count);
	}
	mref->ref_flags = mshadow->ref_flags;
	mref_a->shadow_ref = mshadow_a;
	mref_a->my_brick = brick;

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

#ifdef DELAY_CALLERS
	// delay in case of too many master shadows / memory shortage
	wait_event_interruptible_timeout(brick->caller_event, !brick->delay_callers, HZ / 2);
#endif

	// create a new master shadow
	data = brick_block_alloc(mref->ref_pos, (mref_a->alloc_len = mref->ref_len));
	if (unlikely(!data)) {
		return -ENOMEM;
	}
	atomic64_add(mref->ref_len, &brick->shadow_mem_used);
#ifdef CONFIG_MARS_DEBUG
	memset(data, 0x11, mref->ref_len);
#endif
	mref_a->shadow_data = data;
	mref_a->do_dealloc = true;
	if (!mref->ref_data) { // buffered IO
		mref->ref_data = data;
		mref_a->do_buffered = true;
		atomic_inc(&brick->total_mshadow_buffered_count);
	}
	mref_a->my_brick = brick;
	mref->ref_flags = 0;
	mref_a->shadow_ref = mref_a; // cyclic self-reference => indicates master shadow

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

	if (mref->ref_len > brick->max_mref_size && brick->max_mref_size > 0)
		mref->ref_len = brick->max_mref_size;

	atomic_inc(&brick->outer_balance_count);

	if (atomic_read(&mref->ref_count) > 0) { // setup already performed
		MARS_IO("again %d\n", atomic_read(&mref->ref_count));
		atomic_inc(&mref->ref_count);
		return mref->ref_len;
	}

	mref_a = trans_logger_mref_get_aspect(brick, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	get_lamport(&mref_a->stamp);

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
	while (unlikely(!brick->power.led_on)) {
		msleep(HZ / 10);
	}

	return _write_ref_get(output, mref_a);

err:
	return -EINVAL;
}

static noinline
void pos_complete(struct trans_logger_mref_aspect *orig_mref_a);

static noinline
void __trans_logger_ref_put(struct trans_logger_brick *brick, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_input *input;

restart:
	CHECK_PTR(mref_a, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

	CHECK_ATOMIC(&mref->ref_count, 1);

	// are we a shadow (whether master or slave)?
	shadow_a = mref_a->shadow_ref;
	if (shadow_a) {
		bool finished;

		CHECK_PTR(shadow_a, err);
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

#ifndef OLD_POSCOMPLETE
		if (mref_a->is_collected && likely(mref_a->wb_error >= 0)) {
			pos_complete(mref_a);
		}
#endif

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
			brick_block_free(mref_a->shadow_data, mref_a->alloc_len);
			atomic64_sub(mref->ref_len, &brick->shadow_mem_used);
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
	CHECK_PTR(input, err);

	GENERIC_INPUT_CALL(input, mref_put, mref);

err: ;
}

static noinline
void _trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;

	mref_a = trans_logger_mref_get_aspect(output->brick, mref);
	CHECK_PTR(mref_a, err);

	__trans_logger_ref_put(output->brick, mref_a);
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
	struct trans_logger_brick *brick;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	if (unlikely(&mref_a->cb != cb)) {
		MARS_FAT("bad callback -- hanging up\n");
		goto err;
	}
	brick = mref_a->my_brick;
	CHECK_PTR(brick, err);

	NEXT_CHECKED_CALLBACK(cb, err);

	atomic_dec(&brick->fly_count);
	atomic_inc(&brick->total_cb_count);
	wake_up_interruptible_all(&brick->worker_event);
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

	CHECK_ATOMIC(&mref->ref_count, 1);

	mref_a = trans_logger_mref_get_aspect(brick, mref);
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
		wake_up_interruptible_all(&brick->worker_event);
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(mref->ref_rw != READ)) {
		MARS_FAT("bad operation %d on non-shadow\n", mref->ref_rw);
	}

	atomic_inc(&brick->fly_count);

	mref_a->my_brick = brick;

	INSERT_CALLBACK(mref, &mref_a->cb, _trans_logger_endio, mref_a);

	input = output->brick->inputs[TL_INPUT_READ];

	GENERIC_INPUT_CALL(input, mref_io, mref);
	return;
err:
	MARS_FAT("cannot handle IO\n");
}

////////////////////////////// writeback info //////////////////////////////

/* save final completion status when necessary
 */
static noinline
void pos_complete(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_brick *brick = orig_mref_a->my_brick;
	struct trans_logger_input *log_input = orig_mref_a->log_input;
	struct list_head *tmp;
	unsigned long flags;

	CHECK_PTR(log_input, err);

	atomic_inc(&brick->total_writeback_count);

	tmp = &orig_mref_a->pos_head;

	traced_lock(&log_input->pos_lock, flags);
	// am I the first member? (means "youngest" list entry)
	if (tmp == log_input->pos_list.next) {
		if (unlikely(!log_input)) {
			MARS_ERR("cannot tell what input I am operating on\n");
		} else {
			loff_t finished = orig_mref_a->log_pos;
			MARS_IO("finished = %lld\n", finished);
			if (finished <= log_input->replay_min_pos) {
				MARS_ERR("backskip in log replay: %lld -> %lld\n", log_input->replay_min_pos, orig_mref_a->log_pos);
			}
			log_input->replay_min_pos = finished;
		}
	} else {
		struct trans_logger_mref_aspect *prev_mref_a;
		prev_mref_a = container_of(tmp->prev, struct trans_logger_mref_aspect, pos_head);
		if (orig_mref_a->log_pos <= prev_mref_a->log_pos) {
			MARS_ERR("backskip: %lld -> %lld\n", orig_mref_a->log_pos, prev_mref_a->log_pos);
		} else {
			/* Transitively transfer log_pos to the predecessor
			 * to correctly reflect the committed region.
			 */
			prev_mref_a->log_pos = orig_mref_a->log_pos;
		}
	}
	list_del_init(tmp);
	atomic_dec(&brick->pos_count);
	traced_unlock(&log_input->pos_lock, flags);
err:;
}

static noinline
void free_writeback(struct writeback_info *wb)
{
	struct list_head *tmp;

	if (unlikely(wb->w_error < 0)) {
		MARS_ERR("writeback error = %d at pos = %lld len = %d, writeback is incomplete\n", wb->w_error, wb->w_pos, wb->w_len);
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
		if (unlikely(!orig_mref_a->is_collected)) {
			MARS_ERR("request %lld (len = %d) was not collected\n", orig_mref->ref_pos, orig_mref->ref_len);
		}
#ifdef LATE_COMPLETE
		while (!orig_mref_a->is_completed) {
			MARS_ERR("request %lld (len = %d) was not completed\n", orig_mref->ref_pos, orig_mref->ref_len);
			msleep(3000);
		}
#endif
#ifdef OLD_POSCOMPLETE
		if (likely(wb->w_error >= 0)) {
			pos_complete(orig_mref_a);
		}
#else
		if (unlikely(wb->w_error < 0)) {
			orig_mref_a->wb_error = wb->w_error;
		}
#endif

		__trans_logger_ref_put(orig_mref_a->my_brick, orig_mref_a);
	}

	brick_mem_free(wb);
}

/* Generic endio() for writeback_info
 */
static noinline
void wb_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;
	int rw;
	atomic_t *dec;
	void (**_endio)(struct generic_callback *cb);
	void (*endio)(struct generic_callback *cb);

	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);

	if (cb->cb_error < 0) {
		wb->w_error = cb->cb_error;
	}

	atomic_dec(&brick->wb_balance_count);

	rw = sub_mref_a->orig_rw;
	dec = rw ? &wb->w_sub_write_count : &wb->w_sub_read_count;
	CHECK_ATOMIC(dec, 1);
	if (!atomic_dec_and_test(dec)) {
		goto done;
	}

	_endio = rw ? &wb->write_endio : &wb->read_endio;
	endio = *_endio;
	*_endio = NULL;
	if (likely(endio)) {
		endio(cb);
	} else {
		MARS_ERR("internal: no endio defined\n");
	}
done:
	wake_up_interruptible_all(&brick->worker_event);
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
struct writeback_info *make_writeback(struct trans_logger_brick *brick, loff_t pos, int len, struct timespec *elder, struct trans_logger_input *log_input)
{
	struct writeback_info *wb;
	struct trans_logger_input *read_input;
	struct trans_logger_input *write_input;
	int write_input_nr;

	/* Allocate structure representing a bunch of adjacent writebacks
	 */
	wb = brick_zmem_alloc(sizeof(struct writeback_info));
	if (!wb) {
		goto err;
	}
	if (unlikely(len < 0)) {
		MARS_ERR("len = %d\n", len);
	}

	wb->w_brick = brick;
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
	hash_extend(brick, &wb->w_pos, &wb->w_len, elder, &wb->w_collect_list);

	pos = wb->w_pos;
	len = wb->w_len;

	if (unlikely(len < 0)) {
		MARS_ERR("len = %d\n", len);
	}

	/* Determine the "channels" we want to operate on
	 */
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

			sub_mref = trans_logger_alloc_mref(brick);
			if (unlikely(!sub_mref)) {
				MARS_FAT("cannot alloc sub_mref\n");
				goto err;
			}

			sub_mref->ref_pos = pos;
			sub_mref->ref_len = len;
			sub_mref->ref_may_write = READ;
			sub_mref->ref_rw = READ;
			sub_mref->ref_data = NULL;

			sub_mref_a = trans_logger_mref_get_aspect(brick, sub_mref);
			CHECK_PTR(sub_mref_a, err);

			sub_mref_a->my_input = read_input;
			sub_mref_a->log_input = log_input;
			sub_mref_a->my_brick = brick;
			sub_mref_a->orig_rw = READ;
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

	/* Always create sub_mrefs for writeback (phase4)
	 */
	while (len > 0) {
		struct trans_logger_mref_aspect *sub_mref_a;
		struct mref_object *sub_mref;
		struct trans_logger_mref_aspect *orig_mref_a;
		struct mref_object *orig_mref;
		void *data;
		int this_len = len;
		int diff;
		int status;

		atomic_inc(&brick->total_hash_find_count);

		orig_mref_a = _hash_find(&wb->w_collect_list, pos, &this_len, elder, true);
		if (unlikely(!orig_mref_a)) {
			MARS_FAT("could not find data\n");
			goto err;
		}

		orig_mref = orig_mref_a->object;
		diff = pos - orig_mref->ref_pos;
		if (unlikely(diff < 0)) {
			MARS_FAT("bad diff %d\n", diff);
			goto err;
		}
		data = orig_mref_a->shadow_data + diff;

		sub_mref = trans_logger_alloc_mref(brick);
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

		sub_mref_a = trans_logger_mref_get_aspect(brick, sub_mref);
		CHECK_PTR(sub_mref_a, err);

		sub_mref_a->orig_mref_a = orig_mref_a;
		sub_mref_a->my_input = write_input;
		sub_mref_a->log_input = log_input;
		sub_mref_a->my_brick = brick;
		sub_mref_a->orig_rw = WRITE;
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
		wb->w_error = -EINVAL;
		free_writeback(wb);
	}
	return NULL;
}

static inline
void _fire_one(struct list_head *tmp, bool do_update)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct mref_object *sub_mref;
	struct trans_logger_input *sub_input;
	struct trans_logger_input *log_input;
	
	sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
	sub_mref = sub_mref_a->object;

	if (unlikely(sub_mref_a->is_fired)) {
		MARS_ERR("trying to fire twice\n");
		return;
	}
	sub_mref_a->is_fired = true;

	SETUP_CALLBACK(sub_mref, wb_endio, sub_mref_a);

	sub_input = sub_mref_a->my_input;
	log_input = sub_mref_a->log_input;

	if (do_update) {
		struct trans_logger_mref_aspect *orig_mref_a = sub_mref_a->orig_mref_a;
		if (unlikely(!orig_mref_a)) {
			MARS_ERR("internal problem\n");
		} else {
			loff_t max_pos = orig_mref_a->log_pos;
			if (log_input->replay_max_pos < max_pos) {
				log_input->replay_max_pos = max_pos;
			}
		}
	}

#ifdef DO_WRITEBACK
	GENERIC_INPUT_CALL(sub_input, mref_io, sub_mref);
#else
	SIMPLE_CALLBACK(sub_mref, 0);
#endif
	if (do_update) { // CHECK: shouldnt we do this always?
		GENERIC_INPUT_CALL(sub_input, mref_put, sub_mref);
	}
}

static inline
void fire_writeback(struct list_head *start, bool do_update)
{
	struct list_head *tmp;

	/* Caution! The wb structure may get deallocated
	 * during _fire_one() in some cases (e.g. when the
	 * callback is directly called by the mref_io operation).
	 * Ensure that no ptr dereferencing can take
	 * place after working on the last list member.
	 */
	tmp = start->next;
	while (tmp != start) {
		struct list_head *next = tmp->next;
		list_del_init(tmp);
		_fire_one(tmp, do_update);
		tmp = next;
	}
}

////////////////////////////// worker thread //////////////////////////////

/********************************************************************* 
 * Phase 1: write transaction log entry for the original write request.
 */

static noinline
void _complete(struct trans_logger_brick *brick, struct trans_logger_mref_aspect *orig_mref_a, int error, bool pre_io)
{
	struct mref_object *orig_mref;

	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);

	if (orig_mref_a->is_completed || 
	   (pre_io &&
	    (brick->completion_semantics >= 2 ||
	     (brick->completion_semantics >= 1 && !orig_mref->ref_skip_sync)))) {
		goto done;
	}

	orig_mref_a->is_completed = true;
	if (likely(error >= 0)) {
		orig_mref->ref_flags &= ~MREF_WRITING;
		orig_mref->ref_flags |= MREF_UPTODATE;
	}
	CHECKED_CALLBACK(orig_mref, error, err);

done:
	return;

err: 
	MARS_ERR("giving up...\n");
}

static noinline
void phase1_preio(void *private)
{
	struct trans_logger_mref_aspect *orig_mref_a;
	struct trans_logger_brick *brick;

	orig_mref_a = private;
	CHECK_PTR(orig_mref_a, err);
	brick = orig_mref_a->my_brick;
	CHECK_PTR(brick, err);

	// signal completion to the upper layer
	// FIXME: immediate error signalling is impossible here, but some delayed signalling should be possible as a workaround. Think!
	CHECK_ATOMIC(&orig_mref_a->object->ref_count, 1);
#ifdef EARLY_COMPLETION
	_complete(brick, orig_mref_a, 0, true);
	CHECK_ATOMIC(&orig_mref_a->object->ref_count, 1);
#endif
	return;
err: 
	MARS_ERR("giving up...\n");
}

static noinline
void phase1_endio(void *private, int error)
{
	struct mref_object *orig_mref;
	struct trans_logger_mref_aspect *orig_mref_a;
	struct trans_logger_brick *brick;

	orig_mref_a = private;
	CHECK_PTR(orig_mref_a, err);
	brick = orig_mref_a->my_brick;
	CHECK_PTR(brick, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);

	qq_dec_flying(&brick->q_phase1);

	/* Pin mref->ref_count so it can't go away
	 * after _complete().
	 */
	CHECK_ATOMIC(&orig_mref->ref_count, 1);
	_CHECK(orig_mref_a->shadow_ref, err);
	atomic_inc(&orig_mref->ref_count); // must be paired with __trans_logger_ref_put()
	atomic_inc(&brick->inner_balance_count);

#ifndef LATE_COMPLETE
	// signal completion to the upper layer
	_complete(brick, orig_mref_a, error, false);
#endif

	/* Queue up for the next phase.
	 */
	qq_mref_insert(&brick->q_phase2, orig_mref_a);

	/* Undo the above pinning
	 */
	__trans_logger_ref_put(brick, orig_mref_a);

	wake_up_interruptible_all(&brick->worker_event);
	return;
err: 
	MARS_ERR("giving up...\n");
}

static noinline
bool phase1_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_brick *brick;
	struct trans_logger_input *input;
	struct log_status *logst;
	void *data;
	unsigned long flags;
	bool ok;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	brick = orig_mref_a->my_brick;
	CHECK_PTR(brick, err);
	input = brick->inputs[brick->log_input_nr];
	CHECK_PTR(input, err);
	orig_mref_a->log_input = input;
	logst = &input->logst;

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

	ok = log_finalize(logst, orig_mref->ref_len, phase1_preio, phase1_endio, orig_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	orig_mref_a->log_pos = logst->log_pos + logst->offset;

	traced_lock(&input->pos_lock, flags);
#if 1
	if (!list_empty(&input->pos_list)) {
		struct trans_logger_mref_aspect *last_mref_a;
		last_mref_a = container_of(input->pos_list.prev, struct trans_logger_mref_aspect, pos_head);
		if (last_mref_a->log_pos >= orig_mref_a->log_pos) {
			MARS_ERR("backskip in pos_list, %lld >= %lld\n", last_mref_a->log_pos, orig_mref_a->log_pos);
		}
	}
#endif
	list_add_tail(&orig_mref_a->pos_head, &input->pos_list);
	atomic_inc(&brick->pos_count);
	traced_unlock(&input->pos_lock, flags);

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
	struct trans_logger_brick *brick;

	CHECK_PTR(mref, err);
	shadow_a = mref_a->shadow_ref;
	CHECK_PTR(shadow_a, err);
	brick = mref_a->my_brick;
	CHECK_PTR(brick, err);

	MARS_IO("pos = %lld len = %d rw = %d\n", mref->ref_pos, mref->ref_len, mref->ref_rw);

	if (mref->ref_rw == READ) {
		// nothing to do: directly signal success.
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
		mref->ref_flags |= MREF_UPTODATE;

		CHECKED_CALLBACK(mref, 0, err);

		__trans_logger_ref_put(brick, mref_a);

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
	if (likely(!mref_a->is_hashed)) {
		MARS_IO("hashing %d at %lld\n", mref->ref_len, mref->ref_pos);
		hash_insert(brick, mref_a);
	} else {
		MARS_ERR("tried to hash twice\n");
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
	struct trans_logger_brick *brick;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	qq_dec_flying(&brick->q_phase2);

	// queue up for the next phase
	qq_wb_insert(&brick->q_phase3, wb);
	wake_up_interruptible_all(&brick->worker_event);
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
	struct trans_logger_brick *brick;
	struct writeback_info *wb = NULL;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	brick = orig_mref_a->my_brick;
	CHECK_PTR(brick, err);

	if (orig_mref_a->is_collected) {
		MARS_IO("already collected, pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len);
		goto done;
	}
	if (!orig_mref_a->is_hashed) {
		MARS_IO("AHA not hashed, pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len);
		goto done;
	}

	wb = make_writeback(brick, orig_mref->ref_pos, orig_mref->ref_len, &orig_mref_a->stamp, orig_mref_a->log_input);
	if (unlikely(!wb)) {
		MARS_ERR("no mem\n");
		goto err;
	}

#ifdef LATE_COMPLETE
	// signal completion to the upper layer
	_complete(brick, orig_mref_a, 0, false);
#endif

	if (unlikely(list_empty(&wb->w_collect_list))) {
		MARS_ERR("collection list is empty, orig pos = %lld len = %d (collected=%d), extended pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len, (int)orig_mref_a->is_collected, wb->w_pos, wb->w_len);
		goto err;
	}
	if (unlikely(list_empty(&wb->w_sub_write_list))) {
		MARS_ERR("hmmm.... this should not happen\n");
		goto err;
	}

	wb->read_endio = phase2_endio;
	wb->write_endio = phase4_endio;
	atomic_set(&wb->w_sub_log_count, atomic_read(&wb->w_sub_read_count));

	if (brick->log_reads) {
		qq_inc_flying(&brick->q_phase2);
		fire_writeback(&wb->w_sub_read_list, false);
	} else { // shortcut
#ifdef LATER
		qq_wb_insert(&brick->q_phase4, wb);
		wake_up_interruptible_all(&brick->worker_event);
#else
		return phase4_startio(wb);
#endif
	}

 done:
	return true;
	
 err:
	if (wb) {
		wb->w_error = -EINVAL;
		free_writeback(wb);
	}
	return false;
}


/********************************************************************* 
 * Phase 3: log the old disk version.
 */

static inline
void _phase3_endio(struct writeback_info *wb)
{
	struct trans_logger_brick *brick = wb->w_brick;
	
	// queue up for the next phase
	qq_wb_insert(&brick->q_phase4, wb);
	wake_up_interruptible_all(&brick->worker_event);
	return;
}

static noinline
void phase3_endio(void *private, int error)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;

	sub_mref_a = private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
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
	struct trans_logger_brick *brick;
	struct log_status *logst;
	void *data;
	bool ok;

	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);
	input = sub_mref_a->log_input;
	CHECK_PTR(input, err);
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

	ok = log_finalize(logst, sub_mref->ref_len, NULL, phase3_endio, sub_mref_a);
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
	struct trans_logger_brick *brick;
	bool ok = true;

	CHECK_PTR(wb, err);
	brick = wb->w_brick;
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
		wake_up_interruptible_all(&brick->worker_event);
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
	struct trans_logger_brick *brick;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	hash_put_all(brick, &wb->w_collect_list);

	qq_dec_flying(&brick->q_phase4);
	atomic_inc(&brick->total_writeback_cluster_count);

	free_writeback(wb);

	wake_up_interruptible_all(&brick->worker_event);

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
	qq_inc_flying(&wb->w_brick->q_phase4);
	fire_writeback(&wb->w_sub_write_list, true);
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
		__trans_logger_ref_put(mref_a->my_brick, mref_a);
	} while (--max > 0);
	res = 0;

done:
	if (found) {
		wake_up_interruptible_all(&brick->worker_event);
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
		wake_up_interruptible_all(&brick->worker_event);
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

static inline
bool logst_is_ready(struct trans_logger_brick *brick)
{
	int nr = brick->log_input_nr;
	struct trans_logger_input *input = brick->inputs[nr];
	struct log_status *logst = &input->logst;
	return is_log_ready(logst);
}

/* The readyness of the queues is volatile (may change underneath due
 * to interrupts etc).
 * In order to get consistency during one round of the loop in
 * trans_logger_log(), we capture the status exactly once and
 * use the captured status during processing.
 */
struct condition_status {
	bool log_ready;
	bool q1_ready;
	bool q2_ready;
	bool q3_ready;
	bool q4_ready;
	bool extra_ready;
	bool some_ready;
};

static noinline
bool _condition(struct condition_status *st, struct trans_logger_brick *brick)
{
	st->log_ready = logst_is_ready(brick);
	st->q1_ready = atomic_read(&brick->q_phase1.q_queued) > 0 &&
		st->log_ready;
	st->q2_ready = qq_is_ready(&brick->q_phase2);
	st->q3_ready = qq_is_ready(&brick->q_phase3);
	st->q4_ready = qq_is_ready(&brick->q_phase4);
	st->extra_ready = (kthread_should_stop() && !_congested(brick));
	st->some_ready = st->q1_ready | st->q2_ready | st->q3_ready | st->q4_ready | st->extra_ready;
#if 0
	if (!st->some_ready)
		st->q1_ready = atomic_read(&brick->q_phase1.q_queued) > 0;
#endif
	return st->some_ready;
}

static
void _init_input(struct trans_logger_input *input)
{
	struct trans_logger_brick *brick = input->brick;
	struct log_status *logst = &input->logst;
	loff_t start_pos = input->log_start_pos;

	init_logst(logst, (void*)input, 0);
	logst->align_size = brick->align_size;
	logst->chunk_size = brick->chunk_size;
	logst->max_flying = brick->max_flying;
	
	input->replay_min_pos = start_pos;
	input->replay_max_pos = start_pos; // FIXME: Theoretically, this could be wrong when starting on an interrupted replay / inconsistent system. However, we normally never start ordinary logging in such a case (possibly except some desperate emergency cases when there really is no other chance, such as physical loss of transaction logs). Nevertheless, better use old consistenty information from the FS here.
	logst->log_pos = start_pos;
	input->is_operating = true;
}

static
void _init_inputs(struct trans_logger_brick *brick)
{
	struct trans_logger_input *input;
	int nr = brick->new_input_nr;

	if (brick->log_input_nr != brick->old_input_nr) {
		MARS_IO("nothing to do, new_input_nr = %d log_input_nr = %d old_input_nr = %d\n", brick->new_input_nr, brick->log_input_nr, brick->old_input_nr);
		goto done;
	}
	if (unlikely(nr < TL_INPUT_LOG1 || nr > TL_INPUT_LOG2)) {
		MARS_ERR("bad new_input_nr = %d\n", nr);
		goto done;
	}

	input = brick->inputs[nr];
	CHECK_PTR(input, done);

	if (input->is_operating || !input->connect) {
		MARS_IO("cannot yet switch over to %d (is_operating = %d connect = %p)\n", nr, input->is_operating, input->connect);
		goto done;
	}

	_init_input(input);
	brick->log_input_nr = nr;
	MARS_INF("switching over to new logfile %d (old = %d) startpos = %lld\n", nr, brick->old_input_nr, input->log_start_pos);
done: ;
}

static
void _flush_inputs(struct trans_logger_brick *brick)
{
	int i;
	for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
		struct trans_logger_input *input = brick->inputs[i];
		struct log_status *logst = &input->logst;
		if (input->is_operating && logst->count > 0) {
			atomic_inc(&brick->total_flush_count);
			log_flush(logst);
		}
	}
}

static
void _exit_inputs(struct trans_logger_brick *brick, bool force)
{
	int i;
	for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
		struct trans_logger_input *input = brick->inputs[i];
		struct log_status *logst = &input->logst;
		if (force ||
		    (input->is_operating &&!input->connect)) {
			MARS_DBG("cleaning up input %d (log = %d old = %d)\n", i, brick->log_input_nr, brick->old_input_nr);
			exit_logst(logst);
			input->is_operating = false;
			if (i == brick->old_input_nr)
				brick->old_input_nr = brick->log_input_nr;
		}
	}
}

static noinline
void trans_logger_log(struct trans_logger_brick *brick)
{
#ifdef DELAY_CALLERS
	bool unlimited = false;
	bool old_unlimited = false;
	bool delay_callers;
#endif
	long wait_timeout = HZ;
#ifdef  STAT_DEBUGGING
	long long last_jiffies = jiffies;
#endif
#if 1
	int max_delta = 0;
#endif

	_init_inputs(brick);

	mars_power_led_on((void*)brick, true);

	while (!kthread_should_stop() || _congested(brick)) {
		long long old_jiffies = jiffies;
		long old_wait_timeout;
		bool do_flush;
		struct condition_status st = {};
#if 1
		long long j0;
		long long j1;
		long long j2;
		long long j3;
		long long j4;
#endif

#if 1
		schedule(); // yield
#endif
		MARS_IO("waiting for request\n");

		__wait_event_interruptible_timeout(
			brick->worker_event,
			_condition(&st, brick),
			wait_timeout);

		atomic_inc(&brick->total_round_count);

		_init_inputs(brick);

#if 1
		j0 = jiffies;
#endif

		//MARS_DBG("AHA %d\n", atomic_read(&brick->q_phase1.q_queued));

#ifdef STAT_DEBUGGING
		if (((long long)jiffies) - last_jiffies >= HZ * 5 && brick->power.button) {
			char *txt;
			last_jiffies = jiffies;
			txt = brick->ops->brick_statistics(brick, 0);
			if (txt) {
				MARS_INF("log_ready = %d q1_ready = %d q2_ready = %d q3_ready = %d q4_ready = %d extra_ready = %d some_ready = %d || %s", st.q1_ready, st.log_ready, st.q2_ready, st.q3_ready, st.q4_ready, st.extra_ready, st.some_ready, txt);
				brick_string_free(txt);
			}
		}
#endif
		brick->did_pushback = false;
		brick->did_work = false;

		/* This is highest priority, do it first.
		 */
		if (st.q1_ready) {
			run_mref_queue(&brick->q_phase1, phase0_startio, brick->q_phase1.q_batchlen);
		}
		j1 = jiffies;

		/* In order to speed up draining, check the other queues
		 * in backward direction.
		 */
		/* FIXME: in order to avoid deadlock, q4_ready _must not_
		 * cylically depend from q1 (which is currently the case).
		 * However, for performance reasons q4 should be slowed down
		 * when q1 is too much contended.
		 * Solution: distinguish between hard start/stop and
		 * soft rate (or rate balance).
		 */
		if (true || st.q4_ready) {
			run_wb_queue(&brick->q_phase4, phase4_startio, brick->q_phase4.q_batchlen);
		}
		j2 = jiffies;

		if (true || st.q3_ready) {
			run_wb_queue(&brick->q_phase3, phase3_startio, brick->q_phase3.q_batchlen);
		}
		j3 = jiffies;

		/* FIXME: can also lead to deadlock.
		 * Scheduling should be done by balancing, not completely
		 * stopping individual queues!
		 */
		if (true || st.q2_ready) {
			run_mref_queue(&brick->q_phase2, phase2_startio, brick->q_phase2.q_batchlen);
		}
		j4 = jiffies;

		/* A kind of delayed plugging mechanism
		 */
		old_wait_timeout = wait_timeout;
		wait_timeout = HZ / 10; // 100ms before flushing
#ifdef CONFIG_MARS_DEBUG // debug override for catching long blocks
		//wait_timeout = 16 * HZ;
#endif
		/* Calling log_flush() too often may result in
		 * increased overhead (and thus in lower throughput).
		 * OTOH, calling it too seldom may hold back
		 * IO completion for the end user for some time.
		 * Play around with wait_timeout to optimize this.
		 */
		do_flush = false;
		if (brick->did_work) {
			atomic_inc(&brick->total_restart_count);
			do_flush = !brick->flush_delay;
			if (!do_flush) { // start over soon
				wait_timeout = brick->flush_delay;
			}
		} else if (atomic_read(&brick->q_phase1.q_queued) <= 0 &&
			  (brick->minimize_latency || (long long)jiffies - old_jiffies >= old_wait_timeout)) {
			do_flush = true;
		}
#if 1
		do_flush = true;
#endif
		if (do_flush) {
			_flush_inputs(brick);
		}
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

		if (st.some_ready && !brick->did_work) {
			char *txt;
			txt = brick->ops->brick_statistics(brick, 0);
			MARS_WRN("inconsistent work, pushback = %d q1 = %d q2 = %d q3 = %d q4 = %d extra = %d ====> %s\n", brick->did_pushback, st.q1_ready, st.q2_ready, st.q3_ready, st.q4_ready, st.extra_ready, txt ? txt : "(ERROR)");
			if (txt) {
				brick_string_free(txt);
			}
		}
#endif
#ifdef DELAY_CALLERS // provisionary flood handling FIXME: do better
#define LIMIT_FN(factor,divider)					\
		(atomic_read(&brick->mshadow_count) > brick->shadow_mem_limit  * (factor) / (divider) && brick->shadow_mem_limit > 16) || \
		(atomic64_read(&brick->shadow_mem_used) > brick_global_memlimit  * (factor) / (divider) && brick_global_memlimit > PAGE_SIZE * 16)

		delay_callers = LIMIT_FN(1, 1);
		if (delay_callers != brick->delay_callers) {
			MARS_DBG("mshadow_count = %d/%d global_mem = %ld/%lld stalling %d -> %d\n", atomic_read(&brick->mshadow_count), brick->shadow_mem_limit, atomic64_read(&brick->shadow_mem_used), brick_global_memlimit, brick->delay_callers, delay_callers);
			brick->delay_callers = delay_callers;
			wake_up_interruptible_all(&brick->worker_event);
			wake_up_interruptible_all(&brick->caller_event);
			if (delay_callers)
				atomic_inc(&brick->total_delay_count);
		}
		if (unlimited) {
			unlimited = LIMIT_FN(3, 8);
		} else {
			unlimited = LIMIT_FN(1, 2);
		}
		if (unlimited != old_unlimited) {
			brick->q_phase2.q_unlimited = unlimited;
			brick->q_phase3.q_unlimited = unlimited;
			brick->q_phase4.q_unlimited = unlimited;
			MARS_DBG("mshadow_count = %d/%d global_mem = %ld/%lld unlimited %d -> %d\n", atomic_read(&brick->mshadow_count), brick->shadow_mem_limit, atomic64_read(&brick->shadow_mem_used), brick_global_memlimit, old_unlimited, unlimited);
			old_unlimited = unlimited;
			wake_up_interruptible_all(&brick->worker_event);
			wake_up_interruptible_all(&brick->caller_event);
		}
#endif
		_exit_inputs(brick, false);
	}
	_exit_inputs(brick, true);
}

////////////////////////////// log replay //////////////////////////////

static noinline
void replay_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *mref_a = cb->cb_private;
	struct trans_logger_brick *brick;
	unsigned long flags;

	CHECK_PTR(mref_a, err);
	brick = mref_a->my_brick;
	CHECK_PTR(brick, err);

	if (unlikely(cb->cb_error < 0)) {
		MARS_ERR("IO error = %d\n", cb->cb_error);
		goto done;
	}

	traced_lock(&brick->replay_lock, flags);
	list_del_init(&mref_a->replay_head);
	traced_unlock(&brick->replay_lock, flags);

	atomic_dec(&brick->replay_count);
 done:
	wake_up_interruptible_all(&brick->worker_event);
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
		if (tmp_mref->ref_pos + tmp_mref->ref_len > mref->ref_pos && tmp_mref->ref_pos < mref->ref_pos + mref->ref_len) {
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
	const int max = 512; // limit parallelism somewhat
	int conflicts = 0;
	bool ok = false;
	unsigned long flags;

	wait_event_interruptible_timeout(brick->worker_event,
					 atomic_read(&brick->replay_count) < max
					 && (_has_conflict(brick, mref_a) ? conflicts++ : (ok = true), ok),
					 60 * HZ);

	atomic_inc(&brick->replay_count);
	atomic_inc(&brick->total_replay_count);
	if (conflicts)
		atomic_inc(&brick->total_replay_conflict_count);

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
		
		status = -ENOMEM;
		mref = trans_logger_alloc_mref(brick);
		if (unlikely(!mref)) {
			MARS_ERR("no memory\n");
			goto done;
		}
		mref_a = trans_logger_mref_get_aspect(brick, mref);
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

		SETUP_CALLBACK(mref, replay_endio, mref_a);
		mref_a->my_brick = brick;

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
void trans_logger_replay(struct trans_logger_brick *brick)
{
	struct trans_logger_input *input = brick->inputs[brick->log_input_nr];
	loff_t start_pos;
	loff_t finished_pos;
	long long old_jiffies = jiffies;
	int backoff = 0;
	int status = 0;

	brick->replay_code = 0; // indicates "running"

	start_pos = brick->replay_start_pos;
	init_logst(&input->logst, (void*)input, start_pos);
	input->logst.align_size = brick->align_size;
	input->logst.chunk_size = brick->chunk_size;

	MARS_INF("starting replay from %lld to %lld\n", start_pos, brick->replay_end_pos);
	
	input->replay_min_pos = start_pos;
	input->replay_max_pos = start_pos; // FIXME: this is wrong.

	mars_power_led_on((void*)brick, true);

	for (;;) {
		loff_t new_finished_pos;
		struct log_header lh = {};
		void *buf = NULL;
		int len = 0;

		finished_pos = input->logst.log_pos + input->logst.offset;
		if (kthread_should_stop() ||
		   (!brick->do_continuous_replay && finished_pos >= brick->replay_end_pos)) {
			status = 0; // treat as EOF
			break;
		}

		status = log_read(&input->logst, &lh, &buf, &len);
		if (status == -EAGAIN) {
			MARS_DBG("got -EAGAIN\n");
			msleep(backoff);
			if (backoff < 3000) {
				backoff += 100;
			} else {
				MARS_WRN("logfile replay not possible at position %lld (end_pos = %lld, remaining = %lld), please check/repair your logfile in userspace by some tool!\n", finished_pos, brick->replay_end_pos, brick->replay_end_pos - finished_pos);
			}
			continue;
		}
		if (unlikely(status < 0)) {
			brick->replay_code = status;
			MARS_WRN("cannot read logfile data, status = %d\n", status);
			break;
		}

		new_finished_pos = input->logst.log_pos + input->logst.offset;
		MARS_RPL("read  %lld %lld\n", finished_pos, new_finished_pos);
		
		if ((!status && len <= 0) ||
		   new_finished_pos > brick->replay_end_pos) { // EOF -> wait until kthread_should_stop()
			MARS_DBG("EOF at %lld (old = %lld, end_pos = %lld)\n", new_finished_pos, finished_pos, brick->replay_end_pos);
			if (!brick->do_continuous_replay) {
				// notice: finished_pos remains at old value here!
				brick->replay_end_pos = finished_pos;
				break;
			}
			msleep(1000);
			continue;
		}

		if (lh.l_code != CODE_WRITE_NEW) {
			MARS_IO("ignoring pos = %lld len = %d code = %d\n", lh.l_pos, lh.l_len, lh.l_code);
		} else if (likely(buf && len)) {
			status = apply_data(brick, lh.l_pos, buf, len);
			MARS_RPL("apply %lld %lld (pos=%lld status=%d)\n", finished_pos, new_finished_pos, lh.l_pos, status);
			if (unlikely(status < 0)) {
				brick->replay_code = status;
				MARS_ERR("cannot apply data at pos = %lld len = %d, status = %d\n", lh.l_pos, len, status);
				break;
			} else {
				finished_pos = new_finished_pos;
			}
		}

		// do this _after_ any opportunities for errors...
		if (atomic_read(&brick->replay_count) <= 0 || ((long long)jiffies) - old_jiffies >= HZ * 5) {
			input->replay_min_pos = finished_pos;
			input->replay_max_pos = finished_pos; // FIXME
			old_jiffies = jiffies;
		}
		_exit_inputs(brick, false);
	}

	MARS_INF("waiting for finish...\n");

	wait_event_interruptible_timeout(brick->worker_event, atomic_read(&brick->replay_count) <= 0, 60 * HZ);

	if (unlikely(finished_pos > brick->replay_end_pos)) {
		MARS_ERR("finished_pos too large: %lld + %d = %lld > %lld\n", input->logst.log_pos, input->logst.offset, finished_pos, brick->replay_end_pos);
		finished_pos = brick->replay_end_pos;
	}
	if (status >= 0) {
		input->replay_min_pos = finished_pos;
		input->replay_max_pos = finished_pos; // FIXME
	}

	if (status >= 0 && finished_pos == brick->replay_end_pos) {
		MARS_INF("replay finished at %lld\n", finished_pos);
		brick->replay_code = 1;
	} else {
		MARS_INF("replay stopped prematurely at %lld (of %lld)\n", finished_pos, brick->replay_end_pos);
		brick->replay_code = 2;
	}

	_exit_inputs(brick, true);

	mars_trigger();

	while (!kthread_should_stop()) {
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
		trans_logger_replay(brick);
	} else {
		trans_logger_log(brick);
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
			MARS_INF("stopping thread...\n");
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
	char *res = brick_string_alloc(1024);
	if (!res)
		return NULL;

	snprintf(res, 1023,
		 "mode replay=%d "
		 "continuous=%d "
		 "replay_code=%d "
		 "log_reads=%d | "
		 "replay_start_pos = %lld "
		 "replay_end_pos = %lld | "
		 "new_input_nr = %d "
		 "log_input_nr = %d "
		 "(old = %d) "
		 "replay_min_pos1 = %lld "
		 "replay_max_pos1 = %lld "
		 "replay_min_pos2 = %lld "
		 "replay_max_pos2 = %lld | "
		 "total hash_insert=%d "
		 "hash_find=%d "
		 "hash_extend=%d "
		 "replay=%d "
		 "replay_conflict=%d  (%d%%) "
		 "callbacks=%d "
		 "reads=%d "
		 "writes=%d "
		 "flushes=%d (%d%%) "
		 "wb_clusters=%d "
		 "writebacks=%d (%d%%) "
		 "shortcut=%d (%d%%) "
		 "mshadow=%d "
		 "sshadow=%d "
		 "mshadow_buffered=%d sshadow_buffered=%d "
		 "rounds=%d "
		 "restarts=%d "
		 "delays=%d "
		 "phase1=%d "
		 "phase2=%d "
		 "phase3=%d "
		 "phase4=%d | "
		 "current #mrefs = %d "
		 "shadow_mem_used=%ld/%lld "
		 "replay_count=%d "
		 "mshadow=%d/%d "
		 "sshadow=%d "
		 "hash_count=%d "
		 "pos_count=%d "
		 "balance=%d/%d/%d/%d "
		 "fly=%d "
		 "phase1=%d+%d "
		 "phase2=%d+%d "
		 "phase3=%d+%d "
		 "phase4=%d+%d\n",
		 brick->do_replay,
		 brick->do_continuous_replay,
		 brick->replay_code,
		 brick->log_reads,
		 brick->replay_start_pos,
		 brick->replay_end_pos,
		 brick->new_input_nr,
		 brick->log_input_nr,
		 brick->old_input_nr,
		 brick->inputs[TL_INPUT_LOG1]->replay_min_pos,
		 brick->inputs[TL_INPUT_LOG1]->replay_max_pos, 
		 brick->inputs[TL_INPUT_LOG2]->replay_min_pos,
		 brick->inputs[TL_INPUT_LOG2]->replay_max_pos, 
		 atomic_read(&brick->total_hash_insert_count),
		 atomic_read(&brick->total_hash_find_count),
		 atomic_read(&brick->total_hash_extend_count),
		 atomic_read(&brick->total_replay_count),
		 atomic_read(&brick->total_replay_conflict_count),
		 atomic_read(&brick->total_replay_count) ? atomic_read(&brick->total_replay_conflict_count) * 100 / atomic_read(&brick->total_replay_count) : 0,
		 atomic_read(&brick->total_cb_count),
		 atomic_read(&brick->total_read_count),
		 atomic_read(&brick->total_write_count),
		 atomic_read(&brick->total_flush_count),
		 atomic_read(&brick->total_write_count) ? atomic_read(&brick->total_flush_count) * 100 / atomic_read(&brick->total_write_count) : 0,
		 atomic_read(&brick->total_writeback_cluster_count),
		 atomic_read(&brick->total_writeback_count),
		 atomic_read(&brick->total_writeback_cluster_count) ? atomic_read(&brick->total_writeback_count) * 100 / atomic_read(&brick->total_writeback_cluster_count) : 0,
		 atomic_read(&brick->total_shortcut_count),
		 atomic_read(&brick->total_writeback_count) ? atomic_read(&brick->total_shortcut_count) * 100 / atomic_read(&brick->total_writeback_count) : 0,
		 atomic_read(&brick->total_mshadow_count),
		 atomic_read(&brick->total_sshadow_count),
		 atomic_read(&brick->total_mshadow_buffered_count),
		 atomic_read(&brick->total_sshadow_buffered_count),
		 atomic_read(&brick->total_round_count),
		 atomic_read(&brick->total_restart_count),
		 atomic_read(&brick->total_delay_count),
		 atomic_read(&brick->q_phase1.q_total),
		 atomic_read(&brick->q_phase2.q_total),
		 atomic_read(&brick->q_phase3.q_total),
		 atomic_read(&brick->q_phase4.q_total),
		 atomic_read(&brick->mref_object_layout.alloc_count),
		 atomic64_read(&brick->shadow_mem_used),
		 brick_global_memlimit,
		 atomic_read(&brick->replay_count),
		 atomic_read(&brick->mshadow_count),
		 brick->shadow_mem_limit,
		 atomic_read(&brick->sshadow_count),
		 atomic_read(&brick->hash_count),
		 atomic_read(&brick->pos_count),
		 atomic_read(&brick->sub_balance_count),
		 atomic_read(&brick->inner_balance_count),
		 atomic_read(&brick->outer_balance_count),
		 atomic_read(&brick->wb_balance_count),
		 atomic_read(&brick->fly_count),
		 atomic_read(&brick->q_phase1.q_queued),
		 atomic_read(&brick->q_phase1.q_flying),
		 atomic_read(&brick->q_phase2.q_queued),
		 atomic_read(&brick->q_phase2.q_flying),
		 atomic_read(&brick->q_phase3.q_queued),
		 atomic_read(&brick->q_phase3.q_flying),
		 atomic_read(&brick->q_phase4.q_queued),
		 atomic_read(&brick->q_phase4.q_flying));
	return res;
}

static noinline
void trans_logger_reset_statistics(struct trans_logger_brick *brick)
{
	atomic_set(&brick->total_hash_insert_count, 0);
	atomic_set(&brick->total_hash_find_count, 0);
	atomic_set(&brick->total_hash_extend_count, 0);
	atomic_set(&brick->total_replay_count, 0);
	atomic_set(&brick->total_replay_conflict_count, 0);
	atomic_set(&brick->total_cb_count, 0);
	atomic_set(&brick->total_read_count, 0);
	atomic_set(&brick->total_write_count, 0);
	atomic_set(&brick->total_flush_count, 0);
	atomic_set(&brick->total_writeback_count, 0);
	atomic_set(&brick->total_writeback_cluster_count, 0);
	atomic_set(&brick->total_shortcut_count, 0);
	atomic_set(&brick->total_mshadow_count, 0);
	atomic_set(&brick->total_sshadow_count, 0);
	atomic_set(&brick->total_mshadow_buffered_count, 0);
	atomic_set(&brick->total_sshadow_buffered_count, 0);
	atomic_set(&brick->total_round_count, 0);
	atomic_set(&brick->total_restart_count, 0);
	atomic_set(&brick->total_delay_count, 0);
}


//////////////// object / aspect constructors / destructors ///////////////

static noinline
int trans_logger_mref_aspect_init_fn(struct generic_aspect *_ini)
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
void trans_logger_mref_aspect_exit_fn(struct generic_aspect *_ini)
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
		init_rwsem(&start->hash_mutex);
		INIT_LIST_HEAD(&start->hash_anchor);
	}
	atomic_set(&brick->hash_count, 0);
	spin_lock_init(&brick->replay_lock);
	INIT_LIST_HEAD(&brick->replay_list);
	init_waitqueue_head(&brick->worker_event);
	init_waitqueue_head(&brick->caller_event);
	qq_init(&brick->q_phase1, brick);
	qq_init(&brick->q_phase2, brick);
	qq_init(&brick->q_phase3, brick);
	qq_init(&brick->q_phase4, brick);
#if 1
	brick->q_phase2.q_dep = &brick->q_phase4;
	/* TODO: this is cyclic and therefore potentially dangerous.
	 * Find a better solution to the starvation problem!
	 */
	//brick->q_phase4.q_dep = &brick->q_phase1;
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
	brick->new_input_nr = TL_INPUT_LOG1;
	brick->log_input_nr = TL_INPUT_LOG1;
	brick->old_input_nr = TL_INPUT_LOG1;
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
	spin_lock_init(&input->pos_lock);
	INIT_LIST_HEAD(&input->pos_list);
	return 0;
}

static noinline
int trans_logger_input_destruct(struct trans_logger_input *input)
{
	CHECK_HEAD_EMPTY(&input->pos_list);
	brick_string_free(input->inf_host);
	input->inf_host = NULL;
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct trans_logger_brick_ops trans_logger_brick_ops = {
	.brick_switch = trans_logger_switch,
	.brick_statistics = trans_logger_statistics,
	.reset_statistics = trans_logger_reset_statistics,
};

static struct trans_logger_output_ops trans_logger_output_ops = {
	.mars_get_info = trans_logger_get_info,
	.mref_get = trans_logger_ref_get,
	.mref_put = trans_logger_ref_put,
	.mref_io = trans_logger_ref_io,
};

const struct trans_logger_input_type trans_logger_input_type = {
	.type_name = "trans_logger_input",
	.input_size = sizeof(struct trans_logger_input),
	.input_construct = &trans_logger_input_construct,
	.input_destruct = &trans_logger_input_destruct,
};

static const struct trans_logger_input_type *trans_logger_input_types[] = {
	&trans_logger_input_type,
	&trans_logger_input_type,
	&trans_logger_input_type,
	&trans_logger_input_type,
	&trans_logger_input_type,
	&trans_logger_input_type,
};

const struct trans_logger_output_type trans_logger_output_type = {
	.type_name = "trans_logger_output",
	.output_size = sizeof(struct trans_logger_output),
	.master_ops = &trans_logger_output_ops,
	.output_construct = &trans_logger_output_construct,
};

static const struct trans_logger_output_type *trans_logger_output_types[] = {
	&trans_logger_output_type,
};

const struct trans_logger_brick_type trans_logger_brick_type = {
	.type_name = "trans_logger_brick",
	.brick_size = sizeof(struct trans_logger_brick),
	.max_inputs = TL_INPUT_NR,
	.max_outputs = 1,
	.master_ops = &trans_logger_brick_ops,
	.aspect_types = trans_logger_aspect_types,
	.default_input_types = trans_logger_input_types,
	.default_output_types = trans_logger_output_types,
	.brick_construct = &trans_logger_brick_construct,
};
EXPORT_SYMBOL_GPL(trans_logger_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_trans_logger(void)
{
	MARS_INF("init_trans_logger()\n");
	return trans_logger_register_brick_type();
}

void __exit exit_mars_trans_logger(void)
{
	MARS_INF("exit_trans_logger()\n");
	trans_logger_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS trans_logger brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_trans_logger);
module_exit(exit_mars_trans_logger);
#endif
