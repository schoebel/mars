// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING // here means: display full statistics

// variants
#define KEEP_UNIQUE
//#define USE_KMALLOC
//#define WB_COPY

// changing this is dangerous for data integrity! use only for testing!
#define USE_MEMCPY
#define USE_HIGHER_PHASES
#define APPLY_DATA

#define NEW_CODE

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

//QUEUE_FUNCTIONS(logger,struct trans_logger_mref_aspect,th.th_head,MREF_KEY_FN,th_cmp,mref);
QUEUE_FUNCTIONS(logger,struct logger_head,lh_head,lh_get,lh_cmp,logger);

////////////////////////// logger queue handling ////////////////////////

static inline
void qq_init(struct logger_queue *q, struct trans_logger_output *output)
{
	q_logger_init(q);
	q->q_output = output;
}

static noinline
bool qq_is_ready(struct logger_queue *q)
{
	struct logger_queue *dep;
	int queued = atomic_read(&q->q_queued);
	int contention;
	int max_contention;
	int over;
	int flying;
	bool res = false;

	/* 1) when empty, there is nothing to do.
	 */
	if (queued <= 0)
		goto always_done;

	/* compute some characteristic measures
	 */
	contention = atomic_read(&q->q_output->fly_count);
	if (q->q_dep_plus) {
		contention += atomic_read(q->q_dep_plus);
	}
	dep = q->q_dep;
	while (dep) {
		contention += atomic_read(&dep->q_queued) + atomic_read(&dep->q_flying);
		dep = dep->q_dep;
	}
	max_contention = q->q_max_contention;
	over = queued - q->q_max_queued;
	if (over > 0 && q->q_over_pressure > 0) {
		max_contention += over / q->q_over_pressure;
	}

#if 1
	/* 2) when other queues are too much contended,
	 * refrain from contending the IO system even more.
	 */
	if (contention > max_contention) {
		goto always_done;
	}
#endif

	/* 3) when the maximum queue length is reached, start IO.
	 */
	res = true;
	if (over > 0)
		goto limit;

	/* 4) also start IO when queued requests are too old
	 * (measured in realtime)
	 */
	if (q->q_max_jiffies > 0 &&
	   (long long)jiffies - q->q_last_insert >= q->q_max_jiffies)
		goto limit;

	/* 5) when no contention, start draining the queue.
	 */
	if (contention <= 0)
		goto limit;

	res = false;
	goto always_done;

limit:
	/* Limit the number of flying requests (parallelism)
	 */
	flying = atomic_read(&q->q_flying);
	if (q->q_max_flying > 0 && flying >= q->q_max_flying)
		res = false;

always_done:
	return res;
}

static inline
void qq_insert(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	CHECK_ATOMIC(&mref->ref_count, 1);
	atomic_inc(&mref->ref_count); // must be paired with __trans_logger_ref_put()
	atomic_inc(&q->q_output->inner_balance_count);

	mars_trace(mref, q->q_insert_info);

	q_logger_insert(q, &mref_a->lh);
}

static inline
void qq_pushback(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	CHECK_ATOMIC(&mref_a->object->ref_count, 1);

	mars_trace(mref_a->object, q->q_pushback_info);

	q_logger_pushback(q, &mref_a->lh);
}

static inline
struct trans_logger_mref_aspect *qq_fetch(struct logger_queue *q)
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
struct trans_logger_mref_aspect *hash_find(struct trans_logger_output *output, loff_t pos, int *max_len)
{
	int hash = hash_fn(pos);
	struct hash_anchor *start = &output->hash_table[hash];
	struct trans_logger_mref_aspect *res;
	unsigned int flags;

	traced_readlock(&start->hash_lock, flags);

	res = _hash_find(&start->hash_anchor, pos, max_len, false);

	traced_readunlock(&start->hash_lock, flags);

	return res;
}

static noinline
void hash_insert(struct trans_logger_output *output, struct trans_logger_mref_aspect *elem_a)
{
        int hash = hash_fn(elem_a->object->ref_pos);
        struct hash_anchor *start = &output->hash_table[hash];
        unsigned int flags;

#if 1
	CHECK_HEAD_EMPTY(&elem_a->hash_head);
	CHECK_ATOMIC(&elem_a->object->ref_count, 1);
#endif

	// only for statistics:
	atomic_inc(&output->hash_count);

        traced_writelock(&start->hash_lock, flags);

        list_add(&elem_a->hash_head, &start->hash_anchor);
	elem_a->is_hashed = true;

        traced_writeunlock(&start->hash_lock, flags);
}

/* Find the transitive closure of overlapping requests
 * and collect them into a list.
 */
static noinline
void hash_extend(struct trans_logger_output *output, loff_t *_pos, int *_len, struct list_head *collect_list)
{
	loff_t pos = *_pos;
	int len = *_len;
        int hash = hash_fn(pos);
        struct hash_anchor *start = &output->hash_table[hash];
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
void hash_put_all(struct trans_logger_output *output, struct list_head *list)
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
			start = &output->hash_table[hash];
			traced_writelock(&start->hash_lock, flags);
		} else if (unlikely(hash != first_hash)) {
			MARS_ERR("oops, different hashes: %d != %d\n", hash, first_hash);
		}
		
		if (!elem_a->is_hashed) {
			continue;
		}

		list_del_init(&elem_a->hash_head);
		elem_a->is_hashed = false;
		atomic_dec(&output->hash_count);
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
	struct trans_logger_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static noinline
int _make_sshadow(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a, struct trans_logger_mref_aspect *mshadow_a)
{
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
	mref_a->output = output;

	/* Get an ordinary internal reference
	 */
	atomic_inc(&mref->ref_count); // must be paired with __trans_logger_ref_put()
	atomic_inc(&output->inner_balance_count);

	/* Get an additional internal reference from slave to master,
	 * such that the master cannot go away before the slave.
	 */
	atomic_inc(&mshadow->ref_count);  // is compensated by master transition in __trans_logger_ref_put()
	atomic_inc(&output->inner_balance_count);

	atomic_inc(&output->sshadow_count);
	atomic_inc(&output->total_sshadow_count);
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
	struct mref_object *mref = mref_a->object;
	struct trans_logger_input *input = output->brick->inputs[0];
	struct trans_logger_mref_aspect *mshadow_a;

	/* Look if there is a newer version on the fly, shadowing
	 * the old one.
	 * When a shadow is found, use it as buffer for the mref.
	 */
	mshadow_a = hash_find(output, mref->ref_pos, &mref->ref_len);
	if (!mshadow_a) {
		return GENERIC_INPUT_CALL(input, mref_get, mref);
	}

	return _make_sshadow(output, mref_a, mshadow_a);
}	

static noinline
int _write_ref_get(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	struct page *page;
	void *data;

#ifdef KEEP_UNIQUE
	struct trans_logger_mref_aspect *mshadow_a;
	mshadow_a = hash_find(output, mref->ref_pos, &mref->ref_len);
	if (mshadow_a) {
		return _make_sshadow(output, mref_a, mshadow_a);
	}
#endif

	// create a new master shadow
#ifdef USE_KMALLOC
	data = kmalloc(mref->ref_len, GFP_MARS);
	mref->ref_page = NULL;
#else
	//TODO: allow higher-order pages
	if (mref->ref_len > PAGE_SIZE)
		mref->ref_len = PAGE_SIZE;
	page = alloc_page(GFP_MARS);
	if (unlikely(!page)) {
		return -ENOMEM;
	}
	mref->ref_page = page;
	data = page_address(page);
#endif
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
	mref_a->output = output;
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
	atomic_inc(&output->inner_balance_count);

	atomic_inc(&output->mshadow_count);
	atomic_inc(&output->total_mshadow_count);
	atomic_inc(&global_mshadow_count);

	return mref->ref_len;
}

static noinline
int trans_logger_ref_get(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;
	loff_t base_offset;

	CHECK_PTR(output, err);

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

	atomic_inc(&output->outer_balance_count);

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
		atomic_dec(&output->inner_balance_count);
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
			atomic_dec(&output->sshadow_count);
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			trans_logger_free_mref(mref);
			// now put the master shadow
			mref_a = shadow_a;
			goto restart;
		}
		// we are a master shadow
		CHECK_PTR(mref_a->shadow_data, err);
		if (mref_a->do_dealloc) {
#ifdef USE_KMALLOC
			kfree(mref_a->shadow_data);
#else
			free_page((unsigned long)mref_a->shadow_data);
#endif
			mref_a->shadow_data = NULL;
			mref_a->do_dealloc = false;
		}
		if (mref_a->do_buffered) {
			mref->ref_data = NULL;
		}
		atomic_dec(&output->mshadow_count);
		atomic_dec(&global_mshadow_count);
		trans_logger_free_mref(mref);
		return;
	}

	input = output->brick->inputs[0];
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
	atomic_dec(&output->outer_balance_count);
	_trans_logger_ref_put(output, mref);
}

static noinline
void _trans_logger_endio(struct generic_callback *cb)
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

static noinline
void trans_logger_ref_io(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_input *input = output->brick->inputs[0];
	struct generic_callback *cb;

	CHECK_ATOMIC(&mref->ref_count, 1);

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

	// statistics
	if (mref->ref_rw) {
		atomic_inc(&output->total_write_count);
	} else {
		atomic_inc(&output->total_read_count);
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
		atomic_inc(&output->inner_balance_count);

		qq_insert(&output->q_phase1, mref_a);
		wake_up_interruptible(&output->event);
		return;
	}

	// only READ is allowed on non-shadow buffers
	if (unlikely(mref->ref_rw != READ)) {
		MARS_FAT("bad operation %d on non-shadow\n", mref->ref_rw);
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
	return;
err:
	MARS_FAT("cannot handle IO\n");
}

////////////////////////////// writeback info //////////////////////////////

static noinline
void pos_complete(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_output *output = orig_mref_a->output;
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

		__trans_logger_ref_put(orig_mref_a->output, orig_mref_a);
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
	struct writeback_info *wb;
	int rw;
	atomic_t *dec;
	void (*endio)(struct generic_callback *cb);

	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);

	atomic_dec(&output->wb_balance_count);

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
	struct trans_logger_input *sub_input = brick->inputs[0];
	struct writeback_info *wb = kzalloc(sizeof(struct writeback_info), GFP_MARS);
	if (!wb) {
		goto err;
	}
	INIT_LIST_HEAD(&wb->w_collect_list);
	INIT_LIST_HEAD(&wb->w_sub_read_list);
	INIT_LIST_HEAD(&wb->w_sub_write_list);
	wb->w_output = output;

	wb->w_pos = pos;
	wb->w_len = len;
	if (unlikely(len < 0)) {
		MARS_ERR("len = %d\n", len);
	}

	/* Atomically fetch transitive closure on all requests
	 * overlapping with the current search region.
	 */
	hash_extend(output, &wb->w_pos, &wb->w_len, &wb->w_collect_list);

	pos = wb->w_pos;
	len = wb->w_len;

	if (unlikely(len < 0)) {
		MARS_ERR("len = %d\n", len);
	}

	/* Create sub_mrefs for read of old disk version (phase2)
	 */
	if (brick->log_reads) {
		while (len > 0) {
			struct trans_logger_mref_aspect *sub_mref_a;
			struct mref_object *sub_mref;
			int this_len;
			int status;

			sub_mref = trans_logger_alloc_mref((void*)output, &output->writeback_layout);
			if (unlikely(!sub_mref)) {
				MARS_FAT("cannot alloc sub_mref\n");
				goto err;
			}

			sub_mref->ref_pos = pos;
			sub_mref->ref_len = len;
			sub_mref->ref_may_write = READ;
			sub_mref->ref_rw = READ;
			sub_mref->ref_data = NULL;

			sub_mref_a = trans_logger_mref_get_aspect((struct trans_logger_output*)output, sub_mref);
			CHECK_PTR(sub_mref_a, err);

			sub_mref_a->output = output;
			sub_mref_a->wb = wb;

			status = GENERIC_INPUT_CALL(sub_input, mref_get, sub_mref);
			if (unlikely(status < 0)) {
				MARS_FAT("cannot get sub_ref, status = %d\n", status);
				goto err;
			}
			
			list_add_tail(&sub_mref_a->sub_head, &wb->w_sub_read_list);
			atomic_inc(&wb->w_sub_read_count);
			atomic_inc(&output->wb_balance_count);
		
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

		sub_mref = trans_logger_alloc_mref((void*)output, &output->writeback_layout);
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

		sub_mref_a = trans_logger_mref_get_aspect((struct trans_logger_output*)output, sub_mref);
		CHECK_PTR(sub_mref_a, err);

		sub_mref_a->output = output;
		sub_mref_a->wb = wb;

		status = GENERIC_INPUT_CALL(sub_input, mref_get, sub_mref);
		if (unlikely(status < 0)) {
			MARS_FAT("cannot get sub_ref, status = %d\n", status);
			goto err;
		}
#ifdef WB_COPY
		memcpy(sub_mref->ref_data, data, sub_mref->ref_len);
#endif
		
		list_add_tail(&sub_mref_a->sub_head, &wb->w_sub_write_list);
		atomic_inc(&wb->w_sub_write_count);
		atomic_inc(&output->wb_balance_count);
		
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

static noinline
void fire_writeback(struct writeback_info *wb, struct list_head *start)
{
	struct trans_logger_output *output = wb->w_output;
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_input *sub_input = brick->inputs[0];
	struct list_head *tmp;

	while ((tmp = start->next) != start) {
		struct trans_logger_mref_aspect *sub_mref_a;
		struct mref_object *sub_mref;
		struct generic_callback *cb;

		list_del_init(tmp);
		sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
		sub_mref = sub_mref_a->object;

		cb = &sub_mref_a->cb;
		cb->cb_fn = wb_endio;
		cb->cb_private = sub_mref_a;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		sub_mref->ref_cb = cb;

		GENERIC_INPUT_CALL(sub_input, mref_io, sub_mref);
		GENERIC_INPUT_CALL(sub_input, mref_put, sub_mref);
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
	qq_insert(&output->q_phase2, orig_mref_a);
	wake_up_interruptible(&output->event);
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
	void *data;
	unsigned long flags;
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

	memcpy(data, orig_mref_a->shadow_data, orig_mref->ref_len);

	ok = log_finalize(&brick->logst, orig_mref->ref_len, phase1_endio, orig_mref_a);
	if (unlikely(!ok)) {
		goto err;
	}
	atomic_inc(&output->q_phase1.q_flying);
	orig_mref_a->log_pos = brick->logst.log_pos + brick->logst.offset;

	traced_lock(&brick->pos_lock, flags);
	list_add_tail(&orig_mref_a->pos_head, &brick->pos_list);
	traced_unlock(&brick->pos_lock, flags);

	wake_up_interruptible(&output->event);
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

	CHECK_PTR(mref, err);
	shadow_a = mref_a->shadow_ref;
	CHECK_PTR(shadow_a, err);
	output = mref_a->output;
	CHECK_PTR(output, err);

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
		hash_insert(output, mref_a);
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

atomic_t provisionary_count = ATOMIC_INIT(0);

static noinline
void phase2_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct writeback_info *wb;
	struct trans_logger_output *output;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	atomic_dec(&provisionary_count);


	// queue up for the next phase
	//qq_insert(&output->q_phase3, orig_mref_a);
	wake_up_interruptible(&output->event);
	return;

err: 
	MARS_FAT("hanging up....\n");
}

static noinline
void phase4_endio(struct generic_callback *cb);

static noinline
bool phase2_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct writeback_info *wb;

	CHECK_PTR(orig_mref_a, err);
	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);

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

	atomic_inc(&provisionary_count);

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
	fire_writeback(wb, &wb->w_sub_write_list);

 done:
	return true;
	
 err:
	return false;
}


/********************************************************************* 
 * Phase 3: log the old disk version.
 */

#ifndef NEW_CODE

static noinline
void _phase3_endio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_output *output;
	
	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	
	// queue up for the next phase
	qq_insert(&output->q_phase4, orig_mref_a);
	wake_up_interruptible(&output->event);
	return;

err:
	MARS_FAT("hanging up....\n");
}

static noinline
void phase3_endio(void *private, int error)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_output *output;
	struct trans_logger_mref_aspect *orig_mref_a;

	sub_mref_a = private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	orig_mref_a = sub_mref_a->orig_mref_a;
	CHECK_PTR(orig_mref_a, err);

	atomic_dec(&output->q_phase3.q_flying);

	if (unlikely(error < 0)) {
		MARS_FAT("IO error %d\n", error);
		goto err; // FIXME: this leads to hanging requests. do better.
	}

	if (atomic_dec_and_test(&orig_mref_a->current_sub_count)) {
		_phase3_endio(orig_mref_a);
	}
	return;

err:
	MARS_FAT("hanging up....\n");
}

static noinline
bool _phase3_startio(struct trans_logger_mref_aspect *sub_mref_a)
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
	return true;

err:
	return false;
}

static noinline
bool phase3_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_output *output;

	CHECK_PTR(orig_mref_a, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);

	if (output->brick->log_reads && orig_mref_a->total_sub_count > 0) {
		struct list_head *tmp;

		atomic_set(&orig_mref_a->current_sub_count, orig_mref_a->total_sub_count);
		for (tmp = orig_mref_a->sub_list.next; tmp != &orig_mref_a->sub_list; tmp = tmp->next) {
			struct trans_logger_mref_aspect *sub_mref_a;
			struct mref_object *sub_mref;
			sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
			sub_mref = sub_mref_a->object;
			atomic_inc(&output->q_phase3.q_flying);
			mars_trace(sub_mref, "sub_log");
			_phase3_startio(sub_mref_a);
		}
		wake_up_interruptible(&output->event);
	} else {
		_phase3_endio(orig_mref_a);
	}
	return true;
err:
	return false;
}

#endif // NEW_CODE

/********************************************************************* 
 * Phase 4: overwrite old disk version with new version.
 */

static noinline
void phase4_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct writeback_info *wb;
	struct trans_logger_output *output;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	output = wb->w_output;
	CHECK_PTR(output, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	hash_put_all(wb->w_output, &wb->w_collect_list);

	free_writeback(wb);

	atomic_dec(&provisionary_count);
	wake_up_interruptible(&output->event);

	return;

err: 
	MARS_FAT("hanging up....\n");
}


#ifndef NEW_CODE

static noinline
void _phase4_endio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_brick *brick;
	struct list_head *tmp;
	unsigned long flags;

	orig_mref = orig_mref_a->object;
	CHECK_PTR(orig_mref, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

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

	//MARS_DBG("put ORIGREF.\n");
	CHECK_ATOMIC(&orig_mref->ref_count, 1);
	if (orig_mref_a->is_dirty) {
		MARS_ERR("dirty pos = %lld len = %d\n", orig_mref->ref_pos, orig_mref->ref_len);
		//...
	} else {
		__trans_logger_ref_put(orig_mref_a->output, orig_mref_a);
	}
	wake_up_interruptible(&output->event);
	return;

err:
	MARS_FAT("hanging up....\n");
}

static noinline
void phase4_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_output *output;
	struct trans_logger_mref_aspect *orig_mref_a;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	orig_mref_a = sub_mref_a->orig_mref_a;
	CHECK_PTR(orig_mref_a, err);
	
	mars_trace(sub_mref, "sub_endio");
	mars_log_trace(sub_mref);

	atomic_dec(&output->q_phase4.q_flying);

	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}


	if (atomic_dec_and_test(&orig_mref_a->current_sub_count)) {
		_phase4_endio(orig_mref_a);
	}
	return;

err: 
	MARS_FAT("hanging up....\n");
}


static noinline
bool get_newest_data(struct trans_logger_output *output, void *buf, loff_t pos, int len, struct trans_logger_mref_aspect *orig_mref_a)
{
	while (len > 0) {
		struct trans_logger_mref_aspect *src_a;
		struct mref_object *src;
		int diff;
		int this_len = len;

		src_a = hash_find(output, pos, &this_len);
		if (unlikely(!src_a)) {
			MARS_ERR("data is GONE at pos = %lld len = %d\n", pos, len);
			return false;
		}
		if (unlikely(!src_a->shadow_ref)) {
			MARS_ERR("no shadow at pos = %lld len = %d\n", pos, len);
			return false;
		}
#ifdef KEEP_UNIQUE
		if (unlikely(src_a->shadow_ref != orig_mref_a->shadow_ref)) {
			MARS_ERR("different shadows at pos = %lld len = %d: %p -> %p pos = %lld len = %d / %p -> %p pos = %lld len = %d\n", pos, len, src_a, src_a->shadow_ref, src_a->shadow_ref->object->ref_pos, src_a->shadow_ref->object->ref_len, orig_mref_a, orig_mref_a->shadow_ref, orig_mref_a->shadow_ref->object->ref_pos, orig_mref_a->shadow_ref->object->ref_len);
		}
#else
		if (unlikely(src_a->shadow_ref != src_a)) {
			MARS_ERR("invalid master shadow at pos = %lld len = %d\n", pos, len);
			return false;
		}
#endif
		src = src_a->object;
		CHECK_ATOMIC(&src->ref_count, 1);

		diff = pos - src->ref_pos;
		if (unlikely(diff < 0 || diff + this_len > src->ref_len)) {
			MARS_ERR("bad diff %d (found len = %d, this_len = %d)\n", diff, src->ref_len, this_len);
			return false;
		}
		memcpy(buf, src_a->shadow_data + diff, this_len);

		len -= this_len;
		pos += this_len;
		buf += this_len;

		__trans_logger_ref_put(output, src_a);
	}
	return true;
}

static noinline
bool _phase4_startio(struct trans_logger_mref_aspect *sub_mref_a)
{
	struct mref_object *sub_mref = NULL;
	struct generic_callback *cb;
	struct trans_logger_output *output;
	struct trans_logger_input *sub_input;
	struct trans_logger_mref_aspect *orig_mref_a;
	int status;
	bool ok;

	CHECK_PTR(sub_mref_a, err);
	sub_mref = sub_mref_a->object;
	CHECK_PTR(sub_mref, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	CHECK_PTR(output->brick, err);
	sub_input = output->brick->inputs[0];
	CHECK_PTR(sub_input, err);
	orig_mref_a = sub_mref_a->orig_mref_a;
	CHECK_PTR(orig_mref_a, err);

	orig_mref_a->is_dirty = false;
	orig_mref_a->shadow_ref->is_dirty = false;

	status = 0;
	ok = get_newest_data(output, sub_mref->ref_data, sub_mref->ref_pos, sub_mref->ref_len, orig_mref_a);
	if (unlikely(!ok)) {
		MARS_ERR("cannot get data at pos = %lld len = %d\n", sub_mref->ref_pos, sub_mref->ref_len);
		status = -EIO;
	}

	cb = &sub_mref_a->cb;
	cb->cb_fn = phase4_endio;
	cb->cb_private = sub_mref_a;
	cb->cb_error = status;
	cb->cb_prev = NULL;
	sub_mref->ref_cb = cb;
	sub_mref->ref_rw = WRITE;
	sub_mref->ref_prio = output->q_phase4.q_io_prio;

	atomic_inc(&output->q_phase4.q_flying);

	mars_log_trace(sub_mref);
	mars_trace(sub_mref, "sub_start");

	if (status < 0 || output->brick->debug_shortcut) {
		MARS_IO("SHORTCUT %d\n", sub_mref->ref_len);
		atomic_inc(&output->total_shortcut_count);
		phase4_endio(cb);
	} else {
		atomic_inc(&output->total_writeback_count);
		GENERIC_INPUT_CALL(sub_input, mref_io, sub_mref);
	}

	MARS_IO("put SUBREF.\n");

	GENERIC_INPUT_CALL(sub_input, mref_put, sub_mref);
	atomic_dec(&output->sub_balance_count);
	return true;

err:
	MARS_ERR("cannot start phase 4 IO %p\n", sub_mref);
	return false;
}

static noinline
bool phase4_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_output *output;

	CHECK_PTR(orig_mref_a, err);
	output = orig_mref_a->output;
	CHECK_PTR(output, err);

	if (orig_mref_a->total_sub_count > 0) {
		struct list_head *tmp;

		atomic_set(&orig_mref_a->current_sub_count, orig_mref_a->total_sub_count);
		while ((tmp = orig_mref_a->sub_list.next) != &orig_mref_a->sub_list) {
			struct trans_logger_mref_aspect *sub_mref_a;
			struct mref_object *sub_mref;
			list_del_init(tmp);
			sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
			sub_mref = sub_mref_a->object;
			mars_trace(sub_mref, "sub_write");
			_phase4_startio(sub_mref_a);
		}
		wake_up_interruptible(&output->event);
	} else {
		_phase4_endio(orig_mref_a);
	}
	return true;
err:
	return false;
}

#endif // NEW_CODE

/********************************************************************* 
 * The logger thread.
 * There is only a single instance, dealing with all requests in parallel.
 */

static noinline
int run_queue(struct trans_logger_output *output, struct logger_queue *q, bool (*startio)(struct trans_logger_mref_aspect *sub_mref_a), int max)
{
	struct trans_logger_mref_aspect *mref_a;
	bool found = false;
	bool ok;
	int res;

	while (max-- > 0) {
		mref_a = qq_fetch(q);
		res = -1;
		if (!mref_a)
			goto done;

		found = true;
		
		ok = startio(mref_a);
		if (unlikely(!ok)) {
			qq_pushback(q, mref_a);
			output->did_pushback = true;
			res = 1;
			goto done;
		}
		__trans_logger_ref_put(output, mref_a);
	}
	res = 0;

done:
	if (found) {
		wake_up_interruptible(&output->event);
	}
	return res;
}

static inline 
int _congested(struct trans_logger_output *output)
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

static noinline
void trans_logger_log(struct trans_logger_output *output)
{
	struct trans_logger_brick *brick = output->brick;
	int wait_timeout = HZ;
	long long log_jiffies = jiffies;
#ifdef  STAT_DEBUGGING
	long long last_jiffies = jiffies;
#endif

	brick->replay_pos = brick->current_pos = brick->log_start_pos;
	brick->logst.log_pos = brick->current_pos;

	mars_power_led_on((void*)brick, true);

	while (!kthread_should_stop() || _congested(output)) {
		int status;

#ifdef CONFIG_DEBUG_KERNEL
		wait_timeout = 16 * HZ;
#else
		wait_timeout = 3;
#endif
		MARS_IO("waiting for request\n");

		wait_event_interruptible_timeout(
			output->event,
			atomic_read(&output->q_phase1.q_queued) > 0 ||
#ifdef USE_HIGHER_PHASES
			qq_is_ready(&output->q_phase2) ||
#ifndef NEW_CODE
			qq_is_ready(&output->q_phase3) ||
			qq_is_ready(&output->q_phase4) ||
#endif
#endif
			(kthread_should_stop() && !_congested(output)),
			wait_timeout);

		//MARS_DBG("AHA %d\n", atomic_read(&output->q_phase1.q_queued));
#ifdef MARS_TRACING
		{
			static int old_mshadow_count = 0;
			int cnt;

			cnt = atomic_read(&global_mshadow_count);
			if (cnt + old_mshadow_count > 0 && cnt != old_mshadow_count) {
				unsigned long long now = cpu_clock(raw_smp_processor_id());
				if (!start_trace_clock)
					start_trace_clock = now;
				now -= start_trace_clock;
				mars_log("shadow_count ;%12lld ; %4d\n", now / 1000, cnt);
			}
			old_mshadow_count = cnt;
		}
#endif
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
		output->did_pushback = false;

		/* This is highest priority, do it always.
		 */
		status = run_queue(output, &output->q_phase1, phase0_startio, output->q_phase1.q_batchlen);
		if (status < 0) {
#ifdef STAT_DEBUGGING
			wait_timeout = 10 * HZ;
#else
			wait_timeout = HZ / 50 + 1;
#endif
		}

		/* A kind of delayed plugging mechanism
		 */
		if (atomic_read(&output->q_phase1.q_queued) <= 0 &&
		   (!brick->flush_delay || !log_jiffies ||
		    (long long)jiffies - log_jiffies >= 0)) {
			log_flush(&brick->logst);
			log_jiffies = 0;
		}
#ifdef USE_HIGHER_PHASES
#ifndef NEW_CODE
		if (qq_is_ready(&output->q_phase4)) {
			(void)run_queue(output, &output->q_phase4, phase4_startio, output->q_phase4.q_batchlen);
		}
#endif

		if (qq_is_ready(&output->q_phase2)) {
			(void)run_queue(output, &output->q_phase2, phase2_startio, output->q_phase2.q_batchlen);
		}

#ifndef NEW_CODE
		if (qq_is_ready(&output->q_phase3)) {
			status = run_queue(output, &output->q_phase3, phase3_startio, output->q_phase3.q_batchlen);
		}
#endif
#endif
		if (output->did_pushback) {
#if 0
			log_flush(&brick->logst);
#endif
			wait_timeout = 2;
		}
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
	output = mref_a->output;
	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);

	traced_lock(&brick->replay_lock, flags);
	list_del_init(&mref_a->replay_head);
	traced_unlock(&brick->replay_lock, flags);

	atomic_dec(&output->replay_count);
	wake_up_interruptible(&output->event);
	return;
 err:
	MARS_FAT("cannot handle replay IO\n");
}

static noinline
bool _has_conflict(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct trans_logger_brick *brick = output->brick;
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
void wait_replay(struct trans_logger_output *output, struct trans_logger_mref_aspect *mref_a)
{
	struct trans_logger_brick *brick = output->brick;
	int max = 1024 * 2; // limit parallelism somewhat
	unsigned long flags;

	wait_event_interruptible_timeout(output->event,
					 atomic_read(&output->replay_count) <= max
					 && !_has_conflict(output, mref_a),
					 60 * HZ);

	atomic_inc(&output->replay_count);
	traced_lock(&brick->replay_lock, flags);
	list_add(&mref_a->replay_head, &brick->replay_list);
	traced_unlock(&brick->replay_lock, flags);
}

static noinline
int apply_data(struct trans_logger_output *output, loff_t pos, void *buf, int len)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_input *input = brick->inputs[0];

	int status;

	MARS_IO("got data, pos = %lld, len = %d\n", pos, len);

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
		mref = trans_logger_alloc_mref(output, &output->replay_layout);
		if (unlikely(!mref)) {
			MARS_ERR("no memory\n");
			goto done;
		}
		mref_a = trans_logger_mref_get_aspect(output, mref);
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

		wait_replay(output, mref_a);

		mars_trace(mref, "replay_io");

		memcpy(mref->ref_data, buf, mref->ref_len);

		cb = &mref_a->cb;
		cb->cb_fn = replay_endio;
		cb->cb_private = mref_a;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		mref->ref_cb = cb;
		mref_a->output = output;
		
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
	bool has_triggered = false;

	brick->replay_code = -EAGAIN; // indicates "running"

	MARS_INF("starting replay from %lld to %lld\n", brick->replay_start_pos, brick->replay_end_pos);
	
	init_logst(&brick->logst, (void*)brick->inputs[1], (void*)brick->outputs[0], brick->replay_start_pos);

	brick->replay_pos = brick->current_pos = brick->logst.log_pos;
	mars_power_led_on((void*)brick, true);

	for (;;) {
		struct log_header lh = {};
		void *buf = NULL;
		int len = 0;
		int status;

		if (kthread_should_stop()) {
			break;
		}

		status = log_read(&brick->logst, &lh, &buf, &len);
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

		if (likely(buf && len)) {
			status = apply_data(output, lh.l_pos, buf, len);
			if (unlikely(status < 0)) {
				brick->replay_code = status;
				MARS_ERR("cannot apply data, len = %d, status = %d\n", len, status);
				break;
			}
		}

		// do this _after_ any opportunities for errors...
		if (atomic_read(&output->replay_count) <= 0) {
			brick->replay_pos = brick->current_pos = brick->logst.log_pos + brick->logst.offset;
		}
	}

	wait_event_interruptible_timeout(output->event, atomic_read(&output->replay_count) <= 0, 60 * HZ);

	brick->replay_pos = brick->current_pos = brick->logst.log_pos + brick->logst.offset;

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

	brick->logst.align_size = brick->align_size;
	brick->logst.chunk_size = brick->chunk_size;

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
		if (!output->thread && brick->power.led_off) {
			mars_power_led_off((void*)brick, false);
			init_logst(&brick->logst, (void*)brick->inputs[1], (void*)brick->outputs[0], 0);

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

//////////////// informational / statistics ///////////////

static noinline
char *trans_logger_statistics(struct trans_logger_brick *brick, int verbose)
{
	struct trans_logger_output *output = brick->outputs[0];
	char *res = kmalloc(512, GFP_MARS);
	if (!res)
		return NULL;

	// FIXME: check for allocation overflows

	sprintf(res, "total reads=%d writes=%d writeback=%d shortcut=%d (%d%%) mshadow=%d sshadow=%d phase1=%d phase2=%d phase3=%d phase4=%d | mshadow=%d sshadow=%d hash_count=%d balance=%d/%d/%d/%d fly=%d phase1=%d+%d phase2=%d+%d phase3=%d+%d phase4=%d+%d\n",
		atomic_read(&output->total_read_count), atomic_read(&output->total_write_count), atomic_read(&output->total_writeback_count), atomic_read(&output->total_shortcut_count), atomic_read(&output->total_writeback_count) ? atomic_read(&output->total_shortcut_count) * 100 / atomic_read(&output->total_writeback_count) : 0, atomic_read(&output->total_mshadow_count), atomic_read(&output->total_sshadow_count), atomic_read(&output->q_phase1.q_total), atomic_read(&output->q_phase2.q_total), atomic_read(&output->q_phase3.q_total), atomic_read(&output->q_phase4.q_total),
		atomic_read(&output->mshadow_count), atomic_read(&output->sshadow_count), atomic_read(&output->hash_count), atomic_read(&output->sub_balance_count), atomic_read(&output->inner_balance_count), atomic_read(&output->outer_balance_count), atomic_read(&output->wb_balance_count), atomic_read(&output->fly_count), atomic_read(&output->q_phase1.q_queued), atomic_read(&output->q_phase1.q_flying), atomic_read(&output->q_phase2.q_queued), atomic_read(&output->q_phase2.q_flying), atomic_read(&output->q_phase3.q_queued), atomic_read(&output->q_phase3.q_flying), atomic_read(&output->q_phase4.q_queued), atomic_read(&output->q_phase4.q_flying));
	return res;
}

static noinline
void trans_logger_reset_statistics(struct trans_logger_brick *brick)
{
	struct trans_logger_output *output = brick->outputs[0];
	atomic_set(&output->total_read_count, 0);
	atomic_set(&output->total_write_count, 0);
	atomic_set(&output->total_writeback_count, 0);
	atomic_set(&output->total_shortcut_count, 0);
	atomic_set(&output->total_mshadow_count, 0);
	atomic_set(&output->total_sshadow_count, 0);
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
	spin_lock_init(&brick->pos_lock);
	INIT_LIST_HEAD(&brick->pos_list);
	spin_lock_init(&brick->replay_lock);
	INIT_LIST_HEAD(&brick->replay_list);
	return 0;
}

static noinline
int trans_logger_output_construct(struct trans_logger_output *output)
{
	int i;
	for (i = 0; i < TRANS_HASH_MAX; i++) {
		struct hash_anchor *start = &output->hash_table[i];
		rwlock_init(&start->hash_lock);
		INIT_LIST_HEAD(&start->hash_anchor);
	}
	atomic_set(&output->hash_count, 0);
	init_waitqueue_head(&output->event);
	qq_init(&output->q_phase1, output);
	qq_init(&output->q_phase2, output);
	qq_init(&output->q_phase3, output);
	qq_init(&output->q_phase4, output);
#if 1
	output->q_phase2.q_dep = &output->q_phase3;
	output->q_phase3.q_dep = &output->q_phase4;
	output->q_phase4.q_dep = &output->q_phase1;

	output->q_phase2.q_dep_plus = &provisionary_count;
#endif
	output->q_phase1.q_insert_info   = "q1_ins";
	output->q_phase1.q_pushback_info = "q1_push";
	output->q_phase1.q_fetch_info    = "q1_fetch";
	output->q_phase2.q_insert_info   = "q2_ins";
	output->q_phase2.q_pushback_info = "q2_push";
	output->q_phase2.q_fetch_info    = "q2_fetch";
	output->q_phase3.q_insert_info   = "q3_ins";
	output->q_phase3.q_pushback_info = "q3_push";
	output->q_phase3.q_fetch_info    = "q3_fetch";
	output->q_phase4.q_insert_info   = "q4_ins";
	output->q_phase4.q_pushback_info = "q4_push";
	output->q_phase4.q_fetch_info    = "q4_fetch";
	return 0;
}

static noinline
int trans_logger_input_construct(struct trans_logger_input *input)
{
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
