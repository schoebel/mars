// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Trans_Logger brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING // here means: display full statistics

// changing this is dangerous for data integrity! use only for testing!
#define USE_MEMCPY
//#define USE_KMALLOC
#define USE_HIGHER_PHASES
#define APPLY_DATA
#define CLEAN_ALL
//#define KEEP_UNIQUE
#define NOTRASH_DATA
//#define DO_SKIP
//#define DO_IGNORE // FIXME or DELETE
#define DO_EXTEND

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

#ifdef BITMAP_CHECKS // code stolen
enum {
        REG_OP_ISFREE,          /* true if region is all zero bits */
        REG_OP_ALLOC,           /* set all bits in region */
        REG_OP_RELEASE,         /* clear all bits in region */
};

static int bitmap_op(unsigned long *bitmap, int pos, int nbits_reg, int reg_op)
{
        int index;              /* index first long of region in bitmap */
        int offset;             /* bit offset region in bitmap[index] */
        int nlongs_reg;         /* num longs spanned by region in bitmap */
        int nbitsinlong;        /* num bits of region in each spanned long */
        unsigned long mask;     /* bitmask for one long of region */
        int i;                  /* scans bitmap by longs */
        int ret = 0;            /* return value */

        index = pos / BITS_PER_LONG;
        offset = pos - (index * BITS_PER_LONG);
        nlongs_reg = BITS_TO_LONGS(nbits_reg);
        nbitsinlong = min(nbits_reg,  BITS_PER_LONG);

        /*
         * Can't do "mask = (1UL << nbitsinlong) - 1", as that
         * overflows if nbitsinlong == BITS_PER_LONG.
         */
        mask = (1UL << (nbitsinlong - 1));
        mask += mask - 1;
        mask <<= offset;

        switch (reg_op) {
        case REG_OP_ISFREE:
                for (i = 0; i < nlongs_reg; i++) {
                        if (bitmap[index + i] & mask)
                                goto done;
                }
                ret = 1;        /* all bits in region free (zero) */
                break;

        case REG_OP_ALLOC:
                for (i = 0; i < nlongs_reg; i++)
                        bitmap[index + i] |= mask;
                break;

        case REG_OP_RELEASE:
                for (i = 0; i < nlongs_reg; i++)
                        bitmap[index + i] &= ~mask;
                break;
        }
done:
        return ret;
}

#define CHECK_BITMAP(mref,mref_a)					\
	{								\
		int i;							\
		for (i = 0; i < sizeof(mref_a->dirty_bitmap)/sizeof(long); i++) { \
			if (mref_a->dirty_bitmap[i] != 0) {		\
				MARS_ERR("bitmap %d: dirty = %8lx touched = %8lx slave = %8lx worked = %8lx at pos = %lld len = %d (writes=%d slave_writes=%d reads=%d, start_phase1=%d end_phase1=%d start_phase2=%d sub_count=%d)\n", i, mref_a->dirty_bitmap[i], mref_a->touch_bitmap[i], mref_a->slave_bitmap[i], mref_a->work_bitmap[i], mref->ref_pos, mref->ref_len, mref_a->bitmap_write, mref_a->bitmap_write_slave, mref_a->bitmap_read, mref_a->start_phase1, mref_a->end_phase1, mref_a->start_phase2, mref_a->sub_count); \
			}						\
		}							\
	}
#endif

////////////////////////////////////////////////////////////////////

static inline
bool q_cmp(struct pairing_heap_mref *_a, struct pairing_heap_mref *_b)
{
	struct trans_logger_mref_aspect *mref_a = container_of(_a, struct trans_logger_mref_aspect, ph);
	struct trans_logger_mref_aspect *mref_b = container_of(_b, struct trans_logger_mref_aspect, ph);
	struct mref_object *a = mref_a->object;
	struct mref_object *b = mref_b->object;
	return a->ref_pos < b->ref_pos;
}

_PAIRING_HEAP_FUNCTIONS(static,mref,q_cmp);

static inline
void q_init(struct logger_queue *q, struct trans_logger_output *output)
{
	q->q_output = output;
	INIT_LIST_HEAD(&q->q_anchor);
	q->heap_low = NULL;
	q->heap_high = NULL;
	spin_lock_init(&q->q_lock);
	atomic_set(&q->q_queued, 0);
	atomic_set(&q->q_flying, 0);
}

static noinline
bool q_is_ready(struct logger_queue *q)
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
void q_insert(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	unsigned long flags;

	mars_trace(mref_a->object, q->q_insert_info);

	traced_lock(&q->q_lock, flags);

	if (q->q_ordering) {
		struct pairing_heap_mref **use = &q->heap_high;
		if (mref_a->object->ref_pos <= q->heap_margin) {
			use = &q->heap_low;
		}
		ph_insert_mref(use, &mref_a->ph);
	} else {
		list_add_tail(&mref_a->q_head, &q->q_anchor);
	}
	atomic_inc(&q->q_queued);
	atomic_inc(&q->q_total);
	q->q_last_insert = jiffies;

	traced_unlock(&q->q_lock, flags);
}

static inline
void q_pushback(struct logger_queue *q, struct trans_logger_mref_aspect *mref_a)
{
	unsigned long flags;

	mars_trace(mref_a->object, q->q_pushback_info);

	if (q->q_ordering) {
		atomic_dec(&q->q_total);
		q_insert(q, mref_a);
		return;
	}

	traced_lock(&q->q_lock, flags);

	list_add(&mref_a->q_head, &q->q_anchor);
	atomic_inc(&q->q_queued);
	//q->q_last_insert = jiffies;

	traced_unlock(&q->q_lock, flags);
}

static inline
struct trans_logger_mref_aspect *q_fetch(struct logger_queue *q)
{
	struct trans_logger_mref_aspect *mref_a = NULL;
	unsigned long flags;

	traced_lock(&q->q_lock, flags);

	if (q->q_ordering) {
		if (!q->heap_high) {
			q->heap_high = q->heap_low;
			q->heap_low = NULL;
			q->heap_margin = 0;
			q->last_pos = 0;
		}
		if (q->heap_high) {
			struct mref_object *mref;
			loff_t new_margin;
			mref_a = container_of(q->heap_high, struct trans_logger_mref_aspect, ph);
			mref = mref_a->object;
#if 1
			if (unlikely(mref->ref_pos < q->last_pos)) {
				MARS_ERR("backskip pos %lld -> %lld len = %d\n", q->last_pos, mref->ref_pos, mref->ref_len);
			}
			q->last_pos = mref->ref_pos;
#endif
			mref_a->fetch_margin = q->heap_margin;
			new_margin = mref->ref_pos + mref->ref_len;
			if (new_margin > q->heap_margin) {
				q->heap_margin = new_margin;
			}
			ph_delete_min_mref(&q->heap_high);
			atomic_dec(&q->q_queued);
		}
	} else if (!list_empty(&q->q_anchor)) {
		struct list_head *next = q->q_anchor.next;
		list_del_init(next);
		atomic_dec(&q->q_queued);
		mref_a = container_of(next, struct trans_logger_mref_aspect, q_head);
	}

	traced_unlock(&q->q_lock, flags);

	if (mref_a) {
		mars_trace(mref_a->object, q->q_fetch_info);
	}

	return mref_a;
}

///////////////////////// own helper functions ////////////////////////


static inline
int hash_fn(loff_t base_index)
{
	// simple and stupid
	loff_t tmp;
	tmp = base_index ^ (base_index / TRANS_HASH_MAX);
	return ((unsigned)tmp) % TRANS_HASH_MAX;
}

static noinline
struct trans_logger_mref_aspect *hash_find(struct trans_logger_output *output, loff_t pos, int *max_len, bool do_ignore, struct trans_logger_mref_aspect *cond_insert_a)
{
	loff_t base_index = pos >> REGION_SIZE_BITS;
	int hash = hash_fn(base_index);
	struct hash_anchor *start = &output->hash_table[hash];
	struct list_head *tmp;
	struct trans_logger_mref_aspect *res = NULL;
	int len = *max_len;
	unsigned int flags;
#ifdef STAT_DEBUGGING
	int count = 0;
#endif

	traced_readlock(&start->hash_lock, flags);

	/* The lists are always sorted according to age (newest first).
	 * Caution: there may be duplicates in the list, some of them
	 * overlapping with the search area in many different ways.
	 */
	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
		struct trans_logger_mref_aspect *test_a;
		struct mref_object *test;
		int diff;
#ifdef STAT_DEBUGGING
		static int max = 0;
		if (++count > max) {
			max = count;
			if (!(max % 10)) {
				MARS_DBG("hash max=%d hash=%d base_index=%lld\n", max, hash, base_index);
			}
		}
#endif
		test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
		test = test_a->object;

		// are the regions overlapping?
		if (pos >= test->ref_pos + test->ref_len || pos + len <= test->ref_pos || (test_a->ignore_this & do_ignore)) {
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

	if (res) {
		atomic_inc(&res->object->ref_count); // must be paired with _trans_logger_ref_put()
		atomic_inc(&output->inner_balance_count);
	} else if (cond_insert_a) {
		atomic_inc(&output->hash_count);
		list_add(&cond_insert_a->hash_head, &start->hash_anchor);
		cond_insert_a->is_hashed = true;
	}

	traced_readunlock(&start->hash_lock, flags);

	*max_len = len;
	return res;
}

static noinline
void hash_insert(struct trans_logger_output *output, struct trans_logger_mref_aspect *elem_a)
{
        loff_t base_index = elem_a->object->ref_pos >> REGION_SIZE_BITS;
        int hash = hash_fn(base_index);
        struct hash_anchor *start = &output->hash_table[hash];
        unsigned int flags;

#if 1
	CHECK_HEAD_EMPTY(&elem_a->hash_head);
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
	static atomic_t generation = ATOMIC_INIT(0);
	loff_t pos = *_pos;
	int len = *_len;
        loff_t base_index = pos >> REGION_SIZE_BITS;
        int hash = hash_fn(base_index);
        struct hash_anchor *start = &output->hash_table[hash];
	int my_generation;
	bool extended;
        unsigned int flags;

	if (collect_list) {
		CHECK_HEAD_EMPTY(collect_list);
	}

	do { my_generation = atomic_add_return(1, &generation); } while (!my_generation);  // avoid 0

        traced_readlock(&start->hash_lock, flags);

	do {
		struct list_head *tmp;
		extended = false;

		for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
			struct trans_logger_mref_aspect *test_a;
			struct mref_object *test;
			
			test_a = container_of(tmp, struct trans_logger_mref_aspect, hash_head);
			test = test_a->object;
			
			// are the regions overlapping?
			if (pos >= test->ref_pos + test->ref_len || pos + len <= test->ref_pos) {
				continue; // not relevant
			}
			
			// collect upon the first time
			if (collect_list && test_a->collect_generation != my_generation) {
				test_a->collect_generation = my_generation;
				test_a->is_collected = true;
				atomic_inc(&test->ref_count); // must be paired with _trans_logger_ref_put()
				list_add_tail(&test_a->collect_head, collect_list);
			}
			
			// extend the search region when necessary
			if (test->ref_pos < pos) {
				len += pos - test->ref_pos;
				pos = test->ref_pos;
				extended = true;
			}
			if (test->ref_pos + test->ref_len > pos + len) {
				len += (pos + len) - (test->ref_pos + test->ref_len);
				extended = true;
			}
		}
	} while (extended); // start over for transitive closure

        traced_readunlock(&start->hash_lock, flags);

	*_pos = pos;
	*_len = len;
}

static inline
bool hash_put(struct trans_logger_output *output, struct trans_logger_mref_aspect *elem_a)
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
		elem_a->is_hashed = false;
		atomic_dec(&output->hash_count);
	}

	traced_writeunlock(&start->hash_lock, flags);
	return res;
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
void _trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref);

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
#ifdef BITMAP_CHECKS
	mref_a->shadow_offset = diff;
#endif
	mref_a->do_dealloc = false;
	if (!mref->ref_data) { // buffered IO
		mref->ref_data = mref_a->shadow_data;
		mref_a->do_buffered = true;
	}
	mref->ref_flags = mshadow->ref_flags;
	mref_a->shadow_ref = mshadow_a;
	mref_a->output = output;
	atomic_inc(&mref->ref_count);
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
	mshadow_a = hash_find(output, mref->ref_pos, &mref->ref_len, true, NULL);
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
	mshadow_a = hash_find(output, mref->ref_pos, &mref->ref_len, false, NULL);
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
	atomic_inc(&mref->ref_count);
	atomic_inc(&output->inner_balance_count);
	get_lamport(&mref_a->stamp);
#if 1
	if (unlikely(mref->ref_len <= 0)) {
		MARS_ERR("oops, len = %d\n", mref->ref_len);
		return -EINVAL;
	}
#endif
#ifdef KEEP_UNIQUE
#ifdef DO_IGNORE
	mref_a->ignore_this = true;
	mshadow_a = hash_find(output, mref->ref_pos, &mref->ref_len, false, mref_a);
	if (mshadow_a) {
		MARS_INF("RACE DETECTED\n");
		mref_a->ignore_this = false;
		mref->ref_page = NULL;
		mref_a->shadow_data = NULL;
		mref_a->do_dealloc = false;
		mref_a->ignore_this = false;
		mref_a->shadow_ref = NULL;
		if (mref_a->do_buffered) {
			mref->ref_data = NULL;
		}
		atomic_dec(&mref->ref_count);
		atomic_dec(&output->inner_balance_count);
		return _make_sshadow(output, mref_a, mshadow_a);
	}
#endif
#endif

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

static noinline
void __trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	struct trans_logger_mref_aspect *mref_a;
	struct trans_logger_mref_aspect *shadow_a;
	struct trans_logger_input *input;

	MARS_IO("pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);

restart:
	CHECK_ATOMIC(&mref->ref_count, 1);

	CHECK_PTR(output, err);

	mref_a = trans_logger_mref_get_aspect(output, mref);
	CHECK_PTR(mref_a, err);
	CHECK_PTR(mref_a->object, err);

	// are we a shadow?
	shadow_a = mref_a->shadow_ref;
	if (shadow_a) {
		unsigned long flags;
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
#if 1 // FIXME: do bookkeping here
		traced_lock(&output->brick->pos_lock, flags);
		list_del_init(&mref_a->pos_head);
		traced_unlock(&output->brick->pos_lock, flags);
#endif
		if (shadow_a != mref_a) { // we are a slave shadow
			//MARS_DBG("slave\n");
			atomic_dec(&output->sshadow_count);
			CHECK_HEAD_EMPTY(&mref_a->hash_head);
			trans_logger_free_mref(mref);
			// now put the master shadow
			mref = shadow_a->object;
			goto restart;
		}
		// we are a master shadow
		CHECK_PTR(mref_a->shadow_data, err);
#ifdef BITMAP_CHECKS
		CHECK_BITMAP(mref, mref_a);
#endif
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
void trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	atomic_dec(&output->outer_balance_count);
	_trans_logger_ref_put(output, mref);
}

static noinline
void _trans_logger_ref_put(struct trans_logger_output *output, struct mref_object *mref)
{
	//atomic_dec(&output->inner_balance_count);
	__trans_logger_ref_put(output, mref);
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
		CHECK_HEAD_EMPTY(&mref_a->hash_head);
		CHECK_HEAD_EMPTY(&mref_a->q_head);
		CHECK_HEAD_EMPTY(&mref_a->pos_head);
#endif
		atomic_inc(&mref->ref_count);
		atomic_inc(&output->inner_balance_count);

		q_insert(&output->q_phase1, mref_a);
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
void free_writeback(struct writeback_info *wb)
{
	//...
	kfree(wb);
}

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

	rw = sub_mref->ref_rw;
	dec = rw ? &wb->w_sub_write_count : &wb->w_sub_read_count;
	if (atomic_dec_and_test(dec)) {
		return;
	}

	endio = rw ? wb->write_endio : wb->read_endio;
	if (endio) {
		endio(cb);
	}
	return;

err: 
	MARS_FAT("hanging up....\n");
}

static noinline
struct writeback_info *make_writeback(struct trans_logger_output *output, loff_t pos, int len)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_input *sub_input = brick->inputs[0];
	struct writeback_info *wb = kzalloc(sizeof(struct writeback_info), GFP_MARS);
	struct trans_logger_mref_aspect *base_mref_a = NULL;
	if (!wb) {
		goto err;
	}
	INIT_LIST_HEAD(&wb->w_collect_list);
	INIT_LIST_HEAD(&wb->w_sub_read_list);
	INIT_LIST_HEAD(&wb->w_sub_write_list);
	wb->w_output = output;

	wb->w_pos = pos;
	wb->w_len = len;

	hash_extend(output, &wb->w_pos, &wb->w_len, &wb->w_collect_list);

	pos = wb->w_pos;
	len = wb->w_len;

	while (len > 0) {
		struct trans_logger_mref_aspect *sub_mref_a;
		struct mref_object *sub_mref;
		struct mref_object *base_mref;
		void *data;
		int this_len = len;
		int diff;
		int status;

		base_mref_a = hash_find(output, pos, &this_len, true, NULL);
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

		sub_mref = trans_logger_alloc_mref((void*)output, &brick->logst.ref_object_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot alloc sub_mref\n");
			goto err;
		}

		sub_mref->ref_pos = pos;
		sub_mref->ref_len = this_len;
		sub_mref->ref_may_write = WRITE;
		sub_mref->ref_rw = WRITE;
		sub_mref->ref_data = data;

		sub_mref_a = trans_logger_mref_get_aspect((struct trans_logger_output*)output, sub_mref);
		CHECK_PTR(sub_mref_a, err);

		sub_mref_a->output = output;
		sub_mref_a->wb = wb;
		sub_mref_a->base_mref_a = base_mref_a;
		base_mref_a = NULL;

		status = GENERIC_INPUT_CALL(sub_input, mref_get, sub_mref);
		if (unlikely(status < 0)) {
			MARS_FAT("cannot get sub_ref, status = %d\n", status);
			goto err;
		}
		
		list_add_tail(&sub_mref_a->sub_head, &wb->w_sub_write_list);
		atomic_inc(&wb->w_sub_write_count);
		atomic_inc(&output->wb_balance_count);
		
		this_len = sub_mref->ref_len;
		pos += this_len;
		len -= this_len;
	}

	return wb;

 err:
	if (base_mref_a) {
		_trans_logger_ref_put(output, base_mref_a->object);
	}
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

#ifdef BITMAP_CHECKS
	orig_mref_a->shadow_ref->end_phase1++;
#endif
	// error handling
	if (error < 0)
		orig_cb->cb_error = error;

	// signal completion to the upper layer, as early as possible
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

#ifdef BITMAP_CHECKS
	orig_mref_a->shadow_ref->start_phase1++;
#endif
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

		_trans_logger_ref_put(output, mref);

		return true;
	} 
	// else WRITE
#if 1
	CHECK_HEAD_EMPTY(&mref_a->hash_head);
	CHECK_HEAD_EMPTY(&mref_a->q_head);
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
#ifdef BITMAP_CHECKS
	mref_a->shadow_ref->bitmap_write++;
	bitmap_op(mref_a->shadow_ref->dirty_bitmap, mref_a->shadow_offset/512, mref->ref_len/512, REG_OP_ALLOC);
	bitmap_op(mref_a->shadow_ref->touch_bitmap, mref_a->shadow_offset/512, mref->ref_len/512, REG_OP_ALLOC);
	bitmap_op(mref_a->shadow_ref->work_bitmap, mref_a->shadow_offset/512, mref->ref_len/512, REG_OP_ALLOC);
	if (mref_a->shadow_ref != mref_a) {
		mref_a->shadow_ref->bitmap_write_slave++;
		bitmap_op(mref_a->shadow_ref->slave_bitmap, mref_a->shadow_offset/512, mref->ref_len/512, REG_OP_ALLOC);
	}
#endif
#ifndef KEEP_UNIQUE
	if (unlikely(mref_a->shadow_ref != mref_a)) {
		MARS_ERR("something is wrong: %p != %p\n", mref_a->shadow_ref, mref_a);
	}
#endif
	if (!mref_a->is_hashed) {
		mref_a->is_hashed = true;
		mref_a->ignore_this = false;
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

#ifdef NEW_CODE

static noinline
void new_endio(struct generic_callback *cb)
{
	struct trans_logger_mref_aspect *sub_mref_a;
	struct trans_logger_output *output;
	struct writeback_info *wb;
	struct list_head *tmp;

	CHECK_PTR(cb, err);
	sub_mref_a = cb->cb_private;
	CHECK_PTR(sub_mref_a, err);
	output = sub_mref_a->output;
	CHECK_PTR(output, err);
	wb = sub_mref_a->wb;
	CHECK_PTR(wb, err);
	
	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	while ((tmp = wb->w_collect_list.next) != &wb->w_collect_list) {
		struct trans_logger_mref_aspect *orig_mref_a;
		struct mref_object *orig_mref;

		list_del_init(tmp);
		orig_mref_a = container_of(tmp, struct trans_logger_mref_aspect, collect_head);
		orig_mref = orig_mref_a->object;

		GENERIC_INPUT_CALL(output->brick->inputs[0], mref_put, orig_mref);
	}
	
	return;

err: 
	MARS_FAT("hanging up....\n");
}

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

	wb = make_writeback(output, orig_mref->ref_pos, orig_mref->ref_len);
	if (!wb) {
		goto err;
	}

	wb->write_endio = new_endio;

	fire_writeback(wb, &wb->w_sub_write_list);

 done:
#ifdef CLEAN_ALL
	_trans_logger_ref_put(output, orig_mref);
#endif
	return true;
	
 err:
	return false;
}

#else // NEW_CODE

static noinline
void _phase2_endio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct trans_logger_output *output;

	output = orig_mref_a->output;
	CHECK_PTR(output, err);

	// queue up for the next phase
	if (output->brick->log_reads) {
		q_insert(&output->q_phase3, orig_mref_a);
	} else {
		q_insert(&output->q_phase4, orig_mref_a);
	}
	wake_up_interruptible(&output->event);
	return;

err:
	MARS_FAT("hanging up....\n");
}

static noinline
void phase2_endio(struct generic_callback *cb)
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
	
	atomic_dec(&output->q_phase2.q_flying);

	if (unlikely(cb->cb_error < 0)) {
		MARS_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	if (atomic_dec_and_test(&orig_mref_a->current_sub_count)) {
		_phase2_endio(orig_mref_a);
	}
	return;

err: 
	MARS_FAT("hanging up....\n");
}

static noinline
bool phase2_startio(struct trans_logger_mref_aspect *orig_mref_a)
{
	struct mref_object *orig_mref;
	struct trans_logger_output *output;
	struct trans_logger_input *sub_input;
	struct trans_logger_brick *brick;
	struct generic_callback *cb;
	loff_t margin;
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
	sub_input = brick->inputs[0];
	CHECK_PTR(sub_input, err);

	pos = orig_mref->ref_pos;
	len = orig_mref->ref_len;

#ifdef DO_EXTEND
	hash_extend(output, &pos, &len, NULL);
#endif

#ifdef BITMAP_CHECKS
	orig_mref_a->shadow_ref->start_phase2++;
#endif
	margin = orig_mref_a->fetch_margin;
#ifdef DO_SKIP
	if (pos < margin && margin >= brick->old_margin) {
		int diff = margin - pos;
		MARS_DBG("skip = %d margin = %lld at pos = %lld len = %d newlen = %d\n", diff, margin, pos, len, len - diff);
		pos = margin;
		len -= diff;
	}
#endif
	brick->old_margin = margin;

	/* allocate internal sub_mref for further work
	 */
	if (unlikely(!list_empty(&orig_mref_a->sub_list))) {
		MARS_ERR("oops, list is not empty\n");
	}
	while (len > 0) {
		struct mref_object *sub_mref;
		struct trans_logger_mref_aspect *sub_mref_a;
		sub_mref = trans_logger_alloc_mref((void*)output, &brick->logst.ref_object_layout);
		if (unlikely(!sub_mref)) {
			MARS_FAT("cannot alloc sub_mref\n");
			goto err;
		}

		sub_mref->ref_pos = pos;
		sub_mref->ref_len = len;
		sub_mref->ref_may_write = WRITE;
		sub_mref->ref_rw = READ; // for now
		sub_mref->ref_data = NULL; // for now use buffered IO. // TODO: use direct IO, circumvent memcpy()

		sub_mref_a = trans_logger_mref_get_aspect((struct trans_logger_output*)output, sub_mref);
		CHECK_PTR(sub_mref_a, err);
		sub_mref_a->stamp = orig_mref_a->stamp;
		sub_mref_a->orig_mref_a = orig_mref_a;
		sub_mref_a->output = output;

		status = GENERIC_INPUT_CALL(sub_input, mref_get, sub_mref);
		if (unlikely(status < 0)) {
			MARS_FAT("cannot get sub_ref, status = %d\n", status);
			goto err;
		}

#ifdef BITMAP_CHECKS
		orig_mref_a->shadow_ref->sub_count++;
		bitmap_op(orig_mref_a->shadow_ref->work_bitmap, (sub_mref->ref_pos - orig_mref->ref_pos + orig_mref_a->shadow_offset)/512, sub_mref->ref_len/512, REG_OP_RELEASE);
#endif
		mars_trace(sub_mref, "sub_create");

		atomic_inc(&output->sub_balance_count);
		pos += sub_mref->ref_len;
		len -= sub_mref->ref_len;

		CHECK_ATOMIC(&orig_mref->ref_count, 1);

		cb = &sub_mref_a->cb;
		cb->cb_fn = phase2_endio;
		cb->cb_private = sub_mref_a;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		sub_mref->ref_cb = cb;
		sub_mref->ref_rw = READ;
		sub_mref->ref_prio = output->q_phase2.q_io_prio;

		list_add_tail(&sub_mref_a->sub_head, &orig_mref_a->sub_list);
		orig_mref_a->total_sub_count++;
	}

	if (output->brick->log_reads && orig_mref_a->total_sub_count > 0) {
		struct list_head *tmp;

		atomic_set(&orig_mref_a->current_sub_count, orig_mref_a->total_sub_count);
		for (tmp = orig_mref_a->sub_list.next; tmp != &orig_mref_a->sub_list; tmp = tmp->next) {
			struct trans_logger_mref_aspect *sub_mref_a;
			struct mref_object *sub_mref;
			sub_mref_a = container_of(tmp, struct trans_logger_mref_aspect, sub_head);
			sub_mref = sub_mref_a->object;
			atomic_inc(&output->q_phase2.q_flying);
			mars_trace(sub_mref, "sub_read");
			GENERIC_INPUT_CALL(sub_input, mref_io, sub_mref);
		}
		wake_up_interruptible(&output->event);
	} else {
		_phase2_endio(orig_mref_a);
	}
	return true;

err:
	return false;
}

#endif // NEW_CODE

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
	q_insert(&output->q_phase4, orig_mref_a);
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
#ifdef CLEAN_ALL
		_trans_logger_ref_put(orig_mref_a->output, orig_mref);
#endif
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

#ifndef NOTRASH_DATA
	{
		int i;
		for (i = 0; i < sub_mref->ref_len; i++) {
			char x = ((char*)sub_mref_a->shadow_data)[i];
			if (x != (char)0xff) {
				MARS_ERR("bad byte %d at %d\n", (int)x, i);
				break;
			}
		}
	}
#endif

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

		src_a = hash_find(output, pos, &this_len, true, NULL);
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
#ifdef NOTRASH_DATA
		memcpy(buf, src_a->shadow_data + diff, this_len);
#else
		memset(buf, 0xff, this_len);
#endif
#ifdef BITMAP_CHECKS
		src_a->shadow_ref->bitmap_read++;
		bitmap_op(src_a->shadow_ref->dirty_bitmap, (src_a->shadow_offset + diff)/512, this_len/512, REG_OP_RELEASE);
#endif

		len -= this_len;
		pos += this_len;
		buf += this_len;

		_trans_logger_ref_put(output, src);
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
#ifndef NOTRASH_DATA
	{
		int i;
		for (i = 0; i < sub_mref->ref_len; i++) {
			char x = ((char*)sub_mref->ref_data)[i];
			if (x != (char)0xff) {
				MARS_ERR("bad byte %d at %d\n", (int)x, i);
				break;
			}
		}
	}
#endif

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
		mref_a = q_fetch(q);
		res = -1;
		if (!mref_a)
			goto done;

		found = true;
		
		ok = startio(mref_a);
		if (unlikely(!ok)) {
			q_pushback(q, mref_a);
			output->did_pushback = true;
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
			q_is_ready(&output->q_phase2) ||
#ifndef NEW_CODE
			q_is_ready(&output->q_phase3) ||
			q_is_ready(&output->q_phase4) ||
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
		if (q_is_ready(&output->q_phase4)) {
			(void)run_queue(output, &output->q_phase4, phase4_startio, output->q_phase4.q_batchlen);
		}
#endif

		if (q_is_ready(&output->q_phase2)) {
			(void)run_queue(output, &output->q_phase2, phase2_startio, output->q_phase2.q_batchlen);
		}

#ifndef NEW_CODE
		if (q_is_ready(&output->q_phase3)) {
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

	sprintf(res, "total reads=%d writes=%d writeback=%d shortcut=%d (%d%%) mshadow=%d sshadow=%d phase1=%d phase2=%d phase3=%d phase4=%d | mshadow=%d sshadow=%d hash_count=%d balance=%d/%d/%d fly=%d phase1=%d+%d phase2=%d+%d phase3=%d+%d phase4=%d+%d\n",
		atomic_read(&output->total_read_count), atomic_read(&output->total_write_count), atomic_read(&output->total_writeback_count), atomic_read(&output->total_shortcut_count), atomic_read(&output->total_writeback_count) ? atomic_read(&output->total_shortcut_count) * 100 / atomic_read(&output->total_writeback_count) : 0, atomic_read(&output->total_mshadow_count), atomic_read(&output->total_sshadow_count), atomic_read(&output->q_phase1.q_total), atomic_read(&output->q_phase2.q_total), atomic_read(&output->q_phase3.q_total), atomic_read(&output->q_phase4.q_total),
		atomic_read(&output->mshadow_count), atomic_read(&output->sshadow_count), atomic_read(&output->hash_count), atomic_read(&output->sub_balance_count), atomic_read(&output->inner_balance_count), atomic_read(&output->outer_balance_count), atomic_read(&output->fly_count), atomic_read(&output->q_phase1.q_queued), atomic_read(&output->q_phase1.q_flying), atomic_read(&output->q_phase2.q_queued), atomic_read(&output->q_phase2.q_flying), atomic_read(&output->q_phase3.q_queued), atomic_read(&output->q_phase3.q_flying), atomic_read(&output->q_phase4.q_queued), atomic_read(&output->q_phase4.q_flying));
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
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->q_head);
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
	CHECK_HEAD_EMPTY(&ini->hash_head);
	CHECK_HEAD_EMPTY(&ini->q_head);
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
	q_init(&output->q_phase1, output);
	q_init(&output->q_phase2, output);
	q_init(&output->q_phase3, output);
	q_init(&output->q_phase4, output);
#if 1
	output->q_phase2.q_dep = &output->q_phase3;
	output->q_phase3.q_dep = &output->q_phase4;
	output->q_phase4.q_dep = &output->q_phase1;
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
