// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Buf brick

/* FIXME: this code has been unused for a long time, it is unlikly
 * to work at all.
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/delay.h>

#include "mars.h"

//#define USE_VMALLOC

//#define FAKE_IO // only for testing
//#define FAKE_READS // only for testing
//#define FAKE_WRITES // only for testing

//#define OPTIMIZE_FULL_WRITES // does not work currently!

///////////////////////// own type definitions ////////////////////////

#include "mars_buf.h"

#define PRE_ALLOC 8

///////////////////////// own helper functions ////////////////////////

static inline
int buf_hash_fn(loff_t base_index)
{
	// simple and stupid
	loff_t tmp;
	tmp = base_index ^ (base_index / MARS_BUF_HASH_MAX);
	//tmp ^= tmp / (MARS_BUF_HASH_MAX * MARS_BUF_HASH_MAX);
	return ((unsigned)tmp) % MARS_BUF_HASH_MAX;
}


static
struct buf_head *_hash_find_insert(struct buf_brick *brick, loff_t base_index, struct buf_head *new)
{
	
	int hash = buf_hash_fn(base_index);
	spinlock_t *lock = &brick->cache_anchors[hash].hash_lock;
	struct list_head *start	= &brick->cache_anchors[hash].hash_anchor;
	struct list_head *tmp;
	int count = 0;
	unsigned long flags;

	traced_lock(lock, flags);

	for (tmp = start->next; tmp != start; tmp = tmp->next) {
		struct buf_head *res;
#if 1
		if (!tmp) {
			MARS_ERR("tmp is NULL! brick = %p base_index = %lld hash = %d new = %p\n", brick, base_index, hash, new);
			//dump_stack();
			traced_unlock(lock, flags);
			return NULL;
		}
#endif
#if 1
		{
			static int max = 0;
			if (++count > max) {
				max = count;
				if (!(max % 10)) {
					MARS_INF("hash maxlen=%d hash=%d base_index=%llu\n", max, hash, base_index);
				}
			}
		}
#endif
		res = container_of(tmp, struct buf_head, bf_hash_head);
		if (res->bf_base_index == base_index) { // found
			/* This must be paired with _bf_put()
			 */
			atomic_inc(&res->bf_hash_count);
			traced_unlock(lock, flags);
			return res;
		}
	}

	if (new) {
		_CHECK_ATOMIC(&new->bf_hash_count, !=, 0);
		atomic_inc(&new->bf_hash_count);
		atomic_inc(&brick->hashed_count);
		CHECK_HEAD_EMPTY(&new->bf_hash_head);
		list_add(&new->bf_hash_head, start);
	}

	traced_unlock(lock, flags);

	return NULL;
}

/* Try to remove bf from the hash.
 * When bf is in use, do nothing.
 */
static inline
bool _remove_hash(struct buf_brick *brick, struct buf_head *bf)
{
	int hash;
	spinlock_t *lock;
	unsigned long flags;
	bool success = false;

	hash = buf_hash_fn(bf->bf_base_index);
	lock = &brick->cache_anchors[hash].hash_lock;

	traced_lock(lock, flags);

	if (likely(!atomic_read(&bf->bf_hash_count) && !atomic_read(&bf->bf_mref_count) && !atomic_read(&bf->bf_io_count))) {
		success = true;
		if (likely(!list_empty(&bf->bf_hash_head))) {
			list_del_init(&bf->bf_hash_head);
			atomic_dec(&brick->hashed_count);
		}
	}

	traced_unlock(lock, flags);

	return success;
}


static inline
void _add_bf_list(struct buf_brick *brick, struct buf_head *bf, int nr, bool at_end)
{
	unsigned long flags;

#if 1
	if (nr < 0 || nr >= LIST_MAX)
		MARS_FAT("bad nr %d\n", nr);
#endif

	traced_lock(&brick->brick_lock, flags);

	atomic_inc(&brick->list_count[nr]);
	if (!list_empty(&bf->bf_list_head)) {
		atomic_dec(&brick->list_count[bf->bf_member]);
		list_del(&bf->bf_list_head);
	}
	if (at_end) {
		list_add_tail(&bf->bf_list_head, &brick->list_anchor[nr]);
	} else {
		list_add(&bf->bf_list_head, &brick->list_anchor[nr]);
	}
	bf->bf_member = nr;
	bf->bf_jiffies = jiffies;

	traced_unlock(&brick->brick_lock, flags);
}

static inline
struct buf_head *_fetch_bf_list(struct buf_brick *brick, int nr, unsigned long age)
{
	struct buf_head *bf = NULL;
	unsigned long flags;

#if 1
	if (nr < 0 || nr >= LIST_MAX)
		MARS_FAT("bad nr %d\n", nr);
#endif

	traced_lock(&brick->brick_lock, flags);

	if (!list_empty(&brick->list_anchor[nr])) {
		bf = container_of(brick->list_anchor[nr].prev, struct buf_head, bf_list_head);
#if 1
		if (age != 0 && jiffies - bf->bf_jiffies < age) {
			traced_unlock(&brick->brick_lock, flags);
			return NULL;
		}
#endif
		atomic_dec(&brick->list_count[nr]);
		list_del_init(&bf->bf_list_head);
	}

	traced_unlock(&brick->brick_lock, flags);

	return bf;
}

static inline
void _remove_bf_list(struct buf_brick *brick, struct buf_head *bf)
{
	unsigned long flags;

#if 1
	if (bf->bf_member < 0 || bf->bf_member >= LIST_MAX)
		MARS_FAT("bad nr %d\n", bf->bf_member);
#endif
	traced_lock(&brick->brick_lock, flags);

	if (!list_empty(&bf->bf_list_head)) {
		list_del_init(&bf->bf_list_head);
		atomic_dec(&brick->list_count[bf->bf_member]);
	}

	traced_unlock(&brick->brick_lock, flags);
}

static inline
struct buf_head *_alloc_bf(struct buf_brick *brick)
{
	struct buf_head *bf = brick_zmem_alloc(sizeof(struct buf_head));
	if (unlikely(!bf))
		goto done;

#ifdef USE_VMALLOC
	bf->bf_data = vmalloc(brick->backing_size);
#else
	bf->bf_data = (void*)__get_free_pages(GFP_MARS, brick->backing_order);
#endif
	if (unlikely(!bf->bf_data)) {
		brick_mem_free(bf);
		bf = NULL;
		goto done;
	}

	atomic_inc(&brick->alloc_count);

done:
	return bf;
}

static inline
void _dealloc_bf(struct buf_brick *brick, struct buf_head *bf)
{
	MARS_INF("really freeing bf=%p\n", bf);
	_CHECK_ATOMIC(&bf->bf_hash_count, !=, 0);
	_CHECK_ATOMIC(&bf->bf_mref_count, !=, 0);
	_CHECK_ATOMIC(&bf->bf_io_count, !=, 0);
	CHECK_HEAD_EMPTY(&bf->bf_list_head);
	CHECK_HEAD_EMPTY(&bf->bf_hash_head);
	CHECK_HEAD_EMPTY(&bf->bf_io_pending_anchor);
	CHECK_HEAD_EMPTY(&bf->bf_postpone_anchor);
#ifdef USE_VMALLOC
	vfree(bf->bf_data);
#else
	free_pages((unsigned long)bf->bf_data, brick->backing_order);
#endif
	brick_mem_free(bf);
	atomic_dec(&brick->alloc_count);
}

static inline
void _prune_cache(struct buf_brick *brick, int max_count)
{
	struct buf_head *bf;
	int i;
	for (i = 0; i < LIST_MAX; i++) {
		while (atomic_read(&brick->alloc_count) > max_count) {
			bf = _fetch_bf_list(brick, i, 0);
			if (bf) {
				if (i > 0) {
					bool status;
					status = _remove_hash(brick, bf);
					if (unlikely(!status)) {
						MARS_INF("bf %p is in use\n", bf);
						continue;
					}
				}
				_dealloc_bf(brick, bf);
			}
		}
	}
}

static inline
struct buf_head *_fetch_bf(struct buf_brick *brick)
{
	struct buf_head *bf = NULL;
	while (!bf) {
		static const int ages[LIST_MAX] = {
			[LIST_FORGET] = HZ,
		};
		int i;
		for (i = 0; i < LIST_MAX; i++) {
			bf = _fetch_bf_list(brick, i, ages[i]);
			if (bf)
				goto found;
		}
		bf = _alloc_bf(brick);
		continue;
	found:
		if (i > 0) {
			bool status = _remove_hash(brick, bf);
			if (unlikely(!status)) {
				MARS_INF("bf %p is in use\n", bf);
				bf = NULL; // forget it => _bf_put() must fix it
				continue;
			}
		}
	}
	return bf;
}

static
void __pre_alloc_bf(struct buf_brick *brick, int max)
{
	while (max-- > 0) {
		struct buf_head *bf = _alloc_bf(brick);
		if (unlikely(!bf))
			break;
		INIT_LIST_HEAD(&bf->bf_list_head);
		_add_bf_list(brick, bf, LIST_FREE, true);
	}
}

static inline
void _bf_put(struct buf_head *bf)
{
	int list;
	bool at_end;

	if (!atomic_dec_and_test(&bf->bf_hash_count))
		return;

#if 1
	MARS_DBG("ZERO_COUNT %p %d\n", bf, at_end);
	if (unlikely(!list_empty(&bf->bf_io_pending_anchor))) {
		MARS_ERR("bf_io_pending_anchor is not empty!\n");
	}
	if (unlikely(!list_empty(&bf->bf_postpone_anchor))) {
		MARS_ERR("bf_postpone_anchor is not empty!\n");
	}
#endif

	list = LIST_LRU;
	at_end = !(bf->bf_flags & MREF_UPTODATE);
	if (bf->bf_chain_detected) {
		list = LIST_FORGET;
		at_end = false;
	}
	_add_bf_list(bf->bf_brick, bf, list, at_end);
}

/////////////////////////////////////////////////////////////////////////

/* Routines for the relation bf <-> mref
 */
static inline
void _mref_assign(struct buf_head *bf, struct buf_mref_aspect *mref_a)
{
	if (mref_a->rfa_bf) {
		return;
	}
	mref_a->rfa_bf = bf;
	atomic_inc(&bf->bf_mref_count);
}

static inline
bool _mref_remove(struct buf_head *bf, struct buf_mref_aspect *mref_a)
{
	//struct mref_object *mref;
	bool status;

	if (!mref_a->rfa_bf) {
		return false;
	}
	mref_a->rfa_bf = NULL;
	CHECK_ATOMIC(&bf->bf_mref_count, 1);
	status = atomic_dec_and_test(&bf->bf_mref_count);
	return status;
}





/////////////////////////////////////////////////////////////7


static inline int _get_info(struct buf_brick *brick)
{
	struct buf_input *input = brick->inputs[0];
	int status = GENERIC_INPUT_CALL(input, mars_get_info, &brick->base_info);
	if (status >= 0)
		brick->got_info = true;
	return status;
}

////////////////// own brick / input / output operations //////////////////

static int buf_get_info(struct buf_output *output, struct mars_info *info)
{
	struct buf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int buf_ref_get(struct buf_output *output, struct mref_object *mref)
{
	struct buf_brick *brick = output->brick;
	struct buf_mref_aspect *mref_a;
	struct buf_head *bf;
	struct buf_head *new = NULL;
	loff_t base_pos;
	int base_offset;
	int max_len;
	int status = -EILSEQ;

	might_sleep();
#if 0
	if (!brick->got_info)
		_get_info(brick);
#endif

#ifdef PRE_ALLOC
	if (unlikely(atomic_read(&brick->alloc_count) < brick->max_count)) {
		// grab all memory in one go => avoid memory fragmentation
		__pre_alloc_bf(brick, brick->max_count + PRE_ALLOC - atomic_read(&brick->alloc_count));
	}
#endif
	/* Grab reference.
	 */
	_CHECK_ATOMIC(&mref->ref_count, !=, 0);
	atomic_inc(&mref->ref_count);

	/* shortcut in case of unbuffered IO
	 */
	if (mref->ref_data) {
		/* Note: unbuffered IO is later indicated by rfa_bf == NULL
		 */
		return 0;
	}

	mref_a = buf_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a))
		goto done;
	
	base_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
	base_offset = (mref->ref_pos - base_pos);
	if (unlikely(base_offset < 0 || base_offset >= brick->backing_size)) {
		MARS_ERR("bad base_offset %d\n", base_offset);
	}

	max_len = brick->backing_size - base_offset;
	if (mref->ref_len > max_len)
		mref->ref_len = max_len;

again:
	bf = _hash_find_insert(brick, base_pos >> (brick->backing_order + PAGE_SHIFT), new);
	if (bf) {
#if 1
		loff_t end_pos = bf->bf_pos + brick->backing_size;
		if (mref->ref_pos < bf->bf_pos || mref->ref_pos >= end_pos) {
			MARS_ERR("hash corruption. %lld not in (%lld ... %lld)\n", mref->ref_pos, bf->bf_pos, end_pos);
		}
#endif
		_remove_bf_list(brick, bf);
		atomic_inc(&brick->hit_count);
		if (unlikely(new)) {
			atomic_inc(&brick->nr_collisions);
			MARS_DBG("race detected: alias appeared in the meantime\n");
			_add_bf_list(brick, new, LIST_FREE, true);
			new = NULL;
		}
	} else if (new) {
		atomic_inc(&brick->miss_count);
		MARS_DBG("new elem added\n");
		bf = new;
		new = NULL;
		bf->bf_chain_detected = false;
	} else {
		MARS_DBG("buf_get() hash nothing found\n");

		new = _fetch_bf(brick);
		if (!new)
			goto done;
#if 1
		// dont initialize new->bf_data
		memset(((void*)new) + sizeof(void*), 0, sizeof(struct buf_head) - sizeof(void*));
#else
		new->bf_flags = 0;
		new->bf_error = 0;
		atomic_set(&new->bf_hash_count, 0);
		atomic_set(&new->bf_mfu_stat, 0);
		atomic_set(&new->bf_chain_len, 0);
		new->bf_chain_detected = false;
#endif
		spin_lock_init(&new->bf_lock);
		new->bf_brick = brick;
		new->bf_pos = base_pos;
		new->bf_base_index = base_pos >> (brick->backing_order + PAGE_SHIFT);
#ifdef OPTIMIZE_FULL_WRITES
		/* Important optimization: treat whole buffer as uptodate
		 * upon full write.
		 */
		if (mref->ref_may_write != READ &&
		   ((!base_offset && mref->ref_len >= brick->backing_size) ||
		    (mref->ref_pos >= brick->base_info.current_size && brick->base_info.current_size > 0))) {
			new->bf_flags |= MREF_UPTODATE;
			atomic_inc(&brick->opt_count);
		}
#endif
		//INIT_LIST_HEAD(&new->bf_mref_anchor);
		INIT_LIST_HEAD(&new->bf_list_head);
		INIT_LIST_HEAD(&new->bf_hash_head);
		INIT_LIST_HEAD(&new->bf_io_pending_anchor);
		INIT_LIST_HEAD(&new->bf_postpone_anchor);

		/* Statistics for read-ahead chain detection
		 */
		if (brick->optimize_chains) {
			struct buf_head *prev_bf;
			prev_bf = _hash_find_insert(brick, new->bf_base_index - 1, NULL);
			if (prev_bf) {
				int chainlen = atomic_read(&prev_bf->bf_chain_len);
				atomic_set(&new->bf_chain_len, chainlen + 1);
				atomic_inc(&brick->chain_count);
				prev_bf->bf_chain_detected = true;
				_bf_put(prev_bf);
			}
		}
		/* Check for races against us...
		 */
		goto again;
	}

	_mref_assign(bf, mref_a);

	MARS_DBG("bf=%p index = %lld flags = %d\n", bf, bf->bf_base_index, bf->bf_flags);

	mref->ref_flags = bf->bf_flags;
	mref->ref_data = bf->bf_data + base_offset;

	CHECK_ATOMIC(&mref->ref_count, 1);
	CHECK_ATOMIC(&bf->bf_hash_count, 1);
	CHECK_ATOMIC(&bf->bf_mref_count, 1);

	status = 0;

done:
	return status;
}

static void _buf_ref_put(struct buf_output *output, struct buf_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	struct buf_head *bf;

	/* shortcut in case of unbuffered IO
	 */
	bf = mref_a->rfa_bf;
	if (!bf) {
		struct buf_brick *brick = output->brick;
		GENERIC_INPUT_CALL(brick->inputs[0], mref_put, mref);
		return;
	}

	CHECK_ATOMIC(&mref->ref_count, 1);

	if (!atomic_dec_and_test(&mref->ref_count))
		return;

	MARS_DBG("buf_ref_put() mref=%p mref_a=%p bf=%p flags=%d\n", mref, mref_a, bf, bf->bf_flags);
	_mref_remove(bf, mref_a);
	buf_free_mref(mref);

	_bf_put(bf); // paired with _hash_find_insert()
}

static void buf_ref_put(struct buf_output *output, struct mref_object *mref)
{
	struct buf_mref_aspect *mref_a;
	mref_a = buf_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return;
	}
	_buf_ref_put(output, mref_a);
}

static void _buf_endio(struct generic_callback *cb);

static int _buf_make_io(struct buf_brick *brick, struct buf_head *bf, void *start_data, loff_t start_pos, int start_len, int rw)
{
	struct buf_input *input;
	int status = EINVAL;
#if 1
	loff_t bf_end = bf->bf_pos + brick->backing_size;
	loff_t end_pos;
	if (start_pos < bf->bf_pos || start_pos >= bf_end) {
		MARS_ERR("bad start_pos %llu (%llu ... %llu)\n", start_pos, bf->bf_pos, bf_end);
		goto done;
	}
	end_pos = start_pos + start_len;
	if (end_pos <= bf->bf_pos || end_pos > bf_end) {
		MARS_ERR("bad end_pos %llu (%llu ... %llu)\n", end_pos, bf->bf_pos, bf_end);
		goto done;
	}
	if (!start_data) {
		MARS_ERR("bad start_data\n");
		goto done;
	}
	if (start_len <= 0) {
		MARS_ERR("bad start_len %d\n", start_len);
		goto done;
	}
#endif

	MARS_DBG("bf = %p rw = %d start = %lld len = %d flags = %d\n", bf, rw, start_pos, start_len, bf->bf_flags);

	atomic_set(&bf->bf_io_count, 0);
	status = -ENOMEM;
	input = brick->inputs[0];

	while (start_len > 0) {
		struct mref_object *mref;
		struct buf_mref_aspect *mref_a;
		int len;

		mref = buf_alloc_mref(brick, &brick->mref_object_layout);
		if (unlikely(!mref))
			break;

		mref_a = buf_mref_get_aspect(brick, mref);
		if (unlikely(!mref_a)) {
			buf_free_mref(mref);
			break;
		}

		mref_a->rfa_bf = bf;
		SETUP_CALLBACK(mref, _buf_endio, mref_a);

		mref->ref_pos = start_pos;
		mref->ref_len = start_len;
		mref->ref_may_write = rw;
		mref->ref_rw = rw;
		mref->ref_data = start_data;

		status = GENERIC_INPUT_CALL(input, mref_get, mref);
		if (status < 0) {
			MARS_ERR("status = %d\n", status);
			goto done;
		}

		/* Remember number of fired-off mrefs
		 */
		atomic_inc(&bf->bf_io_count);
		
		len = mref->ref_len;
		
#ifndef FAKE_IO
		GENERIC_INPUT_CALL(input, mref_io, mref);
#else
		// fake IO for testing
		mref_a->cb.cb_error = status;
		mref_a->cb.cb_fn(&mref_a->cb);
#endif

		GENERIC_INPUT_CALL(input, mref_put, mref);

		start_data += len;
		start_pos += len;
		start_len -= len;
#if 1
		if (start_len > 0)
			MARS_ERR("cannot submit request in one go, rest=%d\n", start_len);
#endif
	}
done:
	return status;
}

static void _buf_endio(struct generic_callback *cb)
{
	struct buf_mref_aspect *bf_mref_a = cb->cb_private;
	struct mref_object *bf_mref;
	struct buf_head *bf;
	struct buf_brick *brick;
	LIST_HEAD(tmp);
	int old_flags;
	unsigned long flags;
	void  *start_data = NULL;
	loff_t start_pos = 0;
	int    start_len = 0;
	int error = cb->cb_error;
#if 1
	int count = 0;
#endif

	CHECK_PTR(bf_mref_a, err);
	bf_mref = bf_mref_a->object;
	CHECK_PTR(bf_mref, err);
	bf = bf_mref_a->rfa_bf;
	CHECK_PTR(bf, err);
	brick = bf->bf_brick;
	CHECK_PTR(brick, err);

	MARS_DBG("_buf_endio() bf_mref_a=%p bf_mref=%p bf=%p flags=%d\n", bf_mref_a, bf_mref, bf, bf->bf_flags);

	if (error < 0)
		bf->bf_error = error;

	// wait until all IO on this bf is completed.
	if (!atomic_dec_and_test(&bf->bf_io_count))
		return;

	MARS_DBG("_buf_endio() ZERO bf=%p\n", bf);

	// get an extra reference, to avoid freeing bf underneath during callbacks
	CHECK_ATOMIC(&bf->bf_hash_count, 1);
	atomic_inc(&bf->bf_hash_count);

	traced_lock(&bf->bf_lock, flags);

	// update flags. this must be done before the callbacks.
	old_flags = bf->bf_flags;
	if (bf->bf_error >= 0 && (old_flags & MREF_READING)) {
		bf->bf_flags |= MREF_UPTODATE;
	}

	// clear the flags, callbacks must not see them. may be re-enabled later.
	bf->bf_flags &= ~(MREF_READING | MREF_WRITING);
	/* Remember current version of pending list.
	 * This is necessary because later the callbacks might
	 * change it underneath.
	 */
	if (!list_empty(&bf->bf_io_pending_anchor)) {
		struct list_head *next = bf->bf_io_pending_anchor.next;
		list_del_init(&bf->bf_io_pending_anchor);
		list_add_tail(&tmp, next);
	}

	/* Move pending jobs to work.
	 * This is in essence an automatic restart mechanism.
	 * do this before the callbacks, because they may start
	 * new IOs. If not done in the right order, this could violate
	 * IO ordering semantics.
	 */
	while (!list_empty(&bf->bf_postpone_anchor)) {
		struct buf_mref_aspect *mref_a = container_of(bf->bf_postpone_anchor.next, struct buf_mref_aspect, rfa_pending_head);
		struct mref_object *mref = mref_a->object;

		if (mref_a->rfa_bf != bf) {
			MARS_ERR("bad pointers %p != %p\n", mref_a->rfa_bf, bf);
		}
#if 1
		if (!(++count % 1000)) {
			MARS_ERR("endless loop 1\n");
		}
#endif
		list_del_init(&mref_a->rfa_pending_head);
		list_add_tail(&mref_a->rfa_pending_head, &bf->bf_io_pending_anchor);

		MARS_DBG("postponed mref=%p\n", mref);

		// re-enable flags
		bf->bf_flags |= MREF_WRITING;
		bf->bf_error = 0;

		if (!start_len) {
			// first time: only flush the affected area
			start_data = mref->ref_data;
			start_pos = mref->ref_pos;
			start_len = mref->ref_len;
		} else if (start_data != mref->ref_data ||
			  start_pos != mref->ref_pos ||
			  start_len != mref->ref_len) {
			// another time: flush larger parts
			loff_t start_diff = mref->ref_pos - start_pos;
			loff_t end_diff;
			if (start_diff < 0) {
				start_data += start_diff;
				start_pos += start_diff;
				start_len -= start_diff;
			}
			end_diff = (mref->ref_pos + mref->ref_len) - (start_pos + start_len);
			if (end_diff > 0) {
				start_len += end_diff;
			}
		}
	}

	traced_unlock(&bf->bf_lock, flags);

	/* Signal success by calling all callbacks.
	 * Thanks to the tmp list, we can do this outside the spinlock.
	 */
	count = 0;
	while (!list_empty(&tmp)) {
		struct buf_mref_aspect *mref_a = container_of(tmp.next, struct buf_mref_aspect, rfa_pending_head);
		struct mref_object *mref = mref_a->object;

		if (mref_a->rfa_bf != bf) {
			MARS_ERR("bad pointers %p != %p\n", mref_a->rfa_bf, bf);
		}
#if 1
		if (!(++count % 1000)) {
			MARS_ERR("endless loop 2\n");
		}
#endif
		CHECK_ATOMIC(&mref->ref_count, 1);
		/* It should be safe to do this without locking, because
		 * tmp is on the stack, so there is no concurrency.
		 */
		list_del_init(&mref_a->rfa_pending_head);

		// update infos for callbacks, they may inspect it.
		mref->ref_flags = bf->bf_flags;

		CHECKED_CALLBACK(mref, bf->bf_error, err);

		atomic_dec(&brick->nr_io_pending);

		_buf_ref_put(brick->outputs[0], mref_a);
	}

	if (start_len) {
		MARS_DBG("ATTENTION restart %d\n", start_len);
		_buf_make_io(brick, bf, start_data, start_pos, start_len, WRITE);
	}
	// drop the extra reference from above
	_bf_put(bf);
	return;

err:
	MARS_FAT("giving up.\n");
}

static void buf_ref_io(struct buf_output *output, struct mref_object *mref)
{
	struct buf_brick *brick = output->brick;
	struct buf_mref_aspect *mref_a;
	struct buf_head *bf;
	void  *start_data = NULL;
	loff_t start_pos = 0;
	int    start_len = 0;
	int status = -EINVAL;
	bool delay = false;
	unsigned long flags;

	if (unlikely(!mref)) {
		MARS_FAT("internal problem: forgotten to supply mref\n");
		goto fatal;
	}
	mref_a = buf_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a)) {
		MARS_ERR("internal problem: mref aspect does not work\n");
		goto fatal;
	}
	/* shortcut in case of unbuffered IO
	 */
	bf = mref_a->rfa_bf;
	if (!bf) {
		GENERIC_INPUT_CALL(brick->inputs[0], mref_io, mref);
		return;
	}

	/* Grab an extra reference.
	 * This will be released later in _bf_endio() after
	 * calling the callbacks.
	 */
	CHECK_ATOMIC(&mref->ref_count, 1);
	atomic_inc(&mref->ref_count);
	CHECK_ATOMIC(&bf->bf_hash_count, 1);

	MARS_DBG("IO mref=%p rw=%d bf=%p flags=%d\n", mref, mref->ref_rw, bf, bf->bf_flags);

	if (mref->ref_rw != READ) {
		loff_t end;
		if (unlikely(mref->ref_may_write == READ)) {
			MARS_ERR("sorry, you have forgotten to set ref_may_write\n");
			goto callback;
		}
		end = mref->ref_pos + mref->ref_len;
		//FIXME: race condition :(
		if (!brick->got_info)
			_get_info(brick);
		if (end > brick->base_info.current_size) {
			brick->base_info.current_size = end;
		}
	}

#if 1
	if (jiffies - brick->last_jiffies >= 30 * HZ) {
		unsigned long hit = atomic_read(&brick->hit_count);
		unsigned long miss = atomic_read(&brick->miss_count);
		unsigned long perc = hit * 100 * 100 / (hit + miss);
		brick->last_jiffies = jiffies;
		MARS_INF("BUF %p STATISTICS: alloc=%d hashed=%d free=%d forget=%d lru=%d io_pending=%d hit=%lu (%lu.%02lu%%) miss=%lu collisions=%d opt=%d chain=%d post=%d write=%d io=%d\n", brick, atomic_read(&brick->alloc_count), atomic_read(&brick->hashed_count), atomic_read(&brick->list_count[LIST_FREE]), atomic_read(&brick->list_count[LIST_FORGET]), atomic_read(&brick->list_count[LIST_LRU]), atomic_read(&brick->nr_io_pending), hit, perc / 100, perc % 100, miss, atomic_read(&brick->nr_collisions), atomic_read(&brick->opt_count), atomic_read(&brick->chain_count), atomic_read(&brick->post_count), atomic_read(&brick->write_count), atomic_read(&brick->io_count));
	}
#endif

	traced_lock(&bf->bf_lock, flags);

	if (!list_empty(&mref_a->rfa_pending_head)) {
		MARS_ERR("trying to start IO on an already started mref\n");
		goto already_done;
	}

	if (mref->ref_rw != 0) { // WRITE
#ifdef FAKE_WRITES
		bf->bf_flags |= MREF_UPTODATE;
		goto already_done;
#endif
		if (bf->bf_flags & MREF_READING) {
			MARS_ERR("bad bf_flags %d\n", bf->bf_flags);
		}
		if (!(bf->bf_flags & MREF_WRITING)) {
#if 0
			// by definition, a writeout buffer is always uptodate
			bf->bf_flags |= (MREF_WRITING | MREF_UPTODATE);
#else // wirklich???
			bf->bf_flags |= MREF_WRITING;
#endif
			bf->bf_error = 0;
#if 1
			start_data = mref->ref_data;
			start_pos = mref->ref_pos;
			start_len = mref->ref_len;
#else // only for testing: write the full buffer
			start_data = (void*)((unsigned long)mref->ref_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
#endif
			list_add(&mref_a->rfa_pending_head, &bf->bf_io_pending_anchor);
			delay = true;
		} else {
			list_add(&mref_a->rfa_pending_head, &bf->bf_postpone_anchor);
			atomic_inc(&brick->post_count);
			delay = true;
			MARS_DBG("postponing %lld %d\n", mref->ref_pos, mref->ref_len);
		}
	} else { // READ
#ifdef FAKE_READS
		bf->bf_flags |= MREF_UPTODATE;
		goto already_done;
#endif
#if 0
		if (bf->bf_flags & (MREF_UPTODATE | MREF_WRITING))
#else
		if (bf->bf_flags & MREF_UPTODATE)
#endif
			goto already_done;
		if (!(bf->bf_flags & MREF_READING)) {
			bf->bf_flags |= MREF_READING;
			bf->bf_error = 0;

			// always read the whole buffer.
			start_data = (void*)((unsigned long)mref->ref_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
		}
		list_add(&mref_a->rfa_pending_head, &bf->bf_io_pending_anchor);
		delay = true;
	}

	if (likely(delay)) {
		atomic_inc(&brick->nr_io_pending);
		atomic_inc(&brick->io_count);
		if (mref->ref_rw != 0)
			atomic_inc(&brick->write_count);
	}

	traced_unlock(&bf->bf_lock, flags);

	if (!start_len) {
		// nothing to start, IO is already started.
		goto no_callback;
	}

	status = _buf_make_io(brick, bf, start_data, start_pos, start_len, mref->ref_rw);
	if (likely(status >= 0)) {
		/* No immediate callback, this time.
		 * Callbacks will be called later from _bf_endio().
		 */
		goto no_callback;
	}

	MARS_ERR("error %d during buf_ref_io()\n", status);
	buf_ref_put(output, mref);
	goto callback;

already_done:
	status = bf->bf_error;

	traced_unlock(&bf->bf_lock, flags);

callback:
	mref->ref_flags = bf->bf_flags;
	CHECKED_CALLBACK(mref, status, fatal);

no_callback:
	if (!delay) {
		buf_ref_put(output, mref);
	} // else the ref_put() will be carried out upon IO completion.

	return;
fatal: // no chance to call callback: may produce hanging tasks :(
	MARS_FAT("no chance to call callback, tasks may hang.\n");
}

//////////////// object / aspect constructors / destructors ///////////////

static int buf_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct buf_mref_aspect *ini = (void*)_ini;
	ini->rfa_bf = NULL;
	INIT_LIST_HEAD(&ini->rfa_pending_head);
	//INIT_LIST_HEAD(&ini->tmp_head);
	return 0;
}

static void buf_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct buf_mref_aspect *ini = (void*)_ini;
	(void)ini;
#if 1
	CHECK_HEAD_EMPTY(&ini->rfa_pending_head);
	//CHECK_HEAD_EMPTY(&ini->tmp_head);
#endif
}

MARS_MAKE_STATICS(buf);

////////////////////// brick constructors / destructors ////////////////////

static int buf_brick_construct(struct buf_brick *brick)
{
	int i;
	brick->backing_order = 0;
	brick->backing_size = PAGE_SIZE;
	brick->max_count = 32;
	spin_lock_init(&brick->brick_lock);
	for (i = 0; i < LIST_MAX; i++) {
		INIT_LIST_HEAD(&brick->list_anchor[i]);
	}
	for (i = 0; i < MARS_BUF_HASH_MAX; i++) {
		spin_lock_init(&brick->cache_anchors[i].hash_lock);
		INIT_LIST_HEAD(&brick->cache_anchors[i].hash_anchor);
	}
	return 0;
}

static int buf_output_construct(struct buf_output *output)
{
	return 0;
}

static int buf_brick_destruct(struct buf_brick *brick)
{
	int i;

	brick->max_count = 0;
	_prune_cache(brick, 0);

	for (i = 0; i < LIST_MAX; i++) {
		CHECK_HEAD_EMPTY(&brick->list_anchor[i]);
	}
	for (i = 0; i < MARS_BUF_HASH_MAX; i++) {
		CHECK_HEAD_EMPTY(&brick->cache_anchors[i].hash_anchor);
	}

	return 0;
}

///////////////////////// static structs ////////////////////////

static struct buf_brick_ops buf_brick_ops = {
};

static struct buf_output_ops buf_output_ops = {
	.mars_get_info = buf_get_info,
	.mref_get = buf_ref_get,
	.mref_put = buf_ref_put,
	.mref_io = buf_ref_io,
};

const struct buf_input_type buf_input_type = {
	.type_name = "buf_input",
	.input_size = sizeof(struct buf_input),
};

static const struct buf_input_type *buf_input_types[] = {
	&buf_input_type,
};

const struct buf_output_type buf_output_type = {
	.type_name = "buf_output",
	.output_size = sizeof(struct buf_output),
	.master_ops = &buf_output_ops,
	.output_construct = &buf_output_construct,
};

static const struct buf_output_type *buf_output_types[] = {
	&buf_output_type,
};

const struct buf_brick_type buf_brick_type = {
	.type_name = "buf_brick",
	.brick_size = sizeof(struct buf_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &buf_brick_ops,
	.aspect_types = buf_aspect_types,
	.default_input_types = buf_input_types,
	.default_output_types = buf_output_types,
	.brick_construct = &buf_brick_construct,
	.brick_destruct = &buf_brick_destruct,
};
EXPORT_SYMBOL_GPL(buf_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_buf(void)
{
	MARS_INF("init_buf()\n");
	return buf_register_brick_type();
}

void __exit exit_mars_buf(void)
{
	MARS_INF("exit_buf()\n");
	buf_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS buf brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_buf);
module_exit(exit_mars_buf);
#endif
