// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Buf brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/delay.h>

#include "mars.h"

//#define USE_VMALLOC
//#define FAKE_IO

///////////////////////// own type definitions ////////////////////////

#include "mars_buf.h"

#define PRE_ALLOC 8

///////////////////////// own helper functions ////////////////////////

static inline int buf_hash_fn(loff_t base_index)
{
	// simple and stupid
	loff_t tmp;
	tmp = base_index ^ (base_index / MARS_BUF_HASH_MAX);
	tmp += tmp / 13;
	tmp ^= tmp / (MARS_BUF_HASH_MAX * MARS_BUF_HASH_MAX);
	return tmp % MARS_BUF_HASH_MAX;
}

static struct buf_head *hash_find_insert(struct buf_brick *brick, loff_t base_index, struct buf_head *new)
{
	
	int hash = buf_hash_fn(base_index);
	spinlock_t *lock = &brick->cache_anchors[hash].hash_lock;
	struct list_head *start	= &brick->cache_anchors[hash].hash_anchor;
	struct list_head *tmp;
	struct buf_head *res;
	int count = 0;
	unsigned long flags;

	traced_lock(lock, flags);

	for (tmp = start->next; tmp != start; tmp = tmp->next) {
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
			int old_bf_count = atomic_read(&res->bf_count);
			CHECK_ATOMIC(&res->bf_count, 0);
			atomic_inc(&res->bf_count);

			traced_unlock(lock, flags);

			if (true || old_bf_count <= 0) {
				traced_lock(&brick->brick_lock, flags);
				if (!list_empty(&res->bf_lru_head)) {
					list_del_init(&res->bf_lru_head);
					atomic_dec(&brick->lru_count);
				}
				traced_unlock(&brick->brick_lock, flags);
			}
			return res;
		}
	}

	if (new) {
		atomic_inc(&brick->hashed_count);
		CHECK_HEAD_EMPTY(&new->bf_hash_head);
		list_add(&new->bf_hash_head, start);
	}

	traced_unlock(lock, flags);

	return NULL;
}

static inline void free_bf(struct buf_brick *brick, struct buf_head *bf)
{
	atomic_dec(&brick->alloc_count);
	MARS_INF("really freeing bf=%p\n", bf);
	CHECK_HEAD_EMPTY(&bf->bf_lru_head);
	CHECK_HEAD_EMPTY(&bf->bf_hash_head);
	CHECK_HEAD_EMPTY(&bf->bf_io_pending_anchor);
	CHECK_HEAD_EMPTY(&bf->bf_postpone_anchor);
#ifdef USE_VMALLOC
	vfree(bf->bf_data);
#else
	free_pages((unsigned long)bf->bf_data, brick->backing_order);
#endif
	kfree(bf);
}

/* brick->brick_lock must be held
 */
static inline void __prune_cache(struct buf_brick *brick, int max_count, unsigned long *flags)
{
#if 0
	return;
#endif
	while (atomic_read(&brick->alloc_count) >= max_count) {
		struct buf_head *bf;
		if (list_empty(&brick->free_anchor))
			break;
		bf = container_of(brick->free_anchor.next, struct buf_head, bf_lru_head);
		list_del_init(&bf->bf_lru_head);
		
		traced_unlock(&brick->brick_lock, *flags);

		free_bf(brick, bf);

		traced_lock(&brick->brick_lock, *flags);
	}
}

static inline bool __remove_from_hash(struct buf_brick *brick, struct buf_head *bf, bool force)
{
	int hash;
	spinlock_t *lock;
	unsigned long flags;
	bool ok = false;

	hash = buf_hash_fn(bf->bf_base_index);
	lock = &brick->cache_anchors[hash].hash_lock;

	traced_lock(lock, flags);

	/* Attention! In seldom cases, the hash lock can race against the
	 * brick lock upon hash_find_insert().
	 * Be careful!
	 */
	if (likely(force || !atomic_read(&bf->bf_count))) {
		list_del_init(&bf->bf_hash_head);
		atomic_dec(&brick->hashed_count);
		ok = true;
	}

	traced_unlock(lock, flags);
	return ok;
}

static inline void __lru_free_one(struct buf_brick *brick, unsigned long *flags)
{
	struct buf_head *bf;
	bool ok;

	if (list_empty(&brick->lru_anchor))
		return;

	bf = container_of(brick->lru_anchor.prev, struct buf_head, bf_lru_head);

	list_del_init(&bf->bf_lru_head);
	atomic_dec(&brick->lru_count);

	/* Attention! In seldom cases, the hash lock can race against the
	 * brick lock upon hash_find_insert().
	 * Be careful!
	 */
	if (unlikely(atomic_read(&bf->bf_count) > 0))
		return;

        //traced_unlock(&brick->brick_lock, *flags);

	ok = __remove_from_hash(brick, bf, false);

        //traced_lock(&brick->brick_lock, *flags);

	if (likely(ok)) {
		list_add(&bf->bf_lru_head, &brick->free_anchor);
	} else {
		list_add(&bf->bf_lru_head, &brick->lru_anchor);
		MARS_INF("oops, cannot free %p (bf_count=%d)\n", bf, atomic_read(&bf->bf_count));
	}
}


static inline void __lru_free(struct buf_brick *brick, unsigned long *flags)
{
	while (atomic_read(&brick->hashed_count) >= brick->max_count) {
		if (list_empty(&brick->lru_anchor))
			break;
		__lru_free_one(brick, flags);
	}
}


static inline int get_info(struct buf_brick *brick)
{
	struct buf_input *input = brick->inputs[0];
	int status = GENERIC_INPUT_CALL(input, mars_get_info, &brick->base_info);
	return status;
}

static inline struct buf_head *_alloc_bf(struct buf_brick *brick)
{
	struct buf_head *bf = kzalloc(sizeof(struct buf_head), GFP_MARS);
	if (!bf)
		goto done;

#ifdef USE_VMALLOC
	bf->bf_data = vmalloc(brick->backing_size);
#else
	bf->bf_data = (void*)__get_free_pages(GFP_MARS, brick->backing_order);
#endif
	if (unlikely(!bf->bf_data)) {
		kfree(bf);
		bf = NULL;
	}

	spin_lock_init(&bf->bf_lock);
	bf->bf_brick = brick;
	atomic_inc(&brick->alloc_count);

done:
	return bf;
}

static void __pre_alloc_bf(struct buf_brick *brick, int max)
{
	while (max-- > 0) {
		struct buf_head *bf = _alloc_bf(brick);
		unsigned long flags;

		if (unlikely(!bf))
			break;

		traced_lock(&brick->brick_lock, flags);

		list_add(&bf->bf_lru_head, &brick->free_anchor);

		traced_unlock(&brick->brick_lock, flags);
	}
}

////////////////// own brick / input / output operations //////////////////

static int buf_get_info(struct buf_output *output, struct mars_info *info)
{
	struct buf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static void __bf_put(struct buf_head *bf)
{
	struct buf_brick *brick;
	unsigned long flags;

	brick = bf->bf_brick;

	traced_lock(&brick->brick_lock, flags);

	CHECK_ATOMIC(&bf->bf_count, 1);
	if (!atomic_dec_and_test(&bf->bf_count)) {
		traced_unlock(&brick->brick_lock, flags);
		return;
	}

	MARS_DBG("ZERO_COUNT\n");
	if (unlikely(!list_empty(&bf->bf_io_pending_anchor))) {
		MARS_ERR("bf_io_pending_anchor is not empty!\n");
	}
	if (unlikely(!list_empty(&bf->bf_postpone_anchor))) {
		MARS_ERR("bf_postpone_anchor is not empty!\n");
	}
	CHECK_HEAD_EMPTY(&bf->bf_lru_head);

	atomic_inc(&brick->lru_count);
	atomic_inc(&bf->bf_mfu_stat);

	if (likely(bf->bf_flags & MARS_REF_UPTODATE) && !bf->bf_chain_detected) {
		list_add(&bf->bf_lru_head, &brick->lru_anchor);
	} else {
		list_add_tail(&bf->bf_lru_head, &brick->lru_anchor);
	}

	// lru freeing (this is completely independent from bf)
	__lru_free(brick, &flags);
	__prune_cache(brick, brick->max_count * 2, &flags);

	traced_unlock(&brick->brick_lock, flags);
}

static int buf_ref_get(struct buf_output *output, struct mars_ref_object *mref)
{
	struct buf_brick *brick = output->brick;
	struct buf_mars_ref_aspect *mref_a;
	struct buf_head *bf;
	struct buf_head *new = NULL;
	loff_t base_pos;
	int base_offset;
	int max_len;
	unsigned long flags;
	int status = -EILSEQ;

	might_sleep();

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

	mref_a = buf_mars_ref_get_aspect(output, mref);
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
	bf = hash_find_insert(brick, base_pos >> (brick->backing_order + PAGE_SHIFT), new);
	if (bf) {
#if 1
		loff_t end_pos = bf->bf_pos + brick->backing_size;
		if (mref->ref_pos < bf->bf_pos || mref->ref_pos >= end_pos) {
			MARS_ERR("hash corruption. %lld not in (%lld ... %lld)\n", mref->ref_pos, bf->bf_pos, end_pos);
		}
#endif
		atomic_inc(&brick->hit_count);
		if (unlikely(new)) {
			atomic_inc(&brick->nr_collisions);
			MARS_DBG("race detected: alias elem appeared in the meantime\n");
			traced_lock(&brick->brick_lock, flags);

			list_del(&new->bf_lru_head);
			list_add(&new->bf_lru_head, &brick->free_anchor);

			traced_unlock(&brick->brick_lock, flags);
			new = NULL;
		}
	} else if (new) {
		atomic_inc(&brick->miss_count);
		MARS_DBG("new elem added\n");
		bf = new;
		new = NULL;
	} else {
		MARS_DBG("buf_get() hash nothing found\n");

		traced_lock(&brick->brick_lock, flags);

		if (list_empty(&brick->free_anchor)) {
			__lru_free_one(brick, &flags);
			if (unlikely(list_empty(&brick->free_anchor))) {
				MARS_INF("alloc new buf_head %d\n", atomic_read(&brick->alloc_count));

				traced_unlock(&brick->brick_lock, flags);

				status = -ENOMEM;
				bf = _alloc_bf(brick);
				if (!bf)
					goto done;
				
				traced_lock(&brick->brick_lock, flags);
			
				list_add(&bf->bf_lru_head, &brick->free_anchor);
				traced_unlock(&brick->brick_lock, flags);

				/* during the open lock, somebody might have
				 * raced against us at the same base_pos...
				 */
				goto again;
			}
		}
			
		new = container_of(brick->free_anchor.next, struct buf_head, bf_lru_head);
		list_del_init(&new->bf_lru_head);

		traced_unlock(&brick->brick_lock, flags);

		new->bf_pos = base_pos;
		new->bf_base_index = base_pos >> (brick->backing_order + PAGE_SHIFT);
		new->bf_flags = 0;
		/* Important optimization: treat whole buffer as uptodate
		 * upon full write.
		 */
		if (mref->ref_may_write != READ &&
		   ((!base_offset && mref->ref_len >= brick->backing_size) ||
		    (mref->ref_pos >= brick->base_info.current_size))) {
			new->bf_flags |= MARS_REF_UPTODATE;
			atomic_inc(&brick->opt_count);
		}
		new->bf_error = 0;
		atomic_set(&new->bf_count, 1);
		atomic_set(&new->bf_mfu_stat, 0);
		atomic_set(&new->bf_chain_len, 0);
		new->bf_chain_detected = false;
		//INIT_LIST_HEAD(&new->bf_mref_anchor);
		//INIT_LIST_HEAD(&new->bf_lru_head);
		INIT_LIST_HEAD(&new->bf_hash_head);
		INIT_LIST_HEAD(&new->bf_io_pending_anchor);
		INIT_LIST_HEAD(&new->bf_postpone_anchor);

		/* Statistics for read-ahead chain detection
		 */
		if (brick->optimize_chains) {
			struct buf_head *prev_bf;
			prev_bf = hash_find_insert(brick, new->bf_base_index - 1, NULL);
			if (prev_bf) {
				int chainlen = atomic_read(&prev_bf->bf_chain_len);
				atomic_set(&new->bf_chain_len, chainlen + 1);
				atomic_inc(&brick->chain_count);
				prev_bf->bf_chain_detected = true;
				__bf_put(prev_bf);
			}
		}
		/* Check for races against us...
		 */
		goto again;
	}

	mref_a->rfa_bf = bf;

	MARS_DBG("bf=%p initial bf_count=%d\n", bf, atomic_read(&bf->bf_count));

	mref->ref_flags = bf->bf_flags;

	mref->ref_data = bf->bf_data + base_offset;

	CHECK_ATOMIC(&mref->ref_count, 1);

	//return mref->ref_len;
	status = 0;

done:
	return status;
}

static void _buf_ref_put(struct buf_output *output, struct buf_mars_ref_aspect *mref_a)
{
	struct mars_ref_object *mref = mref_a->object;
	struct buf_head *bf;

	/* shortcut in case of unbuffered IO
	 */
	bf = mref_a->rfa_bf;
	if (!bf) {
		struct buf_brick *brick = output->brick;
		GENERIC_INPUT_CALL(brick->inputs[0], mars_ref_put, mref);
		return;
	}

	CHECK_ATOMIC(&mref->ref_count, 1);

	if (!atomic_dec_and_test(&mref->ref_count))
		return;

	MARS_DBG("buf_ref_put() mref=%p mref_a=%p bf=%p\n", mref, mref_a, bf);
	__bf_put(bf);

	buf_free_mars_ref(mref);
}

static void buf_ref_put(struct buf_output *output, struct mars_ref_object *mref)
{
	struct buf_mars_ref_aspect *mref_a;
	mref_a = buf_mars_ref_get_aspect(output, mref);
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

	atomic_set(&bf->bf_io_count, 0);
	status = -ENOMEM;
	input = brick->inputs[0];

	while (start_len > 0) {
		struct mars_ref_object *mref;
		struct buf_mars_ref_aspect *mref_a;
		int len;

		mref = buf_alloc_mars_ref(brick->outputs[0], &brick->mref_object_layout);
		if (unlikely(!mref))
			break;

		mref_a = buf_mars_ref_get_aspect(brick->outputs[0], mref);
		if (unlikely(!mref_a)) {
			buf_free_mars_ref(mref);
			break;
		}

		mref_a->rfa_bf = bf;
		mref_a->cb.cb_fn = _buf_endio;
		mref_a->cb.cb_private = mref_a;
		mref_a->cb.cb_error = 0;
		mref_a->cb.cb_prev = NULL;
		mref->ref_cb = &mref_a->cb;

		mref->ref_pos = start_pos;
		mref->ref_len = start_len;
		mref->ref_may_write = rw;
		mref->ref_data = start_data;

		status = GENERIC_INPUT_CALL(input, mars_ref_get, mref);
		if (status < 0) {
			MARS_ERR();
			goto done;
		}

		/* Remember number of fired-off mrefs
		 */
		atomic_inc(&bf->bf_io_count);
		
		len = mref->ref_len;
		
#ifndef FAKE_IO
		GENERIC_INPUT_CALL(input, mars_ref_io, mref, rw);
#else
		// fake IO for testing
		mref_a->cb.cb_error = status;
		mref_a->cb.cb_fn(&mref_a->cb);
#endif

		GENERIC_INPUT_CALL(input, mars_ref_put, mref);

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
	struct buf_mars_ref_aspect *bf_mref_a = cb->cb_private;
	struct mars_ref_object *bf_mref;
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
	MARS_DBG("_buf_endio() bf_mref_a=%p bf_mref=%p\n", bf_mref_a, bf_mref);
	CHECK_PTR(bf_mref, err);
	bf = bf_mref_a->rfa_bf;
	CHECK_PTR(bf, err);
	brick = bf->bf_brick;
	CHECK_PTR(brick, err);

	if (error < 0)
		bf->bf_error = error;

	// wait until all IO on this bf is completed.
	if (!atomic_dec_and_test(&bf->bf_io_count))
		return;

	// get an extra reference, to avoid freeing bf underneath during callbacks
	CHECK_ATOMIC(&bf->bf_count, 1);
	atomic_inc(&bf->bf_count);

	traced_lock(&bf->bf_lock, flags);

	// update flags. this must be done before the callbacks.
	old_flags = bf->bf_flags;
	if (bf->bf_error >= 0 && (old_flags & MARS_REF_READING)) {
		bf->bf_flags |= MARS_REF_UPTODATE;
	}
	// clear the flags, callbacks must not see them. may be re-enabled later.
	bf->bf_flags &= ~(MARS_REF_READING | MARS_REF_WRITING);

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
		struct buf_mars_ref_aspect *mref_a = container_of(bf->bf_postpone_anchor.next, struct buf_mars_ref_aspect, rfa_pending_head);
		struct mars_ref_object *mref = mref_a->object;

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

		// re-enable flags
		bf->bf_flags |= MARS_REF_WRITING;
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
		struct buf_mars_ref_aspect *mref_a = container_of(tmp.next, struct buf_mars_ref_aspect, rfa_pending_head);
		struct mars_ref_object *mref = mref_a->object;
		struct generic_callback *cb = mref->ref_cb;

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
		cb->cb_error = bf->bf_error;

		atomic_dec(&brick->nr_io_pending);

		cb->cb_fn(cb);

		_buf_ref_put(brick->outputs[0], mref_a);
	}

	if (start_len) {
		MARS_DBG("ATTENTION restart %d\n", start_len);
		_buf_make_io(brick, bf, start_data, start_pos, start_len, WRITE);
	}
	// drop the extra reference from above
	__bf_put(bf);

err:;
}

static void buf_ref_io(struct buf_output *output, struct mars_ref_object *mref, int rw)
{
	struct buf_brick *brick = output->brick;
	struct buf_mars_ref_aspect *mref_a;
	struct generic_callback *cb;
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
	mref_a = buf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_ERR("internal problem: mref aspect does not work\n");
		goto fatal;
	}
	/* shortcut in case of unbuffered IO
	 */
	bf = mref_a->rfa_bf;
	if (!bf) {
		GENERIC_INPUT_CALL(brick->inputs[0], mars_ref_io, mref, rw);
		return;
	}

	/* Grab an extra reference.
	 * This will be released later in _bf_endio() after
	 * calling the callbacks.
	 */
	CHECK_ATOMIC(&mref->ref_count, 1);
	atomic_inc(&mref->ref_count);
	CHECK_ATOMIC(&bf->bf_count, 1);

	if (rw != READ) {
		loff_t end;
		if (unlikely(mref->ref_may_write == READ)) {
			MARS_ERR("sorry, you have forgotten to set ref_may_write\n");
			goto callback;
		}
		if (unlikely(!(bf->bf_flags & MARS_REF_UPTODATE))) {
			MARS_ERR("sorry, writing is only allowed on UPTODATE buffers\n");
			goto callback;
		}
		end = mref->ref_pos + mref->ref_len;
		//FIXME: race condition :(
		if (end > brick->base_info.current_size) {
			brick->base_info.current_size = end;
		}
	}

	mref->ref_rw = rw;

#if 1
	if (jiffies - brick->last_jiffies >= 30 * HZ) {
		unsigned long hit = atomic_read(&brick->hit_count);
		unsigned long miss = atomic_read(&brick->miss_count);
		unsigned long perc = hit * 100 * 100 / (hit + miss);
		brick->last_jiffies = jiffies;
		MARS_INF("BUF %p STATISTICS: hashed=%d lru=%d alloc=%d io_pending=%d hit=%lu (%lu.%02lu%%) miss=%lu collisions=%d opt=%d chain=%d post=%d write=%d io=%d\n", brick, atomic_read(&brick->hashed_count), atomic_read(&brick->lru_count), atomic_read(&brick->alloc_count), atomic_read(&brick->nr_io_pending), hit, perc / 100, perc % 100, miss, atomic_read(&brick->nr_collisions), atomic_read(&brick->opt_count), atomic_read(&brick->chain_count), atomic_read(&brick->post_count), atomic_read(&brick->write_count), atomic_read(&brick->io_count));
	}
#endif

	traced_lock(&bf->bf_lock, flags);

	if (!list_empty(&mref_a->rfa_pending_head)) {
		MARS_ERR("trying to start IO on an already started mref\n");
		goto already_done;
	}

	if (rw) { // WRITE
		if (bf->bf_flags & MARS_REF_READING) {
			MARS_ERR("bad bf_flags %d\n", bf->bf_flags);
		}
		if (!(bf->bf_flags & MARS_REF_WRITING)) {
			// by definition, a writeout buffer is always uptodate
			bf->bf_flags |= (MARS_REF_WRITING | MARS_REF_UPTODATE);
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
		if (bf->bf_flags & (MARS_REF_UPTODATE | MARS_REF_WRITING)) {
			goto already_done;
		}
		if (!(bf->bf_flags & MARS_REF_READING)) {
			bf->bf_flags |= MARS_REF_READING;
			bf->bf_error = 0;

			// always read the whole buffer.
			start_data = (void*)((unsigned long)mref->ref_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
		}
		list_add(&mref_a->rfa_pending_head, &bf->bf_io_pending_anchor);
		delay = true;
	}

	mref->ref_flags = bf->bf_flags;
	mref->ref_cb->cb_error = bf->bf_error;

	if (likely(delay)) {
		atomic_inc(&brick->nr_io_pending);
		atomic_inc(&brick->io_count);
		if (rw)
			atomic_inc(&brick->write_count);
	}

	traced_unlock(&bf->bf_lock, flags);

	if (!start_len) {
		// nothing to start, IO is already started.
		goto no_callback;
	}

	status = _buf_make_io(brick, bf, start_data, start_pos, start_len, rw);
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
	mref->ref_flags = bf->bf_flags;
	status = bf->bf_error;

	traced_unlock(&bf->bf_lock, flags);

callback:
	cb = mref->ref_cb;
	cb->cb_error = status;

	cb->cb_fn(cb);

no_callback:
	if (!delay) {
		buf_ref_put(output, mref);
	} // else the ref_put() will be later carried out upon IO completion.

fatal: // no chance to call callback: may produce hanging tasks :(
	;
}

//////////////// object / aspect constructors / destructors ///////////////

static int buf_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct buf_mars_ref_aspect *ini = (void*)_ini;
	ini->rfa_bf = NULL;
	INIT_LIST_HEAD(&ini->rfa_pending_head);
	INIT_LIST_HEAD(&ini->tmp_head);
	return 0;
}

static void buf_mars_ref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct buf_mars_ref_aspect *ini = (void*)_ini;
	(void)ini;
#if 1
	CHECK_HEAD_EMPTY(&ini->rfa_pending_head);
	CHECK_HEAD_EMPTY(&ini->tmp_head);
#endif
}

MARS_MAKE_STATICS(buf);

////////////////////// brick constructors / destructors ////////////////////

static int buf_brick_construct(struct buf_brick *brick)
{
	int i;
	brick->backing_order = 0;
	brick->backing_size = PAGE_SIZE << brick->backing_order;
	brick->max_count = 32;
	atomic_set(&brick->alloc_count, 0);
	atomic_set(&brick->hashed_count, 0);
	atomic_set(&brick->lru_count, 0);
	atomic_set(&brick->nr_io_pending, 0);
	atomic_set(&brick->nr_collisions, 0);
	spin_lock_init(&brick->brick_lock);
	//rwlock_init(&brick->brick_lock);
	INIT_LIST_HEAD(&brick->free_anchor);
	INIT_LIST_HEAD(&brick->lru_anchor);
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
	unsigned long flags;

	traced_lock(&brick->brick_lock, flags);

	brick->max_count = 0;
	__lru_free(brick, &flags);
	__prune_cache(brick, 0, &flags);

	traced_unlock(&brick->brick_lock, flags);

	CHECK_HEAD_EMPTY(&brick->free_anchor);
	CHECK_HEAD_EMPTY(&brick->lru_anchor);

	for (i = 0; i < MARS_BUF_HASH_MAX; i++) {
		CHECK_HEAD_EMPTY(&brick->cache_anchors[i].hash_anchor);
	}

	return 0;
}

///////////////////////// static structs ////////////////////////

static struct buf_brick_ops buf_brick_ops = {
};

static struct buf_output_ops buf_output_ops = {
	.make_object_layout = buf_make_object_layout,
	.mars_get_info = buf_get_info,
	.mars_ref_get = buf_ref_get,
	.mars_ref_put = buf_ref_put,
	.mars_ref_io = buf_ref_io,
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
	.aspect_types = buf_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_ALL,
	}
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
	.default_input_types = buf_input_types,
	.default_output_types = buf_output_types,
	.brick_construct = &buf_brick_construct,
	.brick_destruct = &buf_brick_destruct,
};
EXPORT_SYMBOL_GPL(buf_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_buf(void)
{
	printk(MARS_INFO "init_buf()\n");
	return buf_register_brick_type();
}

static void __exit exit_buf(void)
{
	printk(MARS_INFO "exit_buf()\n");
	buf_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS buf brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_buf);
module_exit(exit_buf);
