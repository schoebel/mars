/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* FIXME: this code has been unused for a long time, it is unlikly
 * to work at all.
 */

/*  #define BRICK_DEBUGGING */
/*  #define XIO_DEBUGGING */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/delay.h>

#include "../xio.h"

/*  #define FAKE_IO // only for testing */
/*  #define FAKE_READS // only for testing */
/*  #define FAKE_WRITES // only for testing */

/*  #define OPTIMIZE_FULL_WRITES // does not work currently! */

/************************ own type definitions ***********************/

#include "xio_buf.h"

#define PRE_ALLOC			8

/************************ own helper functions ***********************/

static inline
int buf_hash_fn(loff_t base_index)
{
	/*  simple and stupid */
	loff_t tmp;

	tmp = base_index ^ (base_index / XIO_BUF_HASH_MAX);
	/* tmp ^ = tmp / (XIO_BUF_HASH_MAX * XIO_BUF_HASH_MAX); */
	return ((unsigned)tmp) % XIO_BUF_HASH_MAX;
}

static
struct buf_head *_hash_find_insert(struct buf_brick *brick, loff_t base_index, struct buf_head *new)
{

	int hash = buf_hash_fn(base_index);
	spinlock_t *lock = &brick->cache_anchors[hash].hash_lock;
	struct list_head *start = &brick->cache_anchors[hash].hash_anchor;
	struct list_head *tmp;
	int count = 0;
	unsigned long flags;

	spin_lock_irqsave(lock, flags);

	for (tmp = start->next; tmp != start; tmp = tmp->next) {
		struct buf_head *res;

#if 1
		if (!tmp) {
			XIO_ERR("tmp is NULL! brick = %p base_index = %lld hash = %d new = %p\n",
				brick,
				base_index,
				hash,
				new);
			/* dump_stack(); */
			spin_unlock_irqrestore(lock, flags);
			return NULL;
		}
#endif
#if 1
		{
			static int max;

			if (++count > max) {
				max = count;
				if (!(max % 10))
					XIO_INF("hash maxlen=%d hash=%d base_index=%llu\n", max, hash, base_index);
			}
		}
#endif
		res = container_of(tmp, struct buf_head, bf_hash_head);
		if (res->bf_base_index == base_index) { /*  found */
			/* This must be paired with _bf_put()
			 */
			atomic_inc(&res->bf_hash_count);
			spin_unlock_irqrestore(lock, flags);
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

	spin_unlock_irqrestore(lock, flags);

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

	spin_lock_irqsave(lock, flags);

	if (likely(!atomic_read(&bf->bf_hash_count) && !atomic_read(&bf->bf_aio_count) && !atomic_read(&bf->bf_io_count))) {
		success = true;
		if (likely(!list_empty(&bf->bf_hash_head))) {
			list_del_init(&bf->bf_hash_head);
			atomic_dec(&brick->hashed_count);
		}
	}

	spin_unlock_irqrestore(lock, flags);

	return success;
}

static inline
void _add_bf_list(struct buf_brick *brick, struct buf_head *bf, int nr, bool at_end)
{
	unsigned long flags;

#if 1
	if (nr < 0 || nr >= LIST_MAX)
		XIO_FAT("bad nr %d\n", nr);
#endif

	spin_lock_irqsave(&brick->brick_lock, flags);

	atomic_inc(&brick->list_count[nr]);
	if (!list_empty(&bf->bf_list_head)) {
		atomic_dec(&brick->list_count[bf->bf_member]);
		list_del(&bf->bf_list_head);
	}
	if (at_end)
		list_add_tail(&bf->bf_list_head, &brick->list_anchor[nr]);
	else
		list_add(&bf->bf_list_head, &brick->list_anchor[nr]);
	bf->bf_member = nr;
	bf->bf_jiffies = jiffies;

	spin_unlock_irqrestore(&brick->brick_lock, flags);
}

static inline
struct buf_head *_fetch_bf_list(struct buf_brick *brick, int nr, unsigned long age)
{
	struct buf_head *bf = NULL;
	unsigned long flags;

#if 1
	if (nr < 0 || nr >= LIST_MAX)
		XIO_FAT("bad nr %d\n", nr);
#endif

	spin_lock_irqsave(&brick->brick_lock, flags);

	if (!list_empty(&brick->list_anchor[nr])) {
		bf = container_of(brick->list_anchor[nr].prev, struct buf_head, bf_list_head);
#if 1
		if (age != 0 && jiffies - bf->bf_jiffies < age) {
			spin_unlock(&brick->brick_lock);
			return NULL;
		}
#endif
		atomic_dec(&brick->list_count[nr]);
		list_del_init(&bf->bf_list_head);
	}

	spin_unlock_irqrestore(&brick->brick_lock, flags);

	return bf;
}

static inline
void _remove_bf_list(struct buf_brick *brick, struct buf_head *bf)
{
	unsigned long flags;

#if 1
	if (bf->bf_member < 0 || bf->bf_member >= LIST_MAX)
		XIO_FAT("bad nr %d\n", bf->bf_member);
#endif
	spin_lock_irqsave(&brick->brick_lock, flags);

	if (!list_empty(&bf->bf_list_head)) {
		list_del_init(&bf->bf_list_head);
		atomic_dec(&brick->list_count[bf->bf_member]);
	}

	spin_unlock_irqrestore(&brick->brick_lock, flags);
}

static inline
struct buf_head *_alloc_bf(struct buf_brick *brick)
{
	struct buf_head *bf = brick_zmem_alloc(sizeof(struct buf_head));

	bf->bf_data = (void *)__get_free_pages(GFP_BRICK, brick->backing_order);

	atomic_inc(&brick->alloc_count);

	return bf;
}

static inline
void _dealloc_bf(struct buf_brick *brick, struct buf_head *bf)
{
	XIO_INF("really freeing bf=%p\n", bf);
	_CHECK_ATOMIC(&bf->bf_hash_count, !=, 0);
	_CHECK_ATOMIC(&bf->bf_aio_count, !=, 0);
	_CHECK_ATOMIC(&bf->bf_io_count, !=, 0);
	CHECK_HEAD_EMPTY(&bf->bf_list_head);
	CHECK_HEAD_EMPTY(&bf->bf_hash_head);
	CHECK_HEAD_EMPTY(&bf->bf_io_pending_anchor);
	CHECK_HEAD_EMPTY(&bf->bf_postpone_anchor);
	free_pages((unsigned long)bf->bf_data, brick->backing_order);
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
						XIO_INF("bf %p is in use\n", bf);
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
				XIO_INF("bf %p is in use\n", bf);
				bf = NULL; /*  forget it = > _bf_put() must fix it */
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
		goto out_return;
#if 1
	XIO_DBG("ZERO_COUNT %p %d\n", bf, at_end);
	if (unlikely(!list_empty(&bf->bf_io_pending_anchor)))
		XIO_ERR("bf_io_pending_anchor is not empty!\n");
	if (unlikely(!list_empty(&bf->bf_postpone_anchor)))
		XIO_ERR("bf_postpone_anchor is not empty!\n");
#endif

	list = LIST_LRU;
	at_end = !(bf->bf_flags & AIO_UPTODATE);
	if (bf->bf_chain_detected) {
		list = LIST_FORGET;
		at_end = false;
	}
	_add_bf_list(bf->bf_brick, bf, list, at_end);
out_return:;
}

/***********************************************************************/

/* Routines for the relation bf <-> aio
 */
static inline
void _aio_assign(struct buf_head *bf, struct buf_aio_aspect *aio_a)
{
	if (aio_a->rfa_bf)
		goto out_return;
	aio_a->rfa_bf = bf;
	atomic_inc(&bf->bf_aio_count);
out_return:;
}

static inline
bool _aio_remove(struct buf_head *bf, struct buf_aio_aspect *aio_a)
{
	/* struct aio_object *aio; */
	bool status;

	if (!aio_a->rfa_bf)
		return false;
	aio_a->rfa_bf = NULL;
	CHECK_ATOMIC(&bf->bf_aio_count, 1);
	status = atomic_dec_and_test(&bf->bf_aio_count);
	return status;
}

/***********************************************************/

static inline int _get_info(struct buf_brick *brick)
{
	struct buf_input *input = brick->inputs[0];
	int status = GENERIC_INPUT_CALL(input, xio_get_info, &brick->base_info);

	if (status >= 0)
		brick->got_info = true;
	return status;
}

/***************** own brick * input * output operations *****************/

static int buf_get_info(struct buf_output *output, struct xio_info *info)
{
	struct buf_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, xio_get_info, info);
}

static int buf_io_get(struct buf_output *output, struct aio_object *aio)
{
	struct buf_brick *brick = output->brick;
	struct buf_aio_aspect *aio_a;
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
		/*  grab all memory in one go = > avoid memory fragmentation */
		__pre_alloc_bf(brick, brick->max_count + PRE_ALLOC - atomic_read(&brick->alloc_count));
	}
#endif
	/* Grab reference.
	 */
	obj_get(aio);

	/* shortcut in case of unbuffered IO
	 */
	if (aio->io_data) {
		/* Note: unbuffered IO is later indicated by rfa_bf == NULL
		 */
		return 0;
	}

	aio_a = buf_aio_get_aspect(brick, aio);
	if (unlikely(!aio_a))
		goto done;

	base_pos = aio->io_pos & ~(loff_t)(brick->backing_size - 1);
	base_offset = (aio->io_pos - base_pos);
	if (unlikely(base_offset < 0 || base_offset >= brick->backing_size))
		XIO_ERR("bad base_offset %d\n", base_offset);

	max_len = brick->backing_size - base_offset;
	if (aio->io_len > max_len)
		aio->io_len = max_len;

again:
	bf = _hash_find_insert(brick, base_pos >> (brick->backing_order + PAGE_SHIFT), new);
	if (bf) {
#if 1
		loff_t end_pos = bf->bf_pos + brick->backing_size;

		if (aio->io_pos < bf->bf_pos || aio->io_pos >= end_pos)
			XIO_ERR("hash corruption. %lld not in (%lld ... %lld)\n", aio->io_pos, bf->bf_pos, end_pos);
#endif
		_remove_bf_list(brick, bf);
		atomic_inc(&brick->hit_count);
		if (unlikely(new)) {
			atomic_inc(&brick->nr_collisions);
			XIO_DBG("race detected: alias appeared in the meantime\n");
			_add_bf_list(brick, new, LIST_FREE, true);
			new = NULL;
		}
	} else if (new) {
		atomic_inc(&brick->miss_count);
		XIO_DBG("new elem added\n");
		bf = new;
		new = NULL;
		bf->bf_chain_detected = false;
	} else {
		XIO_DBG("buf_get() hash nothing found\n");

		new = _fetch_bf(brick);
		if (!new)
			goto done;
#if 1
		/*  dont initialize new->bf_data */
		memset(((void *)new) + sizeof(void *), 0, sizeof(struct buf_head) - sizeof(void *));
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
		if (aio->io_may_write != READ &&
		   ((!base_offset && aio->io_len >= brick->backing_size) ||
		    (aio->io_pos >= brick->base_info.current_size && brick->base_info.current_size > 0))) {
			new->bf_flags |= AIO_UPTODATE;
			atomic_inc(&brick->opt_count);
		}
#endif
		/* INIT_LIST_HEAD(&new->bf_aio_anchor); */
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

	_aio_assign(bf, aio_a);

	XIO_DBG("bf=%p index = %lld flags = %d\n", bf, bf->bf_base_index, bf->bf_flags);

	aio->io_flags = bf->bf_flags;
	aio->io_data = bf->bf_data + base_offset;

	obj_check(aio);
	CHECK_ATOMIC(&bf->bf_hash_count, 1);
	CHECK_ATOMIC(&bf->bf_aio_count, 1);

	status = 0;

done:
	return status;
}

static void _buf_io_put(struct buf_output *output, struct buf_aio_aspect *aio_a)
{
	struct aio_object *aio = aio_a->object;
	struct buf_head *bf;

	/* shortcut in case of unbuffered IO
	 */
	bf = aio_a->rfa_bf;
	if (!bf) {
		struct buf_brick *brick = output->brick;

		GENERIC_INPUT_CALL(brick->inputs[0], aio_put, aio);
		goto out_return;
	}

	if (!obj_put(aio))
		goto out_return;
	XIO_DBG("buf_io_put() aio=%p aio_a=%p bf=%p flags=%d\n", aio, aio_a, bf, bf->bf_flags);
	_aio_remove(bf, aio_a);
	obj_free(aio);

	_bf_put(bf); /*  paired with _hash_find_insert() */
out_return:;
}

static void buf_io_put(struct buf_output *output, struct aio_object *aio)
{
	struct buf_aio_aspect *aio_a;

	aio_a = buf_aio_get_aspect(output->brick, aio);
	if (unlikely(!aio_a)) {
		XIO_FAT("cannot get aspect\n");
		goto out_return;
	}
	_buf_io_put(output, aio_a);
out_return:;
}

static void _buf_endio(struct generic_callback *cb);

static int _buf_make_io(struct buf_brick *brick,
	struct buf_head *bf,
	void *start_data,
	loff_t start_pos,
	int start_len,
	int rw)
{
	struct buf_input *input;
	int status = EINVAL;

#if 1
	loff_t bf_end = bf->bf_pos + brick->backing_size;
	loff_t end_pos;

	if (start_pos < bf->bf_pos || start_pos >= bf_end) {
		XIO_ERR("bad start_pos %llu (%llu ... %llu)\n", start_pos, bf->bf_pos, bf_end);
		goto done;
	}
	end_pos = start_pos + start_len;
	if (end_pos <= bf->bf_pos || end_pos > bf_end) {
		XIO_ERR("bad end_pos %llu (%llu ... %llu)\n", end_pos, bf->bf_pos, bf_end);
		goto done;
	}
	if (!start_data) {
		XIO_ERR("bad start_data\n");
		goto done;
	}
	if (start_len <= 0) {
		XIO_ERR("bad start_len %d\n", start_len);
		goto done;
	}
#endif

	XIO_DBG("bf = %p rw = %d start = %lld len = %d flags = %d\n", bf, rw, start_pos, start_len, bf->bf_flags);

	atomic_set(&bf->bf_io_count, 0);
	status = -ENOMEM;
	input = brick->inputs[0];

	while (start_len > 0) {
		struct aio_object *aio;
		struct buf_aio_aspect *aio_a;
		int len;

		aio = buf_alloc_aio(brick);

		aio_a = buf_aio_get_aspect(brick, aio);
		if (unlikely(!aio_a)) {
			obj_free(aio);
			break;
		}

		aio_a->rfa_bf = bf;
		SETUP_CALLBACK(aio, _buf_endio, aio_a);

		aio->io_pos = start_pos;
		aio->io_len = start_len;
		aio->io_may_write = rw;
		aio->io_rw = rw;
		aio->io_data = start_data;

		status = GENERIC_INPUT_CALL(input, aio_get, aio);
		if (status < 0) {
			XIO_ERR("status = %d\n", status);
			goto done;
		}

		/* Remember number of fired-off aios
		 */
		atomic_inc(&bf->bf_io_count);

		len = aio->io_len;

#ifndef FAKE_IO
		GENERIC_INPUT_CALL(input, aio_io, aio);
#else
		/*  fake IO for testing */
		aio_a->cb.cb_error = status;
		aio_a->cb.cb_fn(&aio_a->cb);
#endif

		GENERIC_INPUT_CALL(input, aio_put, aio);

		start_data += len;
		start_pos += len;
		start_len -= len;
#if 1
		if (start_len > 0)
			XIO_ERR("cannot submit request in one go, rest=%d\n", start_len);
#endif
	}
done:
	return status;
}

static void _buf_endio(struct generic_callback *cb)
{
	struct buf_aio_aspect *bf_aio_a = cb->cb_private;
	struct aio_object *bf_aio;
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

	LAST_CALLBACK(cb);
	CHECK_PTR(bf_aio_a, err);
	bf_aio = bf_aio_a->object;
	CHECK_PTR(bf_aio, err);
	bf = bf_aio_a->rfa_bf;
	CHECK_PTR(bf, err);
	brick = bf->bf_brick;
	CHECK_PTR(brick, err);

	XIO_DBG("_buf_endio() bf_aio_a=%p bf_aio=%p bf=%p flags=%d\n", bf_aio_a, bf_aio, bf, bf->bf_flags);

	if (error < 0)
		bf->bf_error = error;

	/*  wait until all IO on this bf is completed. */
	if (!atomic_dec_and_test(&bf->bf_io_count))
		goto out_return;
	XIO_DBG("_buf_endio() ZERO bf=%p\n", bf);

	/*  get an extra reference, to avoid freeing bf underneath during callbacks */
	CHECK_ATOMIC(&bf->bf_hash_count, 1);
	atomic_inc(&bf->bf_hash_count);

	spin_lock_irqsave(&bf->bf_lock, flags);

	/*  update flags. this must be done before the callbacks. */
	old_flags = bf->bf_flags;
	if (bf->bf_error >= 0 && (old_flags & AIO_READING))
		bf->bf_flags |= AIO_UPTODATE;

	/*  clear the flags, callbacks must not see them. may be re-enabled later. */
	bf->bf_flags &= ~(AIO_READING | AIO_WRITING);
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
		struct buf_aio_aspect *aio_a = container_of(bf->bf_postpone_anchor.next,
			struct buf_aio_aspect,

			rfa_pending_head);
		struct aio_object *aio = aio_a->object;

		if (aio_a->rfa_bf != bf)
			XIO_ERR("bad pointers %p != %p\n", aio_a->rfa_bf, bf);
#if 1
		if (!(++count % 1000))
			XIO_ERR("endless loop 1\n");
#endif
		list_del_init(&aio_a->rfa_pending_head);
		list_add_tail(&aio_a->rfa_pending_head, &bf->bf_io_pending_anchor);

		XIO_DBG("postponed aio=%p\n", aio);

		/*  re-enable flags */
		bf->bf_flags |= AIO_WRITING;
		bf->bf_error = 0;

		if (!start_len) {
			/*  first time: only flush the affected area */
			start_data = aio->io_data;
			start_pos = aio->io_pos;
			start_len = aio->io_len;
		} else if (start_data != aio->io_data ||
			  start_pos != aio->io_pos ||
			  start_len != aio->io_len) {
			/*  another time: flush larger parts */
			loff_t start_diff = aio->io_pos - start_pos;
			loff_t end_diff;

			if (start_diff < 0) {
				start_data += start_diff;
				start_pos += start_diff;
				start_len -= start_diff;
			}
			end_diff = (aio->io_pos + aio->io_len) - (start_pos + start_len);
			if (end_diff > 0)
				start_len += end_diff;
		}
	}

	spin_unlock_irqrestore(&bf->bf_lock, flags);

	/* Signal success by calling all callbacks.
	 * Thanks to the tmp list, we can do this outside the spinlock.
	 */
	count = 0;
	while (!list_empty(&tmp)) {
		struct buf_aio_aspect *aio_a = container_of(tmp.next, struct buf_aio_aspect, rfa_pending_head);
		struct aio_object *aio = aio_a->object;

		if (aio_a->rfa_bf != bf)
			XIO_ERR("bad pointers %p != %p\n", aio_a->rfa_bf, bf);
#if 1
		if (!(++count % 1000))
			XIO_ERR("endless loop 2\n");
#endif
		obj_check(aio);
		/* It should be safe to do this without locking, because
		 * tmp is on the stack, so there is no concurrency.
		 */
		list_del_init(&aio_a->rfa_pending_head);

		/*  update infos for callbacks, they may inspect it. */
		aio->io_flags = bf->bf_flags;

		CHECKED_CALLBACK(aio, bf->bf_error, err);

		atomic_dec(&brick->nr_io_pending);

		_buf_io_put(brick->outputs[0], aio_a);
	}

	if (start_len) {
		XIO_DBG("ATTENTION restart %d\n", start_len);
		_buf_make_io(brick, bf, start_data, start_pos, start_len, WRITE);
	}
	/*  drop the extra reference from above */
	_bf_put(bf);
	goto out_return;
err:
	XIO_FAT("giving up.\n");
out_return:;
}

static void buf_io_io(struct buf_output *output, struct aio_object *aio)
{
	struct buf_brick *brick = output->brick;
	struct buf_aio_aspect *aio_a;
	struct buf_head *bf;
	void  *start_data = NULL;
	loff_t start_pos = 0;
	int    start_len = 0;
	int status = -EINVAL;
	bool delay = false;
	unsigned long flags;

	if (unlikely(!aio)) {
		XIO_FAT("internal problem: forgotten to supply aio\n");
		goto fatal;
	}
	aio_a = buf_aio_get_aspect(brick, aio);
	if (unlikely(!aio_a)) {
		XIO_ERR("internal problem: aio aspect does not work\n");
		goto fatal;
	}
	/* shortcut in case of unbuffered IO
	 */
	bf = aio_a->rfa_bf;
	if (!bf) {
		GENERIC_INPUT_CALL(brick->inputs[0], aio_io, aio);
		goto out_return;
	}

	/* Grab an extra reference.
	 * This will be released later in _bf_endio() after
	 * calling the callbacks.
	 */
	obj_get(aio);
	CHECK_ATOMIC(&bf->bf_hash_count, 1);

	XIO_DBG("IO aio=%p rw=%d bf=%p flags=%d\n", aio, aio->io_rw, bf, bf->bf_flags);

	if (aio->io_rw != READ) {
		loff_t end;

		if (unlikely(aio->io_may_write == READ)) {
			XIO_ERR("sorry, you have forgotten to set io_may_write\n");
			goto callback;
		}
		end = aio->io_pos + aio->io_len;
		/* FIXME: race condition :( */
		if (!brick->got_info)
			_get_info(brick);
		if (end > brick->base_info.current_size)
			brick->base_info.current_size = end;
	}

#if 1
	if (jiffies - brick->last_jiffies >= 30 * HZ) {
		unsigned long hit = atomic_read(&brick->hit_count);
		unsigned long miss = atomic_read(&brick->miss_count);
		unsigned long perc = hit * 100 * 100 / (hit + miss);

		brick->last_jiffies = jiffies;
		XIO_INF("BUF %p STATISTICS: alloc=%d hashed=%d free=%d forget=%d lru=%d io_pending=%d hit=%lu (%lu.%02lu%%) miss=%lu collisions=%d opt=%d chain=%d post=%d write=%d io=%d\n",
			brick,
			atomic_read(&brick->alloc_count),
			atomic_read(&brick->hashed_count),
			atomic_read(&brick->list_count[LIST_FREE]),
			atomic_read(&brick->list_count[LIST_FORGET]),
			atomic_read(&brick->list_count[LIST_LRU]),
			atomic_read(&brick->nr_io_pending),
			hit,
			perc / 100,
			perc % 100,
			miss,
			atomic_read(&brick->nr_collisions),
			atomic_read(&brick->opt_count),
			atomic_read(&brick->chain_count),
			atomic_read(&brick->post_count),
			atomic_read(&brick->write_count),
			atomic_read(&brick->io_count));
	}
#endif

	spin_lock_irqsave(&bf->bf_lock, flags);

	if (!list_empty(&aio_a->rfa_pending_head)) {
		XIO_ERR("trying to start IO on an already started aio\n");
		goto already_done;
	}

	if (aio->io_rw != 0) { /*  WRITE */
#ifdef FAKE_WRITES
		bf->bf_flags |= AIO_UPTODATE;
		goto already_done;
#endif
		if (bf->bf_flags & AIO_READING)
			XIO_ERR("bad bf_flags %d\n", bf->bf_flags);
		if (!(bf->bf_flags & AIO_WRITING)) {
#if 0
			/*  by definition, a writeout buffer is always uptodate */
			bf->bf_flags |= (AIO_WRITING | AIO_UPTODATE);
#else /*  really ??? */
			bf->bf_flags |= AIO_WRITING;
#endif
			bf->bf_error = 0;
#if 1
			start_data = aio->io_data;
			start_pos = aio->io_pos;
			start_len = aio->io_len;
#else /*  only for testing: write the full buffer */
			start_data = (void *)((unsigned long)aio->io_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = aio->io_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
#endif
			list_add(&aio_a->rfa_pending_head, &bf->bf_io_pending_anchor);
			delay = true;
		} else {
			list_add(&aio_a->rfa_pending_head, &bf->bf_postpone_anchor);
			atomic_inc(&brick->post_count);
			delay = true;
			XIO_DBG("postponing %lld %d\n", aio->io_pos, aio->io_len);
		}
	} else { /*  READ */
#ifdef FAKE_READS
		bf->bf_flags |= AIO_UPTODATE;
		goto already_done;
#endif
#if 0
		if (bf->bf_flags & (AIO_UPTODATE | AIO_WRITING))
#else
		if (bf->bf_flags & AIO_UPTODATE)
#endif
			goto already_done;
		if (!(bf->bf_flags & AIO_READING)) {
			bf->bf_flags |= AIO_READING;
			bf->bf_error = 0;

			/*  always read the whole buffer. */
			start_data = (void *)((unsigned long)aio->io_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = aio->io_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
		}
		list_add(&aio_a->rfa_pending_head, &bf->bf_io_pending_anchor);
		delay = true;
	}

	if (likely(delay)) {
		atomic_inc(&brick->nr_io_pending);
		atomic_inc(&brick->io_count);
		if (aio->io_rw != 0)
			atomic_inc(&brick->write_count);
	}

	spin_unlock_irqrestore(&bf->bf_lock, flags);

	if (!start_len) {
		/*  nothing to start, IO is already started. */
		goto no_callback;
	}

	status = _buf_make_io(brick, bf, start_data, start_pos, start_len, aio->io_rw);
	if (likely(status >= 0)) {
		/* No immediate callback, this time.
		 * Callbacks will be called later from _bf_endio().
		 */
		goto no_callback;
	}

	XIO_ERR("error %d during buf_io_io()\n", status);
	buf_io_put(output, aio);
	goto callback;

already_done:
	status = bf->bf_error;

	spin_unlock_irqrestore(&bf->bf_lock, flags);

callback:
	aio->io_flags = bf->bf_flags;
	CHECKED_CALLBACK(aio, status, fatal);

no_callback:
	if (!delay) {
		buf_io_put(output, aio);
	} /*  else the io_put() will be carried out upon IO completion. */

	goto out_return;
fatal: /*  no chance to call callback: may produce hanging tasks :( */
	XIO_FAT("no chance to call callback, tasks may hang.\n");
out_return:;
}

/*************** object * aspect constructors * destructors **************/

static int buf_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct buf_aio_aspect *ini = (void *)_ini;

	ini->rfa_bf = NULL;
	INIT_LIST_HEAD(&ini->rfa_pending_head);
	/* INIT_LIST_HEAD(&ini->tmp_head); */
	return 0;
}

static void buf_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct buf_aio_aspect *ini = (void *)_ini;

	(void)ini;
#if 1
	CHECK_HEAD_EMPTY(&ini->rfa_pending_head);
	/* CHECK_HEAD_EMPTY(&ini->tmp_head); */
#endif
}

XIO_MAKE_STATICS(buf);

/********************* brick constructors * destructors *******************/

static int buf_brick_construct(struct buf_brick *brick)
{
	int i;

	brick->backing_order = 0;
	brick->backing_size = PAGE_SIZE;
	brick->max_count = 32;
	spin_lock_init(&brick->brick_lock);
	for (i = 0; i < LIST_MAX; i++)
		INIT_LIST_HEAD(&brick->list_anchor[i]);
	for (i = 0; i < XIO_BUF_HASH_MAX; i++) {
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

	for (i = 0; i < LIST_MAX; i++)
		CHECK_HEAD_EMPTY(&brick->list_anchor[i]);
	for (i = 0; i < XIO_BUF_HASH_MAX; i++)
		CHECK_HEAD_EMPTY(&brick->cache_anchors[i].hash_anchor);

	return 0;
}

/************************ static structs ***********************/

static struct buf_brick_ops buf_brick_ops;

static struct buf_output_ops buf_output_ops = {
	.xio_get_info = buf_get_info,
	.aio_get = buf_io_get,
	.aio_put = buf_io_put,
	.aio_io = buf_io_io,
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

/***************** module init stuff ************************/

int __init init_xio_buf(void)
{
	XIO_INF("init_buf()\n");
	return buf_register_brick_type();
}

void exit_xio_buf(void)
{
	XIO_INF("exit_buf()\n");
	buf_unregister_brick_type();
}
