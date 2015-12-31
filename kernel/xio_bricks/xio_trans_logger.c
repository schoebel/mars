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

/*  Trans_Logger brick */

//#define BRICK_DEBUGGING
#define XIO_DEBUGGING
//#define REPLAY_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>

#include "xio.h"
#include "../lib/lib_rank.h"
#include "../lib/lib_limiter.h"

#include "xio_trans_logger.h"

/*  variants */
#define KEEP_UNIQUE
#define DELAY_CALLERS			/*  this is _needed_ for production systems */
/* When possible, queue 1 executes phase3_startio() directly without
 * intermediate queueing into queue 3 = > may be irritating, but has better
 * performance. NOTICE: when some day the IO scheduling should be
 * different between queue 1 and 3, you MUST disable this in order
 * to distinguish between them!
 */
#define SHORTCUT_1_to_3

/*  commenting this out is dangerous for data integrity! use only for testing! */
#define USE_MEMCPY
#define DO_WRITEBACK			/*  otherwise FAKE IO */
#define REPLAY_DATA

/*  tuning */
#ifdef BRICK_DEBUG_MEM
#define CONF_TRANS_CHUNKSIZE		(128 * 1024 - PAGE_SIZE * 2)
#else
#define CONF_TRANS_CHUNKSIZE		(128 * 1024)
#endif
#define CONF_TRANS_MAX_AIO_SIZE		PAGE_SIZE
//#define CONF_TRANS_ALIGN	PAGE_SIZE /*  FIXME: does not work */
#define CONF_TRANS_ALIGN		0

#ifdef REPLAY_DEBUGGING
#define XIO_RPL(_fmt, _args...)  _XIO_MSG(false, "REPLAY ", _fmt, ##_args)
#else
#define XIO_RPL(_args...) /*empty*/
#endif

struct trans_logger_hash_anchor {
	struct rw_semaphore hash_mutex;
	struct list_head hash_anchor;
};

#define NR_HASH_PAGES			64

#define MAX_HASH_PAGES			(PAGE_SIZE / sizeof(struct trans_logger_hash_anchor *))
#define HASH_PER_PAGE			(PAGE_SIZE / sizeof(struct trans_logger_hash_anchor))
#define HASH_TOTAL			(NR_HASH_PAGES * HASH_PER_PAGE)

/************************ global tuning ***********************/

int trans_logger_completion_semantics = 1;

int trans_logger_do_crc =
#ifdef CONFIG_MARS_DEBUG
	true;
#else
	false;
#endif

int trans_logger_mem_usage; /*	in KB */

int trans_logger_max_interleave = -1;

int trans_logger_resume = 1;

int trans_logger_replay_timeout = 1; /*  in s */

struct writeback_group global_writeback = {
	.lock = __RW_LOCK_UNLOCKED(global_writeback.lock),
	.group_anchor = LIST_HEAD_INIT(global_writeback.group_anchor),
	.until_percent = 30,
};

static
void add_to_group(struct writeback_group *gr, struct trans_logger_brick *brick)
{
	unsigned long flags;

	write_lock_irqsave(&gr->lock, flags);
	list_add_tail(&brick->group_head, &gr->group_anchor);
	write_unlock_irqrestore(&gr->lock, flags);
}

static
void remove_from_group(struct writeback_group *gr, struct trans_logger_brick *brick)
{
	unsigned long flags;

	write_lock_irqsave(&gr->lock, flags);
	list_del_init(&brick->group_head);
	gr->leader = NULL;
	write_unlock_irqrestore(&gr->lock, flags);
}

static
struct trans_logger_brick *elect_leader(struct writeback_group *gr)
{
	struct trans_logger_brick *res = gr->leader;
	struct list_head *tmp;
	unsigned long flags;

	if (res && gr->until_percent >= 0) {
		loff_t used = atomic64_read(&res->shadow_mem_used);

		if (used > gr->biggest * gr->until_percent / 100)
			goto done;
	}

	read_lock_irqsave(&gr->lock, flags);
	for (tmp = gr->group_anchor.next; tmp != &gr->group_anchor; tmp = tmp->next) {
		struct trans_logger_brick *test = container_of(tmp, struct trans_logger_brick, group_head);
		loff_t new_used = atomic64_read(&test->shadow_mem_used);

		if (!res || new_used > atomic64_read(&res->shadow_mem_used)) {
			res = test;
			gr->biggest = new_used;
		}
	}
	read_unlock_irqrestore(&gr->lock, flags);

	gr->leader = res;

done:
	return res;
}

/************************ own type definitions ***********************/

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

_PAIRING_HEAP_FUNCTIONS(static, logger, tr_cmp);

static inline
loff_t *lh_get(struct logger_head *th)
{
	return th->lh_pos;
}

QUEUE_FUNCTIONS(logger, struct logger_head, lh_head, lh_get, lh_cmp, logger);

/************************* logger queue handling ***********************/

static inline
void qq_init(struct logger_queue *q, struct trans_logger_brick *brick)
{
	q_logger_init(q);
	q->q_event = &brick->worker_event;
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

static inline
void qq_aio_insert(struct logger_queue *q, struct trans_logger_aio_aspect *aio_a)
{
	struct aio_object *aio = aio_a->object;

	obj_get(aio); /*  must be paired with __trans_logger_io_put() */
	atomic_inc(&q->q_brick->inner_balance_count);

	q_logger_insert(q, &aio_a->lh);
}

static inline
void qq_wb_insert(struct logger_queue *q, struct writeback_info *wb)
{
	q_logger_insert(q, &wb->w_lh);
}

static inline
void qq_aio_pushback(struct logger_queue *q, struct trans_logger_aio_aspect *aio_a)
{
	obj_check(aio_a->object);

	q->pushback_count++;

	q_logger_pushback(q, &aio_a->lh);
}

static inline
void qq_wb_pushback(struct logger_queue *q, struct writeback_info *wb)
{
	q->pushback_count++;
	q_logger_pushback(q, &wb->w_lh);
}

static inline
struct trans_logger_aio_aspect *qq_aio_fetch(struct logger_queue *q)
{
	struct logger_head *test;
	struct trans_logger_aio_aspect *aio_a = NULL;

	test = q_logger_fetch(q);

	if (test) {
		aio_a = container_of(test, struct trans_logger_aio_aspect, lh);
		obj_check(aio_a->object);
	}
	return aio_a;
}

static inline
struct writeback_info *qq_wb_fetch(struct logger_queue *q)
{
	struct logger_head *test;
	struct writeback_info *res = NULL;

	test = q_logger_fetch(q);

	if (test)
		res = container_of(test, struct writeback_info, w_lh);
	return res;
}

/************************ own helper functions ***********************/

static inline
int hash_fn(loff_t pos)
{
	/*  simple and stupid */
	long base_index = pos >> REGION_SIZE_BITS;

	base_index += base_index / HASH_TOTAL / 7;
	return base_index % HASH_TOTAL;
}

static inline
struct trans_logger_aio_aspect *_hash_find(struct list_head *start,
	loff_t pos,
	int *max_len,
	bool use_collect_head,
	bool find_unstable)
{
	struct list_head *tmp;
	struct trans_logger_aio_aspect *res = NULL;
	int len = *max_len;

	/* The lists are always sorted according to age (newest first).
	 * Caution: there may be duplicates in the list, some of them
	 * overlapping with the search area in many different ways.
	 */
	for (tmp = start->next; tmp != start; tmp = tmp->next) {
		struct trans_logger_aio_aspect *test_a;
		struct aio_object *test;
		int diff;

		if (use_collect_head)
			test_a = container_of(tmp, struct trans_logger_aio_aspect, collect_head);
		else
			test_a = container_of(tmp, struct trans_logger_aio_aspect, hash_head);
		test = test_a->object;

		obj_check(test);

		/*  are the regions overlapping? */
		if (pos >= test->io_pos + test->io_len || pos + len <= test->io_pos)
			continue; /*  not relevant */

		/*  searching for unstable elements (only in special cases) */
		if (find_unstable && test_a->is_stable)
			break;

		diff = test->io_pos - pos;
		if (diff <= 0) {
			int restlen = test->io_len + diff;

			res = test_a;
			if (restlen < len)
				len = restlen;
			break;
		}
		if (diff < len)
			len = diff;
	}

	*max_len = len;
	return res;
}

static
struct trans_logger_aio_aspect *hash_find(struct trans_logger_brick *brick,
	loff_t pos,
	int *max_len,
	bool find_unstable)
{

	int hash = hash_fn(pos);
	struct trans_logger_hash_anchor *sub_table = brick->hash_table[hash / HASH_PER_PAGE];
	struct trans_logger_hash_anchor *start = &sub_table[hash % HASH_PER_PAGE];
	struct trans_logger_aio_aspect *res;

	atomic_inc(&brick->total_hash_find_count);

	down_read(&start->hash_mutex);

	res = _hash_find(&start->hash_anchor, pos, max_len, false, find_unstable);

	/* Ensure the found aio can't go away...
	 */
	if (res && res->object)
		obj_get(res->object);

	up_read(&start->hash_mutex);

	return res;
}

static
void hash_insert(struct trans_logger_brick *brick, struct trans_logger_aio_aspect *elem_a)
{
	int hash = hash_fn(elem_a->object->io_pos);
	struct trans_logger_hash_anchor *sub_table = brick->hash_table[hash / HASH_PER_PAGE];
	struct trans_logger_hash_anchor *start = &sub_table[hash % HASH_PER_PAGE];

	CHECK_HEAD_EMPTY(&elem_a->hash_head);
	obj_check(elem_a->object);

	/*  only for statistics: */
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
static
void hash_extend(struct trans_logger_brick *brick, loff_t *_pos, int *_len, struct list_head *collect_list)
{
	loff_t pos = *_pos;
	int len = *_len;
	int hash = hash_fn(pos);
	struct trans_logger_hash_anchor *sub_table = brick->hash_table[hash / HASH_PER_PAGE];
	struct trans_logger_hash_anchor *start = &sub_table[hash % HASH_PER_PAGE];
	struct list_head *tmp;
	bool extended;

	if (collect_list)
		CHECK_HEAD_EMPTY(collect_list);

	atomic_inc(&brick->total_hash_extend_count);

	down_read(&start->hash_mutex);

	do {
		extended = false;

		for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
			struct trans_logger_aio_aspect *test_a;
			struct aio_object *test;
			loff_t diff;

			test_a = container_of(tmp, struct trans_logger_aio_aspect, hash_head);
			test = test_a->object;

			obj_check(test);

			/*  are the regions overlapping? */
			if (pos >= test->io_pos + test->io_len || pos + len <= test->io_pos)
				continue; /*  not relevant */

			/*  collision detection */
			if (test_a->is_collected)
				goto collision;

			/*  no writeback of non-persistent data */
			if (!(test_a->is_persistent & test_a->is_completed))
				goto collision;

			/*  extend the search region when necessary */
			diff = pos - test->io_pos;
			if (diff > 0) {
				len += diff;
				pos = test->io_pos;
				extended = true;
			}
			diff = (test->io_pos + test->io_len)	- (pos + len);
			if (diff > 0) {
				len += diff;
				extended = true;
			}
		}
	} while (extended); /*	start over for transitive closure */

	*_pos = pos;
	*_len = len;

	for (tmp = start->hash_anchor.next; tmp != &start->hash_anchor; tmp = tmp->next) {
		struct trans_logger_aio_aspect *test_a;
		struct aio_object *test;

		test_a = container_of(tmp, struct trans_logger_aio_aspect, hash_head);
		test = test_a->object;

		/*  are the regions overlapping? */
		if (pos >= test->io_pos + test->io_len || pos + len <= test->io_pos)
			continue; /*  not relevant */

		/*  collect */
		CHECK_HEAD_EMPTY(&test_a->collect_head);
		if (unlikely(test_a->is_collected))
			XIO_ERR("collision detection did not work\n");
		test_a->is_collected = true;
		obj_check(test);
		list_add_tail(&test_a->collect_head, collect_list);
	}

collision:
	up_read(&start->hash_mutex);
}

/* Atomically put all elements from the list.
 * All elements must reside in the same collision list.
 */
static inline
void hash_put_all(struct trans_logger_brick *brick, struct list_head *list)
{
	struct list_head *tmp;
	struct trans_logger_hash_anchor *start = NULL;
	int first_hash = -1;

	for (tmp = list->next; tmp != list; tmp = tmp->next) {
		struct trans_logger_aio_aspect *elem_a;
		struct aio_object *elem;
		int hash;

		elem_a = container_of(tmp, struct trans_logger_aio_aspect, collect_head);
		elem = elem_a->object;
		CHECK_PTR(elem, err);
		obj_check(elem);

		hash = hash_fn(elem->io_pos);
		if (!start) {
			struct trans_logger_hash_anchor *sub_table = brick->hash_table[hash / HASH_PER_PAGE];

			start = &sub_table[hash % HASH_PER_PAGE];
			first_hash = hash;
			down_write(&start->hash_mutex);
		} else if (unlikely(hash != first_hash)) {
			XIO_ERR("oops, different hashes: %d != %d\n", hash, first_hash);
		}

		if (!elem_a->is_hashed)
			continue;

		list_del_init(&elem_a->hash_head);
		elem_a->is_hashed = false;
		atomic_dec(&brick->hash_count);
	}

err:
	if (start)
		up_write(&start->hash_mutex);
}

static inline
void hash_ensure_stableness(struct trans_logger_brick *brick, struct trans_logger_aio_aspect *aio_a)
{
	if (!aio_a->is_stable) {
		struct aio_object *aio = aio_a->object;
		int hash = hash_fn(aio->io_pos);
		struct trans_logger_hash_anchor *sub_table = brick->hash_table[hash / HASH_PER_PAGE];
		struct trans_logger_hash_anchor *start = &sub_table[hash % HASH_PER_PAGE];

		down_write(&start->hash_mutex);

		aio_a->is_stable = true;

		up_write(&start->hash_mutex);
	}
}

static
void _inf_callback(struct trans_logger_input *input, bool force)
{
	if (!force &&
	    input->inf_last_jiffies &&
	    input->inf_last_jiffies + 4 * HZ > (long long)jiffies)
		goto out_return;
	if (input->inf.inf_callback && input->is_operating) {
		input->inf_last_jiffies = jiffies;

		input->inf.inf_callback(&input->inf);

		input->inf_last_jiffies = jiffies;
	} else {
		XIO_DBG("%p skipped callback, callback = %p is_operating = %d\n",
			input,
			input->inf.inf_callback,
			input->is_operating);
	}
out_return:;
}

static inline
int _congested(struct trans_logger_brick *brick)
{
	return atomic_read(&brick->q_phase[0].q_queued) ||
		atomic_read(&brick->q_phase[0].q_flying) ||
		atomic_read(&brick->q_phase[1].q_queued) ||
		atomic_read(&brick->q_phase[1].q_flying) ||
		atomic_read(&brick->q_phase[2].q_queued) ||
		atomic_read(&brick->q_phase[2].q_flying) ||
		atomic_read(&brick->q_phase[3].q_queued) ||
		atomic_read(&brick->q_phase[3].q_flying);
}

/***************** own brick * input * output operations *****************/

atomic_t   global_mshadow_count = ATOMIC_INIT(0);

atomic64_t global_mshadow_used = ATOMIC64_INIT(0);

static
int trans_logger_get_info(struct trans_logger_output *output, struct xio_info *info)
{
	struct trans_logger_input *input = output->brick->inputs[TL_INPUT_READ];

	return GENERIC_INPUT_CALL(input, xio_get_info, info);
}

static
int _make_sshadow(struct trans_logger_output *output,
	struct trans_logger_aio_aspect *aio_a,
	struct trans_logger_aio_aspect *mshadow_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct aio_object *aio = aio_a->object;
	struct aio_object *mshadow;
	int diff;

	mshadow = mshadow_a->object;
	if (unlikely(aio->io_len > mshadow->io_len)) {
		XIO_ERR("oops %d -> %d\n", aio->io_len, mshadow->io_len);
		aio->io_len = mshadow->io_len;
	}
	if (unlikely(mshadow_a == aio_a)) {
		XIO_ERR("oops %p == %p\n", mshadow_a, aio_a);
		return -EINVAL;
	}

	diff = aio->io_pos - mshadow->io_pos;
	if (unlikely(diff < 0)) {
		XIO_ERR("oops diff = %d\n", diff);
		return -EINVAL;
	}

	/* Attach aio to the existing shadow ("slave shadow").
	 */
	aio_a->shadow_data = mshadow_a->shadow_data + diff;
	aio_a->do_dealloc = false;
	if (!aio->io_data) { /*  buffered IO */
		aio->io_data = aio_a->shadow_data;
		aio_a->do_buffered = true;
		atomic_inc(&brick->total_sshadow_buffered_count);
	}
	aio->io_flags = mshadow->io_flags;
	aio_a->shadow_aio = mshadow_a;
	aio_a->my_brick = brick;

	/* Get an ordinary internal reference
	 */
	obj_get_first(aio); /*	must be paired with __trans_logger_io_put() */
	atomic_inc(&brick->inner_balance_count);

	/* The internal reference from slave to master is already
	 * present due to hash_find(),
	 * such that the master cannot go away before the slave.
	 * It is compensated by master transition in __trans_logger_io_put()
	 */
	atomic_inc(&brick->inner_balance_count);

	atomic_inc(&brick->sshadow_count);
	atomic_inc(&brick->total_sshadow_count);

	if (unlikely(aio->io_len <= 0)) {
		XIO_ERR("oops, len = %d\n", aio->io_len);
		return -EINVAL;
	}

	return aio->io_len;
}

static
int _read_io_get(struct trans_logger_output *output, struct trans_logger_aio_aspect *aio_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct aio_object *aio = aio_a->object;
	struct trans_logger_input *input = brick->inputs[TL_INPUT_READ];
	struct trans_logger_aio_aspect *mshadow_a;

	/* Look if there is a newer version on the fly, shadowing
	 * the old one.
	 * When a shadow is found, use it as buffer for the aio.
	 */
	mshadow_a = hash_find(brick, aio->io_pos, &aio->io_len, false);
	if (!mshadow_a)
		return GENERIC_INPUT_CALL(input, aio_get, aio);

	return _make_sshadow(output, aio_a, mshadow_a);
}

static
int _write_io_get(struct trans_logger_output *output, struct trans_logger_aio_aspect *aio_a)
{
	struct trans_logger_brick *brick = output->brick;
	struct aio_object *aio = aio_a->object;
	void *data;

#ifdef KEEP_UNIQUE
	struct trans_logger_aio_aspect *mshadow_a;

#endif

#ifdef CONFIG_MARS_DEBUG
	if (unlikely(aio->io_len <= 0)) {
		XIO_ERR("oops, io_len = %d\n", aio->io_len);
		return -EINVAL;
	}
#endif

#ifdef KEEP_UNIQUE
	mshadow_a = hash_find(brick, aio->io_pos, &aio->io_len, true);
	if (mshadow_a)
		return _make_sshadow(output, aio_a, mshadow_a);
#endif

#ifdef DELAY_CALLERS
	/*  delay in case of too many master shadows / memory shortage */
	wait_event_interruptible_timeout(brick->caller_event,
					 !brick->delay_callers &&
					 (brick_global_memlimit < 1024 ||
					  atomic64_read(&global_mshadow_used) / 1024 < brick_global_memlimit),
					 HZ / 2);
#endif

	/*  create a new master shadow */
	data = brick_block_alloc(aio->io_pos, (aio_a->alloc_len = aio->io_len));
	atomic64_add(aio->io_len, &brick->shadow_mem_used);
#ifdef CONFIG_MARS_DEBUG
	memset(data, 0x11, aio->io_len);
#endif
	aio_a->shadow_data = data;
	aio_a->do_dealloc = true;
	if (!aio->io_data) { /*  buffered IO */
		aio->io_data = data;
		aio_a->do_buffered = true;
		atomic_inc(&brick->total_mshadow_buffered_count);
	}
	aio_a->my_brick = brick;
	aio->io_flags = 0;
	aio_a->shadow_aio = aio_a; /*  cyclic self-reference = > indicates master shadow */

	atomic_inc(&brick->mshadow_count);
	atomic_inc(&brick->total_mshadow_count);
	atomic_inc(&global_mshadow_count);
	atomic64_add(aio->io_len, &global_mshadow_used);

	atomic_inc(&brick->inner_balance_count);
	obj_get_first(aio); /*	must be paired with __trans_logger_io_put() */

	return aio->io_len;
}

static
int trans_logger_io_get(struct trans_logger_output *output, struct aio_object *aio)
{
	struct trans_logger_brick *brick;
	struct trans_logger_aio_aspect *aio_a;
	loff_t base_offset;

	CHECK_PTR(output, err);
	brick = output->brick;
	CHECK_PTR(brick, err);
	CHECK_PTR(aio, err);

	aio_a = trans_logger_aio_get_aspect(brick, aio);
	CHECK_PTR(aio_a, err);
	CHECK_ASPECT(aio_a, aio, err);

	atomic_inc(&brick->outer_balance_count);

	if (aio->obj_initialized) { /*	setup already performed */
		obj_check(aio);
		obj_get(aio); /*  must be paired with __trans_logger_io_put() */
		return aio->io_len;
	}

	get_lamport(&aio_a->stamp);

	if (aio->io_len > CONF_TRANS_MAX_AIO_SIZE && CONF_TRANS_MAX_AIO_SIZE > 0)
		aio->io_len = CONF_TRANS_MAX_AIO_SIZE;

	/*  ensure that REGION_SIZE boundaries are obeyed by hashing */
	base_offset = aio->io_pos & (loff_t)(REGION_SIZE - 1);
	if (aio->io_len > REGION_SIZE - base_offset)
		aio->io_len = REGION_SIZE - base_offset;

	if (aio->io_may_write == READ)
		return _read_io_get(output, aio_a);

	if (unlikely(brick->stopped_logging)) { /*  only in EMERGENCY mode */
		aio_a->is_emergency = true;
		/* Wait until writeback has finished.
		 * We have to this because writeback is out-of-order.
		 * Otherwise consistency could be violated for some time.
		 */
		while (_congested(brick)) {
			/*  in case of emergency, busy-wait should be acceptable */
			brick_msleep(HZ / 10);
		}
		return _read_io_get(output, aio_a);
	}

	/* FIXME: THIS IS PROVISIONARY (use event instead)
	 */
	while (unlikely(!brick->power.on_led))
		brick_msleep(HZ / 10);

	return _write_io_get(output, aio_a);

err:
	return -EINVAL;
}

static void pos_complete(struct trans_logger_aio_aspect *orig_aio_a);

static
void __trans_logger_io_put(struct trans_logger_brick *brick, struct trans_logger_aio_aspect *aio_a)
{
	struct aio_object *aio;
	struct trans_logger_aio_aspect *shadow_a;
	struct trans_logger_input *input;

restart:
	CHECK_PTR(aio_a, err);
	aio = aio_a->object;
	CHECK_PTR(aio, err);

	obj_check(aio);

	/*  are we a shadow (whether master or slave)? */
	shadow_a = aio_a->shadow_aio;
	if (shadow_a) {
		bool finished;

		CHECK_PTR(shadow_a, err);
		CHECK_PTR(shadow_a->object, err);
		obj_check(shadow_a->object);

		finished = obj_put(aio);
		atomic_dec(&brick->inner_balance_count);
		if (unlikely(finished && aio_a->is_hashed)) {
			XIO_ERR("trying to put a hashed aio, pos = %lld len = %d\n", aio->io_pos, aio->io_len);
			finished = false; /*  leaves a memleak */
		}

		if (!finished)
			goto out_return;

		CHECK_HEAD_EMPTY(&aio_a->lh.lh_head);
		CHECK_HEAD_EMPTY(&aio_a->hash_head);
		CHECK_HEAD_EMPTY(&aio_a->replay_head);
		CHECK_HEAD_EMPTY(&aio_a->collect_head);
		CHECK_HEAD_EMPTY(&aio_a->sub_list);
		CHECK_HEAD_EMPTY(&aio_a->sub_head);

		if (aio_a->is_collected && likely(aio_a->wb_error >= 0))
			pos_complete(aio_a);

		CHECK_HEAD_EMPTY(&aio_a->pos_head);

		if (shadow_a != aio_a) { /*  we are a slave shadow */
			/* XIO_DBG("slave\n"); */
			atomic_dec(&brick->sshadow_count);
			CHECK_HEAD_EMPTY(&aio_a->hash_head);
			obj_free(aio);
			/*  now put the master shadow */
			aio_a = shadow_a;
			goto restart;
		}
		/*  we are a master shadow */
		CHECK_PTR(aio_a->shadow_data, err);
		if (aio_a->do_dealloc) {
			brick_block_free(aio_a->shadow_data, aio_a->alloc_len);
			atomic64_sub(aio->io_len, &brick->shadow_mem_used);
			aio_a->shadow_data = NULL;
			aio_a->do_dealloc = false;
		}
		if (aio_a->do_buffered)
			aio->io_data = NULL;
		atomic_dec(&brick->mshadow_count);
		atomic_dec(&global_mshadow_count);
		atomic64_sub(aio->io_len, &global_mshadow_used);
		obj_free(aio);
		goto out_return;
	}

	/*  only READ is allowed on non-shadow buffers */
	if (unlikely(aio->io_rw != READ && !aio_a->is_emergency))
		XIO_FAT("bad operation %d on non-shadow\n", aio->io_rw);

	/*  no shadow = > call through */
	input = brick->inputs[TL_INPUT_READ];
	CHECK_PTR(input, err);

	GENERIC_INPUT_CALL(input, aio_put, aio);

err:;
out_return:;
}

static
void _trans_logger_io_put(struct trans_logger_output *output, struct aio_object *aio)
{
	struct trans_logger_aio_aspect *aio_a;

	aio_a = trans_logger_aio_get_aspect(output->brick, aio);
	CHECK_PTR(aio_a, err);
	CHECK_ASPECT(aio_a, aio, err);

	__trans_logger_io_put(output->brick, aio_a);
	goto out_return;
err:
	XIO_FAT("giving up...\n");
out_return:;
}

static
void trans_logger_io_put(struct trans_logger_output *output, struct aio_object *aio)
{
	struct trans_logger_brick *brick = output->brick;

	atomic_dec(&brick->outer_balance_count);
	_trans_logger_io_put(output, aio);
}

static
void _trans_logger_endio(struct generic_callback *cb)
{
	struct trans_logger_aio_aspect *aio_a;
	struct trans_logger_brick *brick;

	aio_a = cb->cb_private;
	CHECK_PTR(aio_a, err);
	if (unlikely(&aio_a->cb != cb)) {
		XIO_FAT("bad callback -- hanging up\n");
		goto err;
	}
	brick = aio_a->my_brick;
	CHECK_PTR(brick, err);

	NEXT_CHECKED_CALLBACK(cb, err);

	atomic_dec(&brick->any_fly_count);
	atomic_inc(&brick->total_cb_count);
	wake_up_interruptible_all(&brick->worker_event);
	goto out_return;
err:
	XIO_FAT("cannot handle callback\n");
out_return:;
}

static
void trans_logger_io_io(struct trans_logger_output *output, struct aio_object *aio)
{
	struct trans_logger_brick *brick = output->brick;
	struct trans_logger_aio_aspect *aio_a;
	struct trans_logger_aio_aspect *shadow_a;
	struct trans_logger_input *input;

	obj_check(aio);

	aio_a = trans_logger_aio_get_aspect(brick, aio);
	CHECK_PTR(aio_a, err);
	CHECK_ASPECT(aio_a, aio, err);

	/*  statistics */
	if (aio->io_rw)
		atomic_inc(&brick->total_write_count);
	else
		atomic_inc(&brick->total_read_count);
	/*  is this a shadow buffer? */
	shadow_a = aio_a->shadow_aio;
	if (shadow_a) {
		CHECK_HEAD_EMPTY(&aio_a->lh.lh_head);
		CHECK_HEAD_EMPTY(&aio_a->hash_head);
		CHECK_HEAD_EMPTY(&aio_a->pos_head);

		obj_get(aio); /*  must be paired with __trans_logger_io_put() */
		atomic_inc(&brick->inner_balance_count);

		qq_aio_insert(&brick->q_phase[0], aio_a);
		wake_up_interruptible_all(&brick->worker_event);
		goto out_return;
	}

	/*  only READ is allowed on non-shadow buffers */
	if (unlikely(aio->io_rw != READ && !aio_a->is_emergency))
		XIO_FAT("bad operation %d on non-shadow\n", aio->io_rw);

	atomic_inc(&brick->any_fly_count);

	aio_a->my_brick = brick;

	INSERT_CALLBACK(aio, &aio_a->cb, _trans_logger_endio, aio_a);

	input = output->brick->inputs[TL_INPUT_READ];

	GENERIC_INPUT_CALL(input, aio_io, aio);
	goto out_return;
err:
	XIO_FAT("cannot handle IO\n");
out_return:;
}

/***************************** writeback info *****************************/

/* save final completion status when necessary
 */
static
void pos_complete(struct trans_logger_aio_aspect *orig_aio_a)
{
	struct trans_logger_brick *brick = orig_aio_a->my_brick;
	struct trans_logger_input *log_input = orig_aio_a->log_input;
	loff_t finished;
	struct list_head *tmp;

	CHECK_PTR(brick, err);
	CHECK_PTR(log_input, err);

	atomic_inc(&brick->total_writeback_count);

	tmp = &orig_aio_a->pos_head;

	down(&log_input->inf_mutex);

	finished = orig_aio_a->log_pos;
	/*  am I the first member? (means "youngest" list entry) */
	if (tmp == log_input->pos_list.next) {
		if (unlikely(finished <= log_input->inf.inf_min_pos))
			XIO_ERR("backskip in log writeback: %lld -> %lld\n", log_input->inf.inf_min_pos, finished);
		if (unlikely(finished > log_input->inf.inf_max_pos))
			XIO_ERR("min_pos > max_pos: %lld > %lld\n", finished, log_input->inf.inf_max_pos);
		log_input->inf.inf_min_pos = finished;
		get_lamport(&log_input->inf.inf_min_pos_stamp);
		_inf_callback(log_input, false);
	} else {
		struct trans_logger_aio_aspect *prev_aio_a;

		prev_aio_a = container_of(tmp->prev, struct trans_logger_aio_aspect, pos_head);
		if (unlikely(finished <= prev_aio_a->log_pos)) {
			XIO_ERR("backskip: %lld -> %lld\n", finished, prev_aio_a->log_pos);
		} else {
			/* Transitively transfer log_pos to the predecessor
			 * to correctly reflect the committed region.
			 */
			prev_aio_a->log_pos = finished;
		}
	}

	list_del_init(tmp);
	atomic_dec(&log_input->pos_count);

	up(&log_input->inf_mutex);
err:;
}

static
void free_writeback(struct writeback_info *wb)
{
	struct list_head *tmp;

	if (unlikely(wb->w_error < 0)) {
		XIO_ERR("writeback error = %d at pos = %lld len = %d, writeback is incomplete\n",
			wb->w_error,
			wb->w_pos,
			wb->w_len);
	}

	/* Now complete the original requests.
	 */
	while ((tmp = wb->w_collect_list.next) != &wb->w_collect_list) {
		struct trans_logger_aio_aspect *orig_aio_a;
		struct aio_object *orig_aio;

		list_del_init(tmp);

		orig_aio_a = container_of(tmp, struct trans_logger_aio_aspect, collect_head);
		orig_aio = orig_aio_a->object;

		obj_check(orig_aio);
		if (unlikely(!orig_aio_a->is_collected)) {
			XIO_ERR("request %lld (len = %d) was not collected\n",
				orig_aio->io_pos,
				orig_aio->io_len);
		}
		if (unlikely(wb->w_error < 0))
			orig_aio_a->wb_error = wb->w_error;

		__trans_logger_io_put(orig_aio_a->my_brick, orig_aio_a);
	}

	brick_mem_free(wb);
}

/* Generic endio() for writeback_info
 */
static
void wb_endio(struct generic_callback *cb)
{
	struct trans_logger_aio_aspect *sub_aio_a;
	struct aio_object *sub_aio;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;
	atomic_t *dec;
	int rw;
	void (**_endio)(struct generic_callback *cb);
	void (*endio)(struct generic_callback *cb);

	LAST_CALLBACK(cb);
	sub_aio_a = cb->cb_private;
	CHECK_PTR(sub_aio_a, err);
	sub_aio = sub_aio_a->object;
	CHECK_PTR(sub_aio, err);
	wb = sub_aio_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);

	if (cb->cb_error < 0)
		wb->w_error = cb->cb_error;

	atomic_dec(&brick->wb_balance_count);

	rw = sub_aio_a->orig_rw;
	dec = rw ? &wb->w_sub_write_count : &wb->w_sub_read_count;
	CHECK_ATOMIC(dec, 1);
	if (!atomic_dec_and_test(dec))
		goto done;

	_endio = rw ? &wb->write_endio : &wb->read_endio;
	endio = *_endio;
	*_endio = NULL;
	if (likely(endio))
		endio(cb);
	else
		XIO_ERR("internal: no endio defined\n");
done:
	wake_up_interruptible_all(&brick->worker_event);
	goto out_return;
err:
	XIO_FAT("hanging up....\n");
out_return:;
}

/* Atomically create writeback info, based on "snapshot" of current hash
 * state.
 * Notice that the hash can change during writeback IO, thus we need
 * struct writeback_info to precisely catch that information at a single
 * point in time.
 */
static
struct writeback_info *make_writeback(struct trans_logger_brick *brick, loff_t pos, int len)
{
	struct writeback_info *wb;
	struct trans_logger_input *read_input;
	struct trans_logger_input *write_input;
	int write_input_nr;

	/* Allocate structure representing a bunch of adjacent writebacks
	 */
	wb = brick_zmem_alloc(sizeof(struct writeback_info));
	if (unlikely(len < 0))
		XIO_ERR("len = %d\n", len);

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
	hash_extend(brick, &wb->w_pos, &wb->w_len, &wb->w_collect_list);

	if (list_empty(&wb->w_collect_list))
		goto collision;

	pos = wb->w_pos;
	len = wb->w_len;

	if (unlikely(len < 0))
		XIO_ERR("len = %d\n", len);

	/* Determine the "channels" we want to operate on
	 */
	read_input = brick->inputs[TL_INPUT_READ];
	write_input_nr = TL_INPUT_WRITEBACK;
	write_input = brick->inputs[write_input_nr];
	if (!write_input->connect) {
		write_input_nr = TL_INPUT_READ;
		write_input = read_input;
	}

	/* Create sub_aios for read of old disk version (phase1)
	 */
	if (brick->log_reads) {
		while (len > 0) {
			struct trans_logger_aio_aspect *sub_aio_a;
			struct aio_object *sub_aio;
			struct trans_logger_input *log_input;
			int this_len;
			int status;

			sub_aio = trans_logger_alloc_aio(brick);

			sub_aio->io_pos = pos;
			sub_aio->io_len = len;
			sub_aio->io_may_write = READ;
			sub_aio->io_rw = READ;
			sub_aio->io_data = NULL;

			sub_aio_a = trans_logger_aio_get_aspect(brick, sub_aio);
			CHECK_PTR(sub_aio_a, err);
			CHECK_ASPECT(sub_aio_a, sub_aio, err);

			sub_aio_a->my_input = read_input;
			log_input = brick->inputs[brick->log_input_nr];
			sub_aio_a->log_input = log_input;
			atomic_inc(&log_input->log_obj_count);
			sub_aio_a->my_brick = brick;
			sub_aio_a->orig_rw = READ;
			sub_aio_a->wb = wb;

			status = GENERIC_INPUT_CALL(read_input, aio_get, sub_aio);
			if (unlikely(status < 0)) {
				XIO_FAT("cannot get sub_aio, status = %d\n", status);
				goto err;
			}

			list_add_tail(&sub_aio_a->sub_head, &wb->w_sub_read_list);
			atomic_inc(&wb->w_sub_read_count);
			atomic_inc(&brick->wb_balance_count);

			this_len = sub_aio->io_len;
			pos += this_len;
			len -= this_len;
		}
		/* Re-init for startover
		 */
		pos = wb->w_pos;
		len = wb->w_len;
	}

	/* Always create sub_aios for writeback (phase3)
	 */
	while (len > 0) {
		struct trans_logger_aio_aspect *sub_aio_a;
		struct aio_object *sub_aio;
		struct trans_logger_aio_aspect *orig_aio_a;
		struct aio_object *orig_aio;
		struct trans_logger_input *log_input;
		void *data;
		int this_len = len;
		int diff;
		int status;

		atomic_inc(&brick->total_hash_find_count);

		orig_aio_a = _hash_find(&wb->w_collect_list, pos, &this_len, true, false);
		if (unlikely(!orig_aio_a)) {
			XIO_FAT("could not find data\n");
			goto err;
		}

		orig_aio = orig_aio_a->object;
		diff = pos - orig_aio->io_pos;
		if (unlikely(diff < 0)) {
			XIO_FAT("bad diff %d\n", diff);
			goto err;
		}
		data = orig_aio_a->shadow_data + diff;

		sub_aio = trans_logger_alloc_aio(brick);

		sub_aio->io_pos = pos;
		sub_aio->io_len = this_len;
		sub_aio->io_may_write = WRITE;
		sub_aio->io_rw = WRITE;
		sub_aio->io_data = data;

		sub_aio_a = trans_logger_aio_get_aspect(brick, sub_aio);
		CHECK_PTR(sub_aio_a, err);
		CHECK_ASPECT(sub_aio_a, sub_aio, err);

		sub_aio_a->orig_aio_a = orig_aio_a;
		sub_aio_a->my_input = write_input;
		log_input = orig_aio_a->log_input;
		sub_aio_a->log_input = log_input;
		atomic_inc(&log_input->log_obj_count);
		sub_aio_a->my_brick = brick;
		sub_aio_a->orig_rw = WRITE;
		sub_aio_a->wb = wb;

		status = GENERIC_INPUT_CALL(write_input, aio_get, sub_aio);
		if (unlikely(status < 0)) {
			XIO_FAT("cannot get sub_aio, status = %d\n", status);
			wb->w_error = status;
			goto err;
		}

		list_add_tail(&sub_aio_a->sub_head, &wb->w_sub_write_list);
		atomic_inc(&wb->w_sub_write_count);
		atomic_inc(&brick->wb_balance_count);

		this_len = sub_aio->io_len;
		pos += this_len;
		len -= this_len;
	}

	return wb;

err:
	XIO_ERR("cleaning up...\n");
collision:
	if (wb)
		free_writeback(wb);
	return NULL;
}

static inline
void _fire_one(struct list_head *tmp, bool do_update)
{
	struct trans_logger_aio_aspect *sub_aio_a;
	struct aio_object *sub_aio;
	struct trans_logger_input *sub_input;

	sub_aio_a = container_of(tmp, struct trans_logger_aio_aspect, sub_head);
	sub_aio = sub_aio_a->object;

	if (unlikely(sub_aio_a->is_fired)) {
		XIO_ERR("trying to fire twice\n");
		goto out_return;
	}
	sub_aio_a->is_fired = true;

	SETUP_CALLBACK(sub_aio, wb_endio, sub_aio_a);

	sub_input = sub_aio_a->my_input;

#ifdef DO_WRITEBACK
	GENERIC_INPUT_CALL(sub_input, aio_io, sub_aio);
#else
	SIMPLE_CALLBACK(sub_aio, 0);
#endif
	if (do_update) { /*  CHECK: shouldn't we do this always? */
		GENERIC_INPUT_CALL(sub_input, aio_put, sub_aio);
	}
out_return:;
}

static inline
void fire_writeback(struct list_head *start, bool do_update)
{
	struct list_head *tmp;

	/* Caution! The wb structure may get deallocated
	 * during _fire_one() in some cases (e.g. when the
	 * callback is directly called by the aio_io operation).
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

static inline
void update_max_pos(struct trans_logger_aio_aspect *orig_aio_a)
{
	loff_t max_pos = orig_aio_a->log_pos;
	struct trans_logger_input *log_input = orig_aio_a->log_input;

	CHECK_PTR(log_input, done);

	down(&log_input->inf_mutex);

	if (unlikely(max_pos < log_input->inf.inf_min_pos))
		XIO_ERR("new max_pos < min_pos: %lld < %lld\n", max_pos, log_input->inf.inf_min_pos);
	if (log_input->inf.inf_max_pos < max_pos) {
		log_input->inf.inf_max_pos = max_pos;
		get_lamport(&log_input->inf.inf_max_pos_stamp);
		_inf_callback(log_input, false);
	}

	up(&log_input->inf_mutex);
done:;
}

static inline
void update_writeback_info(struct writeback_info *wb)
{
	struct list_head *start = &wb->w_collect_list;
	struct list_head *tmp;

	/* Notice: in case of log rotation, each list member
	 * may belong to a different log_input.
	 */
	for (tmp = start->next; tmp != start; tmp = tmp->next) {
		struct trans_logger_aio_aspect *orig_aio_a;

		orig_aio_a = container_of(tmp, struct trans_logger_aio_aspect, collect_head);
		update_max_pos(orig_aio_a);
	}
}

/***************************** worker thread *****************************/

/*********************************************************************
 * Phase 0: write transaction log entry for the original write request.
 */

static
void _complete(struct trans_logger_brick *brick, struct trans_logger_aio_aspect *orig_aio_a, int error, bool pre_io)
{
	struct aio_object *orig_aio;

	orig_aio = orig_aio_a->object;
	CHECK_PTR(orig_aio, err);

	if (orig_aio_a->is_completed ||
	    (pre_io &&
	     (trans_logger_completion_semantics >= 2 ||
	      (trans_logger_completion_semantics >= 1 && !orig_aio->io_skip_sync)))) {
		goto done;
	}

	if (cmpxchg(&orig_aio_a->is_completed, false, true))
		goto done;

	atomic_dec(&brick->log_fly_count);

	if (likely(error >= 0)) {
		aio_checksum(orig_aio);
		orig_aio->io_flags &= ~AIO_WRITING;
		orig_aio->io_flags |= AIO_UPTODATE;
	}
	CHECKED_CALLBACK(orig_aio, error, err);

done:
	goto out_return;
err:
	XIO_ERR("giving up...\n");
out_return:;
}

static
void phase0_preio(void *private)
{
	struct trans_logger_aio_aspect *orig_aio_a;
	struct trans_logger_brick *brick;

	orig_aio_a = private;
	CHECK_PTR(orig_aio_a, err);
	CHECK_PTR(orig_aio_a->object, err);
	brick = orig_aio_a->my_brick;
	CHECK_PTR(brick, err);

	/*  signal completion to the upper layer */
/**/

	obj_check(orig_aio_a->object);
	_complete(brick, orig_aio_a, 0, true);
	obj_check(orig_aio_a->object);
	goto out_return;
err:
	XIO_ERR("giving up...\n");
out_return:;
}

static
void phase0_endio(void *private, int error)
{
	struct aio_object *orig_aio;
	struct trans_logger_aio_aspect *orig_aio_a;
	struct trans_logger_brick *brick;

	orig_aio_a = private;
	CHECK_PTR(orig_aio_a, err);

/*	remove_this */
	if (unlikely(cmpxchg(&orig_aio_a->is_endio, false, true))) {
		XIO_ERR("Sigh this should not happen %p %p\n",
			 orig_aio_a, orig_aio_a->object);
		goto out_return;
	}

/*	end_remove_this */
	brick = orig_aio_a->my_brick;
	CHECK_PTR(brick, err);
	orig_aio = orig_aio_a->object;
	CHECK_PTR(orig_aio, err);

	orig_aio_a->is_persistent = true;
	qq_dec_flying(&brick->q_phase[0]);

	_CHECK(orig_aio_a->shadow_aio, err);

	/*  signal completion to the upper layer */
	_complete(brick, orig_aio_a, error, false);

	/* Queue up for the next phase.
	 */
	qq_aio_insert(&brick->q_phase[1], orig_aio_a);

	/* Undo the above pinning
	 */
	__trans_logger_io_put(brick, orig_aio_a);

	banning_reset(&brick->q_phase[0].q_banning);

	wake_up_interruptible_all(&brick->worker_event);
	goto out_return;
err:
	XIO_ERR("giving up...\n");
out_return:;
}

static
bool phase0_startio(struct trans_logger_aio_aspect *orig_aio_a)
{
	struct aio_object *orig_aio;
	struct trans_logger_brick *brick;
	struct trans_logger_input *input;
	struct log_status *logst;
	loff_t log_pos;
	void *data;
	bool ok;

	CHECK_PTR(orig_aio_a, err);
	orig_aio = orig_aio_a->object;
	CHECK_PTR(orig_aio, err);
	brick = orig_aio_a->my_brick;
	CHECK_PTR(brick, err);
	input = orig_aio_a->log_input;
	CHECK_PTR(input, err);
	logst = &input->logst;
	logst->do_crc = trans_logger_do_crc;

	{
		struct log_header l = {
			.l_stamp = orig_aio_a->stamp,
			.l_pos = orig_aio->io_pos,
			.l_len = orig_aio->io_len,
			.l_code = CODE_WRITE_NEW,
		};
		data = log_reserve(logst, &l);
	}
	if (unlikely(!data))
		goto err;

	hash_ensure_stableness(brick, orig_aio_a);

	memcpy(data, orig_aio_a->shadow_data, orig_aio->io_len);

	/* Pin aio->obj_count so it can't go away
	 * after _complete().
	 * This may happen rather early in phase0_preio().
	 */
	obj_get(orig_aio); /*  must be paired with __trans_logger_io_put() */
	atomic_inc(&brick->inner_balance_count);
	atomic_inc(&brick->log_fly_count);

	ok = log_finalize(logst, orig_aio->io_len, phase0_endio, orig_aio_a);
	if (unlikely(!ok)) {
		atomic_dec(&brick->log_fly_count);
		goto err;
	}
	log_pos = logst->log_pos + logst->offset;
	orig_aio_a->log_pos = log_pos;

	/*  update new log_pos in the symlinks */
	down(&input->inf_mutex);
	input->inf.inf_log_pos = log_pos;
	memcpy(&input->inf.inf_log_pos_stamp, &logst->log_pos_stamp, sizeof(input->inf.inf_log_pos_stamp));
	_inf_callback(input, false);

#ifdef CONFIG_MARS_DEBUG
	if (!list_empty(&input->pos_list)) {
		struct trans_logger_aio_aspect *last_aio_a;

		last_aio_a = container_of(input->pos_list.prev, struct trans_logger_aio_aspect, pos_head);
		if (last_aio_a->log_pos >= orig_aio_a->log_pos)
			XIO_ERR("backskip in pos_list, %lld >= %lld\n", last_aio_a->log_pos, orig_aio_a->log_pos);
	}
#endif
	list_add_tail(&orig_aio_a->pos_head, &input->pos_list);
	atomic_inc(&input->pos_count);
	up(&input->inf_mutex);

	qq_inc_flying(&brick->q_phase[0]);

	phase0_preio(orig_aio_a);

	return true;

err:
	return false;
}

static
bool prep_phase_startio(struct trans_logger_aio_aspect *aio_a)
{
	struct aio_object *aio = aio_a->object;
	struct trans_logger_aio_aspect *shadow_a;
	struct trans_logger_brick *brick;

	CHECK_PTR(aio, err);
	shadow_a = aio_a->shadow_aio;
	CHECK_PTR(shadow_a, err);
	brick = aio_a->my_brick;
	CHECK_PTR(brick, err);

	if (aio->io_rw == READ) {
		/*  nothing to do: directly signal success. */
		struct aio_object *shadow = shadow_a->object;

		if (unlikely(shadow == aio))
			XIO_ERR("oops, we should be a slave shadow, but are a master one\n");
#ifdef USE_MEMCPY
		if (aio_a->shadow_data != aio->io_data) {
			if (unlikely(aio->io_len <= 0 || aio->io_len > PAGE_SIZE))
				XIO_ERR("implausible io_len = %d\n", aio->io_len);
			memcpy(aio->io_data, aio_a->shadow_data, aio->io_len);
		}
#endif
		aio->io_flags |= AIO_UPTODATE;

		CHECKED_CALLBACK(aio, 0, err);

		__trans_logger_io_put(brick, aio_a);

		return true;
	}
	/*  else WRITE */
	CHECK_HEAD_EMPTY(&aio_a->lh.lh_head);
	CHECK_HEAD_EMPTY(&aio_a->hash_head);
	if (unlikely(aio->io_flags & (AIO_READING | AIO_WRITING)))
		XIO_ERR("bad flags %d\n", aio->io_flags);
	/* In case of non-buffered IO, the buffer is
	 * under control of the user. In particular, he
	 * may change it without telling us.
	 * Therefore we make a copy (or "snapshot") here.
	 */
	aio->io_flags |= AIO_WRITING;
#ifdef USE_MEMCPY
	if (aio_a->shadow_data != aio->io_data) {
		if (unlikely(aio->io_len <= 0 || aio->io_len > PAGE_SIZE))
			XIO_ERR("implausible io_len = %d\n", aio->io_len);
		memcpy(aio_a->shadow_data, aio->io_data, aio->io_len);
	}
#endif
	aio_a->is_dirty = true;
	aio_a->shadow_aio->is_dirty = true;
#ifndef KEEP_UNIQUE
	if (unlikely(aio_a->shadow_aio != aio_a))
		XIO_ERR("something is wrong: %p != %p\n", aio_a->shadow_aio, aio_a);
#endif
	if (likely(!aio_a->is_hashed)) {
		struct trans_logger_input *log_input;

		log_input = brick->inputs[brick->log_input_nr];
		aio_a->log_input = log_input;
		atomic_inc(&log_input->log_obj_count);
		hash_insert(brick, aio_a);
	} else {
		XIO_ERR("tried to hash twice\n");
	}
	return phase0_startio(aio_a);

err:
	XIO_ERR("cannot work\n");
	brick_msleep(1000);
	return false;
}

/*********************************************************************
 * Phase 1: read original version of data.
 * This happens _after_ phase 0, deliberately.
 * We are explicitly dealing with old and new versions.
 * The new version is hashed in memory all the time (such that parallel
 * READs will see them), so we have plenty of time for getting the
 * old version from disk somewhen later, e.g. when IO contention is low.
 */

static
void phase1_endio(struct generic_callback *cb)
{
	struct trans_logger_aio_aspect *sub_aio_a;
	struct writeback_info *wb;
	struct trans_logger_brick *brick;

	CHECK_PTR(cb, err);
	sub_aio_a = cb->cb_private;
	CHECK_PTR(sub_aio_a, err);
	wb = sub_aio_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);

	if (unlikely(cb->cb_error < 0)) {
		XIO_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	qq_dec_flying(&brick->q_phase[1]);

	banning_reset(&brick->q_phase[1].q_banning);

	/*  queue up for the next phase */
	qq_wb_insert(&brick->q_phase[2], wb);
	wake_up_interruptible_all(&brick->worker_event);
	goto out_return;
err:
	XIO_FAT("hanging up....\n");
out_return:;
}

static void phase3_endio(struct generic_callback *cb);

static bool phase3_startio(struct writeback_info *wb);

static
bool phase1_startio(struct trans_logger_aio_aspect *orig_aio_a)
{
	struct aio_object *orig_aio;
	struct trans_logger_brick *brick;
	struct writeback_info *wb = NULL;

	CHECK_PTR(orig_aio_a, err);
	orig_aio = orig_aio_a->object;
	CHECK_PTR(orig_aio, err);
	brick = orig_aio_a->my_brick;
	CHECK_PTR(brick, err);

	if (orig_aio_a->is_collected)
		goto done;
	if (!orig_aio_a->is_hashed)
		goto done;

	wb = make_writeback(brick, orig_aio->io_pos, orig_aio->io_len);
	if (unlikely(!wb))
		goto collision;

	if (unlikely(list_empty(&wb->w_sub_write_list))) {
		XIO_ERR("sub_write_list is empty, orig pos = %lld len = %d (collected=%d), extended pos = %lld len = %d\n",
			orig_aio->io_pos,
			orig_aio->io_len,
			(int)orig_aio_a->is_collected,
			wb->w_pos,
			wb->w_len);
		goto err;
	}

	wb->read_endio = phase1_endio;
	wb->write_endio = phase3_endio;
	atomic_set(&wb->w_sub_log_count, atomic_read(&wb->w_sub_read_count));

	if (brick->log_reads) {
		qq_inc_flying(&brick->q_phase[1]);
		fire_writeback(&wb->w_sub_read_list, false);
	} else { /*  shortcut */
#ifndef SHORTCUT_1_to_3
		qq_wb_insert(&brick->q_phase[3], wb);
		wake_up_interruptible_all(&brick->worker_event);
#else
		return phase3_startio(wb);
#endif
	}

done:
	return true;

err:
	if (wb)
		free_writeback(wb);
collision:
	return false;
}

/*********************************************************************
 * Phase 2: log the old disk version.
 */

static inline
void _phase2_endio(struct writeback_info *wb)
{
	struct trans_logger_brick *brick = wb->w_brick;

	/*  queue up for the next phase */
	qq_wb_insert(&brick->q_phase[3], wb);
	wake_up_interruptible_all(&brick->worker_event);
	goto out_return;
out_return:;
}

static
void phase2_endio(void *private, int error)
{
	struct trans_logger_aio_aspect *sub_aio_a;
	struct trans_logger_brick *brick;
	struct writeback_info *wb;

	sub_aio_a = private;
	CHECK_PTR(sub_aio_a, err);
	wb = sub_aio_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);

	qq_dec_flying(&brick->q_phase[2]);

	if (unlikely(error < 0)) {
		XIO_FAT("IO error %d\n", error);
		goto err; /*  FIXME: this leads to hanging requests. do better. */
	}

	CHECK_ATOMIC(&wb->w_sub_log_count, 1);
	if (atomic_dec_and_test(&wb->w_sub_log_count)) {
		banning_reset(&brick->q_phase[2].q_banning);
		_phase2_endio(wb);
	}
	goto out_return;
err:
	XIO_FAT("hanging up....\n");
out_return:;
}

static
bool _phase2_startio(struct trans_logger_aio_aspect *sub_aio_a)
{
	struct aio_object *sub_aio = NULL;
	struct writeback_info *wb;
	struct trans_logger_input *input;
	struct trans_logger_brick *brick;
	struct log_status *logst;
	void *data;
	bool ok;

	CHECK_PTR(sub_aio_a, err);
	sub_aio = sub_aio_a->object;
	CHECK_PTR(sub_aio, err);
	wb = sub_aio_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);
	input = sub_aio_a->log_input;
	CHECK_PTR(input, err);
	logst = &input->logst;
	logst->do_crc = trans_logger_do_crc;

	{
		struct log_header l = {
			.l_stamp = sub_aio_a->stamp,
			.l_pos = sub_aio->io_pos,
			.l_len = sub_aio->io_len,
			.l_code = CODE_WRITE_OLD,
		};
		data = log_reserve(logst, &l);
	}

	if (unlikely(!data))
		goto err;

	memcpy(data, sub_aio->io_data, sub_aio->io_len);

	ok = log_finalize(logst, sub_aio->io_len, phase2_endio, sub_aio_a);
	if (unlikely(!ok))
		goto err;

	qq_inc_flying(&brick->q_phase[2]);

	return true;

err:
	XIO_FAT("cannot log old data, pos = %lld len = %d\n",
		sub_aio ? sub_aio->io_pos : 0,
		sub_aio ? sub_aio->io_len : 0);
	return false;
}

static
bool phase2_startio(struct writeback_info *wb)
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
			struct trans_logger_aio_aspect *sub_aio_a;
			struct aio_object *sub_aio;

			sub_aio_a = container_of(tmp, struct trans_logger_aio_aspect, sub_head);
			sub_aio = sub_aio_a->object;

			if (!_phase2_startio(sub_aio_a))
				ok = false;
		}
		wake_up_interruptible_all(&brick->worker_event);
	} else {
		_phase2_endio(wb);
	}
	return ok;
err:
	return false;
}

/*********************************************************************
 * Phase 3: overwrite old disk version with new version.
 */

static
void phase3_endio(struct generic_callback *cb)
{
	struct trans_logger_aio_aspect *sub_aio_a;
	struct writeback_info *wb;
	struct trans_logger_brick *brick;

	CHECK_PTR(cb, err);
	sub_aio_a = cb->cb_private;
	CHECK_PTR(sub_aio_a, err);
	wb = sub_aio_a->wb;
	CHECK_PTR(wb, err);
	brick = wb->w_brick;
	CHECK_PTR(brick, err);

	if (unlikely(cb->cb_error < 0)) {
		XIO_FAT("IO error %d\n", cb->cb_error);
		goto err;
	}

	hash_put_all(brick, &wb->w_collect_list);

	qq_dec_flying(&brick->q_phase[3]);
	atomic_inc(&brick->total_writeback_cluster_count);

	free_writeback(wb);

	banning_reset(&brick->q_phase[3].q_banning);

	wake_up_interruptible_all(&brick->worker_event);

	goto out_return;
err:
	XIO_FAT("hanging up....\n");
out_return:;
}

static
bool phase3_startio(struct writeback_info *wb)
{
	struct list_head *start = &wb->w_sub_read_list;
	struct list_head *tmp;

	/* Cleanup read requests (if they exist from previous phases)
	 */
	while ((tmp = start->next) != start) {
		struct trans_logger_aio_aspect *sub_aio_a;
		struct aio_object *sub_aio;
		struct trans_logger_input *sub_input;

		list_del_init(tmp);

		sub_aio_a = container_of(tmp, struct trans_logger_aio_aspect, sub_head);
		sub_aio = sub_aio_a->object;
		sub_input = sub_aio_a->my_input;

		GENERIC_INPUT_CALL(sub_input, aio_put, sub_aio);
	}

	update_writeback_info(wb);

	/* Start writeback IO
	 */
	qq_inc_flying(&wb->w_brick->q_phase[3]);
	fire_writeback(&wb->w_sub_write_list, true);
	return true;
}

/*********************************************************************
 * The logger thread.
 * There is only a single instance, dealing with all requests in parallel.
 */

static
int run_aio_queue(struct logger_queue *q,
	bool (*startio)(struct trans_logger_aio_aspect *sub_aio_a),
	int max,
	bool do_limit)
{
	struct trans_logger_brick *brick = q->q_brick;
	int total_len = 0;
	bool found = false;
	bool ok;
	int res = 0;

	do {
		struct trans_logger_aio_aspect *aio_a;

		aio_a = qq_aio_fetch(q);
		if (!aio_a)
			goto done;

		if (do_limit && likely(aio_a->object))
			total_len += aio_a->object->io_len;

		ok = startio(aio_a);
		if (unlikely(!ok)) {
			qq_aio_pushback(q, aio_a);
			goto done;
		}
		res++;
		found = true;
		__trans_logger_io_put(aio_a->my_brick, aio_a);
	} while (--max > 0);

done:
	if (found) {
		rate_limit(&global_writeback.limiter, (total_len - 1) / 1024 + 1);
		wake_up_interruptible_all(&brick->worker_event);
	}
	return res;
}

static
int run_wb_queue(struct logger_queue *q, bool (*startio)(struct writeback_info *wb), int max)
{
	struct trans_logger_brick *brick = q->q_brick;
	int total_len = 0;
	bool found = false;
	bool ok;
	int res = 0;

	do {
		struct writeback_info *wb;

		wb = qq_wb_fetch(q);
		if (!wb)
			goto done;

		total_len += wb->w_len;

		ok = startio(wb);
		if (unlikely(!ok)) {
			qq_wb_pushback(q, wb);
			goto done;
		}
		res++;
		found = true;
	} while (--max > 0);

done:
	if (found) {
		rate_limit(&global_writeback.limiter, (total_len - 1) / 1024 + 1);
		wake_up_interruptible_all(&brick->worker_event);
	}
	return res;
}

/* Ranking tables.
 */
static
struct rank_info float_queue_rank_log[] = {
	{     0,    0 },
	{     1,  100 },
	{ RKI_DUMMY }
};

static
struct rank_info float_queue_rank_io[] = {
	{     0,    0 },
	{     1,    1 },
	{ RKI_DUMMY }
};

static
struct rank_info float_fly_rank_log[] = {
	{     0,    0 },
	{     1,    1 },
	{    32,   10 },
	{ RKI_DUMMY }
};

static
struct rank_info float_fly_rank_io[] = {
	{     0,    0 },
	{     1,   10 },
	{     2,  -10 },
	{ 10000, -200 },
	{ RKI_DUMMY }
};

static
struct rank_info nofloat_queue_rank_log[] = {
	{     0,    0 },
	{     1,   10 },
	{ RKI_DUMMY }
};

static
struct rank_info nofloat_queue_rank_io[] = {
	{     0,    0 },
	{     1,   10 },
	{   100,  100 },
	{ RKI_DUMMY }
};

#define nofloat_fly_rank_log float_fly_rank_log

static
struct rank_info nofloat_fly_rank_io[] = {
	{     0,    0 },
	{     1,   10 },
	{   128,    8 },
	{   129, -200 },
	{ RKI_DUMMY }
};

static
struct rank_info *queue_ranks[2][LOGGER_QUEUES] = {
	[0] = {
		[0] = float_queue_rank_log,
		[1] = float_queue_rank_io,
		[2] = float_queue_rank_io,
		[3] = float_queue_rank_io,
	},
	[1] = {
		[0] = nofloat_queue_rank_log,
		[1] = nofloat_queue_rank_io,
		[2] = nofloat_queue_rank_io,
		[3] = nofloat_queue_rank_io,
	},
};
static
struct rank_info *fly_ranks[2][LOGGER_QUEUES] = {
	[0] = {
		[0] = float_fly_rank_log,
		[1] = float_fly_rank_io,
		[2] = float_fly_rank_io,
		[3] = float_fly_rank_io,
	},
	[1] = {
		[0] = nofloat_fly_rank_log,
		[1] = nofloat_fly_rank_io,
		[2] = nofloat_fly_rank_io,
		[3] = nofloat_fly_rank_io,
	},
};

static
struct rank_info extra_rank_aio_flying[] = {
	{     0,    0 },
	{     1,   10 },
	{    16,   30 },
	{    31,    0 },
	{    32, -200 },
	{ RKI_DUMMY }
};

static
struct rank_info global_rank_aio_flying[] = {
	{     0,    0 },
	{    63,    0 },
	{    64, -200 },
	{ RKI_DUMMY }
};

static
int _do_ranking(struct trans_logger_brick *brick, struct rank_data rkd[])
{
	int res;
	int i;
	int floating_mode;
	int aio_flying;
	bool delay_callers;

	ranking_start(rkd, LOGGER_QUEUES);

	/*  check the memory situation... */
	delay_callers = false;
	floating_mode = 1;
	if (brick_global_memlimit >= 1024) {
		int global_mem_used = atomic64_read(&global_mshadow_used) / 1024;

		trans_logger_mem_usage = global_mem_used;

		floating_mode = (global_mem_used < brick_global_memlimit / 2) ? 0 : 1;

		if (global_mem_used >= brick_global_memlimit)
			delay_callers = true;

	} else if (brick->shadow_mem_limit >= 8) {
		int local_mem_used = atomic64_read(&brick->shadow_mem_used) / 1024;

		floating_mode = (local_mem_used < brick->shadow_mem_limit / 2) ? 0 : 1;

		if (local_mem_used >= brick->shadow_mem_limit)
			delay_callers = true;
	}
	if (delay_callers) {
		if (!brick->delay_callers) {
			brick->delay_callers = true;
			atomic_inc(&brick->total_delay_count);
		}
	} else if (brick->delay_callers) {
		brick->delay_callers = false;
		wake_up_interruptible(&brick->caller_event);
	}

	/*  global limit for flying aios */
	ranking_compute(&rkd[0], global_rank_aio_flying, atomic_read(&global_aio_flying));

	/*  local limit for flying aios */
	aio_flying = 0;
	for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
		struct trans_logger_input *input = brick->inputs[i];

		aio_flying += atomic_read(&input->logst.aio_flying);
	}

	/*  obey the basic rules... */
	for (i = 0; i < LOGGER_QUEUES; i++) {
		int queued = atomic_read(&brick->q_phase[i].q_queued);
		int flying;

		/* This must come first.
		 * When a queue is empty, you must not credit any positive points.
		 * Otherwise, (almost) infinite selection of untreatable
		 * queues may occur.
		 */
		if (queued <= 0)
			continue;

		if (banning_is_hit(&brick->q_phase[i].q_banning))
			break;

		if (i == 0) {
			/*  limit aio IO parallelism on transaction log */
			ranking_compute(&rkd[0], extra_rank_aio_flying, aio_flying);
		} else if (i == 1 && !floating_mode) {
			struct trans_logger_brick *leader;
			int lim;

			if (!aio_flying && atomic_read(&brick->q_phase[0].q_queued) > 0)
				break;

			leader = elect_leader(&global_writeback);
			if (leader != brick)
				break;

			if (banning_is_hit(&xio_global_ban))
				break;

			lim = rate_limit(&global_writeback.limiter, 0);
			if (lim > 0)
				break;
		}

		ranking_compute(&rkd[i], queue_ranks[floating_mode][i], queued);

		flying = atomic_read(&brick->q_phase[i].q_flying);

		ranking_compute(&rkd[i], fly_ranks[floating_mode][i], flying);
	}

	/*  finalize it */
	ranking_stop(rkd, LOGGER_QUEUES);

	res = ranking_select(rkd, LOGGER_QUEUES);

	return res;
}

static
void _init_input(struct trans_logger_input *input, loff_t start_pos, loff_t end_pos)
{
	struct trans_logger_brick *brick = input->brick;
	struct log_status *logst = &input->logst;

	init_logst(logst, (void *)input, start_pos, end_pos);
	logst->signal_event = &brick->worker_event;
	logst->align_size = CONF_TRANS_ALIGN;
	logst->chunk_size = CONF_TRANS_CHUNKSIZE;
	logst->max_size = CONF_TRANS_MAX_AIO_SIZE;

	input->inf.inf_min_pos = start_pos;
	input->inf.inf_max_pos = end_pos;
	get_lamport(&input->inf.inf_max_pos_stamp);
	memcpy(&input->inf.inf_min_pos_stamp, &input->inf.inf_max_pos_stamp, sizeof(input->inf.inf_min_pos_stamp));

	logst->log_pos = start_pos;
	input->inf.inf_log_pos = start_pos;
	input->inf_last_jiffies = jiffies;
	input->inf.inf_is_replaying = false;
	input->inf.inf_is_logging = false;

	input->is_operating = true;
}

static
void _init_inputs(struct trans_logger_brick *brick, bool is_first)
{
	struct trans_logger_input *input;
	int old_nr = brick->old_input_nr;
	int log_nr = brick->log_input_nr;
	int new_nr = brick->new_input_nr;

	if (!is_first &&
	    (new_nr == log_nr ||
	     log_nr != old_nr)) {
		goto done;
	}
	if (unlikely(new_nr < TL_INPUT_LOG1 || new_nr > TL_INPUT_LOG2)) {
		XIO_ERR("bad new_input_nr = %d\n", new_nr);
		goto done;
	}

	input = brick->inputs[new_nr];
	CHECK_PTR(input, done);

	if (input->is_operating || !input->connect)
		goto done;

	down(&input->inf_mutex);

	_init_input(input, 0, 0);
	input->inf.inf_is_logging = is_first;

	/*  from now on, new requests should go to the new input */
	brick->log_input_nr = new_nr;
	XIO_INF("switched over to new logfile %d (old = %d)\n", new_nr, old_nr);

	/* Flush the old log buffer and update its symlinks.
	 * Notice: for some short time, _both_ logfiles may grow
	 * due to (harmless) races with log_flush().
	 */
	if (likely(!is_first)) {
		struct trans_logger_input *other_input = brick->inputs[old_nr];

		down(&other_input->inf_mutex);
		log_flush(&other_input->logst);
		_inf_callback(other_input, true);
		up(&other_input->inf_mutex);
	}

	_inf_callback(input, true);

	up(&input->inf_mutex);
done:;
}

static
int _nr_flying_inputs(struct trans_logger_brick *brick)
{
	int count = 0;
	int i;

	for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
		struct trans_logger_input *input = brick->inputs[i];
		struct log_status *logst = &input->logst;

		if (input->is_operating)
			count += logst->count;
	}
	return count;
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

		if (input->is_operating &&
		    (force || !input->connect)) {
			bool old_replaying = input->inf.inf_is_replaying;
			bool old_logging = input->inf.inf_is_logging;

			XIO_DBG("cleaning up input %d (log = %d old = %d), old_replaying = %d old_logging = %d\n",
				i,
				brick->log_input_nr,
				brick->old_input_nr,
				old_replaying,
				old_logging);
			exit_logst(logst);
			/*  no locking here: we should be the only thread doing this. */
			_inf_callback(input, true);
			input->inf_last_jiffies = 0;
			input->inf.inf_is_replaying = false;
			input->inf.inf_is_logging = false;
			input->is_operating = false;
			if (i == brick->old_input_nr && i != brick->log_input_nr) {
				struct trans_logger_input *other_input = brick->inputs[brick->log_input_nr];

				down(&other_input->inf_mutex);
				brick->old_input_nr = brick->log_input_nr;
				other_input->inf.inf_is_replaying = old_replaying;
				other_input->inf.inf_is_logging = old_logging;
				_inf_callback(other_input, true);
				up(&other_input->inf_mutex);
			}
		}
	}
}

/* Performance-critical:
 * Calling log_flush() too often may result in
 * increased overhead (and thus in lower throughput).
 * Call it only when the IO scheduler need not do anything else.
 * OTOH, calling it too seldom may hold back
 * IO completion for the end user for too long time.
 *
 * Be careful to flush any leftovers in the log buffer, at least after
 * some short delay.
 *
 * Description of flush_mode:
 *  0 = flush unconditionally
 *  1 = flush only when nothing can be appended to the transaction log
 *  2 = see 1 && flush only when the user is waiting for an answer
 *  3 = see 1 && not 2 && flush only when there is no other activity (background mode)
 * Notice: 3 makes only sense for leftovers where the user is _not_ waiting for
 */
static inline
void flush_inputs(struct trans_logger_brick *brick, int flush_mode)
{
	if (flush_mode < 1 ||
	    /*	there is nothing to append any more */
	    (atomic_read(&brick->q_phase[0].q_queued) <= 0 &&
	     /*  and the user is waiting for an answer */
	     (flush_mode < 2 ||
	      atomic_read(&brick->log_fly_count) > 0 ||
	     /*  else flush any leftovers in background, when there is no writeback activity */
	      (flush_mode == 3 &&
	       atomic_read(&brick->q_phase[1].q_flying) + atomic_read(&brick->q_phase[3].q_flying) <= 0))))
		_flush_inputs(brick);
}

static
void trans_logger_log(struct trans_logger_brick *brick)
{
	struct rank_data rkd[LOGGER_QUEUES] = {};
	long long old_jiffies = jiffies;
	long long work_jiffies = jiffies;
	int interleave = 0;
	int nr_flying;

	brick->replay_code = 0; /*  indicates "running" */
	brick->disk_io_error = 0;

	_init_inputs(brick, true);

	xio_set_power_on_led((void *)brick, true);

	while (!brick_thread_should_stop() || _congested(brick)) {
		int winner;
		int nr;

		wait_event_interruptible_timeout(
			brick->worker_event,
			({
				winner = _do_ranking(brick, rkd);
				if (winner < 0) { /*  no more work to do */
					int flush_mode = 2 - ((int)(jiffies - work_jiffies)) / (HZ * 2);

					flush_inputs(brick, flush_mode);
					interleave = 0;
				} else { /*  reset the timer whenever something is to do */
					work_jiffies = jiffies;
				}
				winner >= 0;
			}),
			HZ / 10);

		atomic_inc(&brick->total_round_count);

		if (brick->cease_logging)
			brick->stopped_logging = true;
		else if (brick->stopped_logging && !_congested(brick))
			brick->stopped_logging = false;

		_init_inputs(brick, false);

		switch (winner) {
		case 0:
			interleave = 0;
			nr = run_aio_queue(&brick->q_phase[0],
				prep_phase_startio,
				brick->q_phase[0].q_batchlen,
				true);
			goto done;
		case 1:
			if (interleave >= trans_logger_max_interleave && trans_logger_max_interleave >= 0) {
				interleave = 0;
				flush_inputs(brick, 3);
			}
			nr = run_aio_queue(&brick->q_phase[1], phase1_startio, brick->q_phase[1].q_batchlen, true);
			interleave += nr;
			goto done;
		case 2:
			interleave = 0;
			nr = run_wb_queue(&brick->q_phase[2], phase2_startio, brick->q_phase[2].q_batchlen);
			goto done;
		case 3:
			if (interleave >= trans_logger_max_interleave && trans_logger_max_interleave >= 0) {
				interleave = 0;
				flush_inputs(brick, 3);
			}
			nr = run_wb_queue(&brick->q_phase[3], phase3_startio, brick->q_phase[3].q_batchlen);
			interleave += nr;
done:
			if (unlikely(nr <= 0)) {
				/* This should not happen!
				 * However, in error situations, the ranking
				 * algorithm cannot foresee anything.
				 */
				brick->q_phase[winner].no_progress_count++;
				banning_hit(&brick->q_phase[winner].q_banning, 10000);
				flush_inputs(brick, 0);
			}
			ranking_select_done(rkd, winner, nr);
			break;

		default:
			break;
		}

		/* Update symlinks even during pauses.
		 */
		if (winner < 0 && ((long long)jiffies) - old_jiffies >= HZ) {
			int i;

			old_jiffies = jiffies;
			for (i = TL_INPUT_LOG1; i <= TL_INPUT_LOG2; i++) {
				struct trans_logger_input *input = brick->inputs[i];

				down(&input->inf_mutex);
				_inf_callback(input, false);
				up(&input->inf_mutex);
			}
		}

		_exit_inputs(brick, false);
	}

	for (;;) {
		_exit_inputs(brick, true);
		nr_flying = _nr_flying_inputs(brick);
		if (nr_flying <= 0)
			break;
		XIO_INF("%d inputs are operating\n", nr_flying);
		brick_msleep(1000);
	}
}

/***************************** log replay *****************************/

static
void replay_endio(struct generic_callback *cb)
{
	struct trans_logger_aio_aspect *aio_a = cb->cb_private;
	struct trans_logger_brick *brick;
	bool ok;
	unsigned long flags;

	LAST_CALLBACK(cb);
	CHECK_PTR(aio_a, err);
	brick = aio_a->my_brick;
	CHECK_PTR(brick, err);

	if (unlikely(cb->cb_error < 0)) {
		brick->disk_io_error = cb->cb_error;
		XIO_ERR("IO error = %d\n", cb->cb_error);
	}

	spin_lock_irqsave(&brick->replay_lock, flags);
	ok = !list_empty(&aio_a->replay_head);
	list_del_init(&aio_a->replay_head);
	spin_unlock_irqrestore(&brick->replay_lock, flags);

	if (likely(ok))
		atomic_dec(&brick->replay_count);
	else
		XIO_ERR("callback with empty replay_head (replay_count=%d)\n", atomic_read(&brick->replay_count));
	wake_up_interruptible_all(&brick->worker_event);
	goto out_return;
err:
	XIO_FAT("cannot handle replay IO\n");
out_return:;
}

static
bool _has_conflict(struct trans_logger_brick *brick, struct trans_logger_aio_aspect *aio_a)
{
	struct aio_object *aio = aio_a->object;
	struct list_head *tmp;
	bool res = false;
	unsigned long flags;

/**/

	spin_lock_irqsave(&brick->replay_lock, flags);

	for (tmp = brick->replay_list.next; tmp != &brick->replay_list; tmp = tmp->next) {
		struct trans_logger_aio_aspect *tmp_a;
		struct aio_object *tmp_aio;

		tmp_a = container_of(tmp, struct trans_logger_aio_aspect, replay_head);
		tmp_aio = tmp_a->object;
		if (tmp_aio->io_pos + tmp_aio->io_len > aio->io_pos && tmp_aio->io_pos < aio->io_pos + aio->io_len) {
			res = true;
			break;
		}
	}

	spin_unlock_irqrestore(&brick->replay_lock, flags);
	return res;
}

static
void wait_replay(struct trans_logger_brick *brick, struct trans_logger_aio_aspect *aio_a)
{
	const int max = 512; /*  limit parallelism somewhat */
	int conflicts = 0;
	bool ok = false;
	bool was_empty;
	unsigned long flags;

	wait_event_interruptible_timeout(brick->worker_event,
					 atomic_read(&brick->replay_count) < max
					 && (_has_conflict(brick, aio_a) ? conflicts++ : (ok = true), ok),
					 60 * HZ);

	atomic_inc(&brick->total_replay_count);
	if (conflicts)
		atomic_inc(&brick->total_replay_conflict_count);

	spin_lock_irqsave(&brick->replay_lock, flags);
	was_empty = !!list_empty(&aio_a->replay_head);
	if (likely(was_empty))
		atomic_inc(&brick->replay_count);
	else
		list_del(&aio_a->replay_head);
	list_add(&aio_a->replay_head, &brick->replay_list);
	spin_unlock_irqrestore(&brick->replay_lock, flags);

	if (unlikely(!was_empty)) {
		XIO_ERR("replay_head was already used (ok=%d, conflicts=%d, replay_count=%d)\n",
			ok,
			conflicts,
			atomic_read(&brick->replay_count));
	}
}

static
int replay_data(struct trans_logger_brick *brick, loff_t pos, void *buf, int len)
{
	struct trans_logger_input *input = brick->inputs[TL_INPUT_WRITEBACK];
	int status;

	if (!input->connect)
		input = brick->inputs[TL_INPUT_READ];

	/* TODO for better efficiency:
	 * Instead of starting IO here, just put the data into the hashes
	 * and queues such that ordinary IO will be corrected.
	 * Writeback will be lazy then.
	 * The switch infrastructure must be changed before this
	 * becomes possible.
	 */
#ifdef REPLAY_DATA
	while (len > 0) {
		struct aio_object *aio;
		struct trans_logger_aio_aspect *aio_a;

		status = -ENOMEM;
		aio = trans_logger_alloc_aio(brick);
		aio_a = trans_logger_aio_get_aspect(brick, aio);
		CHECK_PTR(aio_a, done);
		CHECK_ASPECT(aio_a, aio, done);

		aio->io_pos = pos;
		aio->io_data = NULL;
		aio->io_len = len;
		aio->io_may_write = WRITE;
		aio->io_rw = WRITE;

		status = GENERIC_INPUT_CALL(input, aio_get, aio);
		if (unlikely(status < 0)) {
			XIO_ERR("cannot get aio, status = %d\n", status);
			goto done;
		}
		if (unlikely(!aio->io_data)) {
			status = -ENOMEM;
			XIO_ERR("cannot get aio, status = %d\n", status);
			goto done;
		}
		if (unlikely(aio->io_len <= 0 || aio->io_len > len)) {
			status = -EINVAL;
			XIO_ERR("bad aio len = %d (requested = %d)\n", aio->io_len, len);
			goto done;
		}

		wait_replay(brick, aio_a);

		memcpy(aio->io_data, buf, aio->io_len);

		SETUP_CALLBACK(aio, replay_endio, aio_a);
		aio_a->my_brick = brick;

		GENERIC_INPUT_CALL(input, aio_io, aio);

		if (unlikely(aio->io_len <= 0)) {
			status = -EINVAL;
			XIO_ERR("bad aio len = %d (requested = %d)\n", aio->io_len, len);
			goto done;
		}

		pos += aio->io_len;
		buf += aio->io_len;
		len -= aio->io_len;

		GENERIC_INPUT_CALL(input, aio_put, aio);
	}
#endif
	status = 0;
done:
	return status;
}

static
void trans_logger_replay(struct trans_logger_brick *brick)
{
	struct trans_logger_input *input = brick->inputs[brick->log_input_nr];
	struct log_header lh = {};
	loff_t start_pos;
	loff_t end_pos;
	loff_t finished_pos = -1;
	loff_t new_finished_pos = -1;
	long long old_jiffies = jiffies;
	int nr_flying;
	int backoff = 0;
	int status = 0;

	brick->replay_code = 0; /*  indicates "running" */
	brick->disk_io_error = 0;

	start_pos = brick->replay_start_pos;
	end_pos = brick->replay_end_pos;
	brick->replay_current_pos = start_pos;

	_init_input(input, start_pos, end_pos);

	input->inf.inf_min_pos = start_pos;
	input->inf.inf_max_pos = end_pos;
	input->inf.inf_log_pos = end_pos;
	input->inf.inf_is_replaying = true;
	input->inf.inf_is_logging = false;

	XIO_INF("starting replay from %lld to %lld\n", start_pos, end_pos);

	xio_set_power_on_led((void *)brick, true);

	for (;;) {
		void *buf = NULL;
		int len = 0;

		if (brick_thread_should_stop() ||
		   (!brick->continuous_replay_mode && finished_pos >= brick->replay_end_pos)) {
			status = 0; /*	treat as EOF */
			break;
		}

		status = log_read(&input->logst, false, &lh, &buf, &len);

		new_finished_pos = input->logst.log_pos + input->logst.offset;
		XIO_RPL("read	%lld %lld\n", finished_pos, new_finished_pos);

		if (status == -EAGAIN) {
			loff_t remaining = brick->replay_end_pos - new_finished_pos;

			XIO_DBG("got -EAGAIN, remaining = %lld\n", remaining);
			if (brick->replay_tolerance > 0 && remaining < brick->replay_tolerance) {
				XIO_WRN("logfile is truncated at position %lld (end_pos = %lld, remaining = %lld, tolerance = %d)\n",
					 new_finished_pos,
					 brick->replay_end_pos,
					 remaining,
					 brick->replay_tolerance);
				finished_pos = new_finished_pos;
				brick->replay_code = status;
				break;
			}
			brick_msleep(backoff);
			if (backoff < trans_logger_replay_timeout * 1000) {
				backoff += 100;
			} else {
				XIO_WRN("logfile replay not possible at position %lld (end_pos = %lld, remaining = %lld), please check/repair your logfile in userspace by some tool!\n",
					 new_finished_pos,
					 brick->replay_end_pos,
					 remaining);
				brick->replay_code = status;
				break;
			}
			continue;
		}
		if (unlikely(status < 0)) {
			brick->replay_code = status;
			XIO_WRN("cannot read logfile data, status = %d\n", status);
			break;
		}

		if ((!status && len <= 0) ||
		   new_finished_pos > brick->replay_end_pos) { /*  EOF -> wait until brick_thread_should_stop() */
			XIO_DBG("EOF at %lld (old = %lld, end_pos = %lld)\n",
				new_finished_pos,
				finished_pos,
				brick->replay_end_pos);
			if (!brick->continuous_replay_mode) {
				/*  notice: finished_pos remains at old value here! */
				break;
			}
			brick_msleep(1000);
			continue;
		}

		if (lh.l_code != CODE_WRITE_NEW) {
			/* ignore other records silently */;
		} else if (unlikely(brick->disk_io_error)) {
			status = brick->disk_io_error;
			brick->replay_code = status;
			XIO_ERR("IO error %d\n", status);
			break;
		} else if (likely(buf && len)) {
			if (brick->replay_limiter)
				rate_limit_sleep(brick->replay_limiter, (len - 1) / 1024 + 1);
			status = replay_data(brick, lh.l_pos, buf, len);
			XIO_RPL("replay %lld %lld (pos=%lld status=%d)\n",
				finished_pos,
				new_finished_pos,
				lh.l_pos,
				status);
			if (unlikely(status < 0)) {
				brick->replay_code = status;
				XIO_ERR("cannot replay data at pos = %lld len = %d, status = %d\n",
					lh.l_pos,
					len,
					status);
				break;
			} else {
				finished_pos = new_finished_pos;
			}
		}

		/*  do this _after_ any opportunities for errors... */
		if ((atomic_read(&brick->replay_count) <= 0 ||
		     ((long long)jiffies) - old_jiffies >= HZ * 3) &&
		    finished_pos >= 0) {
			/*  for safety, wait until the IO queue has drained. */
			wait_event_interruptible_timeout(brick->worker_event,
				atomic_read(&brick->replay_count) <= 0,
				30 * HZ);

			if (unlikely(brick->disk_io_error)) {
				status = brick->disk_io_error;
				brick->replay_code = status;
				XIO_ERR("IO error %d\n", status);
				break;
			}

			down(&input->inf_mutex);
			input->inf.inf_min_pos = finished_pos;
			get_lamport(&input->inf.inf_min_pos_stamp);
			old_jiffies = jiffies;
			_inf_callback(input, false);
			up(&input->inf_mutex);
		}
		_exit_inputs(brick, false);
	}

	XIO_INF("waiting for finish...\n");

	wait_event_interruptible_timeout(brick->worker_event, atomic_read(&brick->replay_count) <= 0, 60 * HZ);

	if (unlikely(finished_pos > brick->replay_end_pos)) {
		XIO_ERR("finished_pos too large: %lld + %d = %lld > %lld\n",
			input->logst.log_pos,
			input->logst.offset,
			finished_pos,
			brick->replay_end_pos);
	}

	if (finished_pos >= 0 && !brick->disk_io_error) {
		input->inf.inf_min_pos = finished_pos;
		brick->replay_current_pos = finished_pos;
	}

	get_lamport(&input->inf.inf_min_pos_stamp);

	if (status >= 0 && finished_pos == brick->replay_end_pos) {
		XIO_INF("replay finished at %lld\n", finished_pos);
		brick->replay_code = 1;
	} else if (status == -EAGAIN && finished_pos + brick->replay_tolerance > brick->replay_end_pos) {
		XIO_INF("TOLERANCE: logfile is incomplete at %lld (of %lld)\n", finished_pos, brick->replay_end_pos);
		brick->replay_code = 2;
	} else if (status < 0) {
		if (finished_pos < 0)
			finished_pos = new_finished_pos;
		if (finished_pos + brick->replay_tolerance > brick->replay_end_pos) {
			XIO_INF("TOLERANCE: logfile is incomplete at %lld (of %lld), status = %d\n",
				finished_pos,
				brick->replay_end_pos,
				status);
		} else {
			XIO_ERR("replay error %d at %lld (of %lld)\n", status, finished_pos, brick->replay_end_pos);
		}
		brick->replay_code = status;
	} else {
		XIO_INF("replay stopped prematurely at %lld (of %lld)\n", finished_pos, brick->replay_end_pos);
		brick->replay_code = 2;
	}

	for (;;) {
		_exit_inputs(brick, true);
		nr_flying = _nr_flying_inputs(brick);
		if (nr_flying <= 0)
			break;
		XIO_INF("%d inputs are operating\n", nr_flying);
		brick_msleep(1000);
	}

	local_trigger();

	while (!brick_thread_should_stop())
		brick_msleep(500);
}

/************************ logger thread * switching ************************/

static
int trans_logger_thread(void *data)
{
	struct trans_logger_output *output = data;
	struct trans_logger_brick *brick = output->brick;

	XIO_INF("........... logger has started.\n");

	if (brick->replay_mode)
		trans_logger_replay(brick);
	else
		trans_logger_log(brick);
	XIO_INF("........... logger has stopped.\n");
	xio_set_power_on_led((void *)brick, false);
	xio_set_power_off_led((void *)brick, true);
	return 0;
}

static
int trans_logger_switch(struct trans_logger_brick *brick)
{
	static int index;
	struct trans_logger_output *output = brick->outputs[0];

	if (brick->power.button) {
		if (!brick->thread && brick->power.off_led) {
			xio_set_power_off_led((void *)brick, false);

			brick->thread = brick_thread_create(trans_logger_thread, output, "xio_logger%d", index++);
			if (unlikely(!brick->thread)) {
				XIO_ERR("cannot create logger thread\n");
				return -ENOENT;
			}
		}
	} else {
		xio_set_power_on_led((void *)brick, false);
		if (brick->thread) {
			XIO_INF("stopping thread...\n");
			brick_thread_stop(brick->thread);
			brick->thread = NULL;
		}
	}
	return 0;
}

/*************** informational * statistics **************/

static
char *trans_logger_statistics(struct trans_logger_brick *brick, int verbose)
{
	char *res = brick_string_alloc(1024);

	snprintf(res, 1023,
		 "mode replay=%d "
		 "continuous=%d "
		 "replay_code=%d "
		 "disk_io_error=%d "
		 "log_reads=%d | "
		 "cease_logging=%d "
		 "stopped_logging=%d "
		 "congested=%d | "
		 "replay_start_pos = %lld "
		 "replay_end_pos = %lld | "
		 "new_input_nr = %d "
		 "log_input_nr = %d "
		 "(old = %d) "
		 "inf_min_pos1 = %lld "
		 "inf_max_pos1 = %lld "
		 "inf_min_pos2 = %lld "
		 "inf_max_pos2 = %lld | "
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
		 "phase0=%d "
		 "phase1=%d "
		 "phase2=%d "
		 "phase3=%d | "
		 "current #aios = %d "
		 "shadow_mem_used=%ld/%lld "
		 "replay_count=%d "
		 "mshadow=%d/%d "
		 "sshadow=%d "
		 "hash_count=%d "
		 "balance=%d/%d/%d/%d "
		 "pos_count1=%d "
		 "pos_count2=%d "
		 "log_aios1=%d "
		 "log_aios2=%d "
		 "any_fly=%d "
		 "log_fly=%d "
		 "aio_flying1=%d "
		 "aio_flying2=%d "
		 "phase0=%d+%d <%d/%d> "
		 "phase1=%d+%d <%d/%d> "
		 "phase2=%d+%d <%d/%d> "
		 "phase3=%d+%d <%d/%d>\n",
		 brick->replay_mode,
		 brick->continuous_replay_mode,
		 brick->replay_code,
		 brick->disk_io_error,
		 brick->log_reads,
		 brick->cease_logging,
		 brick->stopped_logging,
		 _congested(brick),
		 brick->replay_start_pos,
		 brick->replay_end_pos,
		 brick->new_input_nr,
		 brick->log_input_nr,
		 brick->old_input_nr,
		 brick->inputs[TL_INPUT_LOG1]->inf.inf_min_pos,
		 brick->inputs[TL_INPUT_LOG1]->inf.inf_max_pos,
		 brick->inputs[TL_INPUT_LOG2]->inf.inf_min_pos,
		 brick->inputs[TL_INPUT_LOG2]->inf.inf_max_pos,
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
		 atomic_read(&brick->q_phase[0].q_total),
		 atomic_read(&brick->q_phase[1].q_total),
		 atomic_read(&brick->q_phase[2].q_total),
		 atomic_read(&brick->q_phase[3].q_total),
		 atomic_read(&brick->aio_object_layout.alloc_count),
		 atomic64_read(&brick->shadow_mem_used) / 1024,
		 brick_global_memlimit,
		 atomic_read(&brick->replay_count),
		 atomic_read(&brick->mshadow_count),
		 brick->shadow_mem_limit,
		 atomic_read(&brick->sshadow_count),
		 atomic_read(&brick->hash_count),
		 atomic_read(&brick->sub_balance_count),
		 atomic_read(&brick->inner_balance_count),
		 atomic_read(&brick->outer_balance_count),
		 atomic_read(&brick->wb_balance_count),
		 atomic_read(&brick->inputs[TL_INPUT_LOG1]->pos_count),
		 atomic_read(&brick->inputs[TL_INPUT_LOG2]->pos_count),
		 atomic_read(&brick->inputs[TL_INPUT_LOG1]->log_obj_count),
		 atomic_read(&brick->inputs[TL_INPUT_LOG2]->log_obj_count),
		 atomic_read(&brick->any_fly_count),
		 atomic_read(&brick->log_fly_count),
		 atomic_read(&brick->inputs[TL_INPUT_LOG1]->logst.aio_flying),
		 atomic_read(&brick->inputs[TL_INPUT_LOG2]->logst.aio_flying),
		 atomic_read(&brick->q_phase[0].q_queued),
		 atomic_read(&brick->q_phase[0].q_flying),
		 brick->q_phase[0].pushback_count,
		 brick->q_phase[0].no_progress_count,
		 atomic_read(&brick->q_phase[1].q_queued),
		 atomic_read(&brick->q_phase[1].q_flying),
		 brick->q_phase[1].pushback_count,
		 brick->q_phase[1].no_progress_count,
		 atomic_read(&brick->q_phase[2].q_queued),
		 atomic_read(&brick->q_phase[2].q_flying),
		 brick->q_phase[2].pushback_count,
		 brick->q_phase[2].no_progress_count,
		 atomic_read(&brick->q_phase[3].q_queued),
		 atomic_read(&brick->q_phase[3].q_flying),
		 brick->q_phase[3].pushback_count,
		 brick->q_phase[3].no_progress_count);
	return res;
}

static
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

/*************** object * aspect constructors * destructors **************/

static
int trans_logger_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct trans_logger_aio_aspect *ini = (void *)_ini;

	ini->lh.lh_pos = &ini->object->io_pos;
	INIT_LIST_HEAD(&ini->lh.lh_head);
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->pos_head);
	INIT_LIST_HEAD(&ini->replay_head);
	INIT_LIST_HEAD(&ini->collect_head);
	INIT_LIST_HEAD(&ini->sub_list);
	INIT_LIST_HEAD(&ini->sub_head);
	return 0;
}

static
void trans_logger_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct trans_logger_aio_aspect *ini = (void *)_ini;

	CHECK_HEAD_EMPTY(&ini->lh.lh_head);
	CHECK_HEAD_EMPTY(&ini->hash_head);
	CHECK_HEAD_EMPTY(&ini->pos_head);
	CHECK_HEAD_EMPTY(&ini->replay_head);
	CHECK_HEAD_EMPTY(&ini->collect_head);
	CHECK_HEAD_EMPTY(&ini->sub_list);
	CHECK_HEAD_EMPTY(&ini->sub_head);
	if (ini->log_input)
		atomic_dec(&ini->log_input->log_obj_count);
}

XIO_MAKE_STATICS(trans_logger);

/********************* brick constructors * destructors *******************/

static
void _free_pages(struct trans_logger_brick *brick)
{
	int i;

	for (i = 0; i < NR_HASH_PAGES; i++) {
		struct trans_logger_hash_anchor *sub_table = brick->hash_table[i];
		int j;

		if (!sub_table)
			continue;
		for (j = 0; j < HASH_PER_PAGE; j++) {
			struct trans_logger_hash_anchor *start = &sub_table[j];

			CHECK_HEAD_EMPTY(&start->hash_anchor);
		}
		brick_block_free(sub_table, PAGE_SIZE);
	}
	brick_block_free(brick->hash_table, PAGE_SIZE);
}

static
int trans_logger_brick_construct(struct trans_logger_brick *brick)
{
	int i;

	brick->hash_table = brick_block_alloc(0, PAGE_SIZE);
	memset(brick->hash_table, 0, PAGE_SIZE);

	for (i = 0; i < NR_HASH_PAGES; i++) {
		struct trans_logger_hash_anchor *sub_table;
		int j;

		/*  this should be usually optimized away as dead code */
		if (unlikely(i >= MAX_HASH_PAGES)) {
			XIO_ERR("sorry, subtable index %d is too large.\n", i);
			_free_pages(brick);
			return -EINVAL;
		}

		sub_table = brick_block_alloc(0, PAGE_SIZE);
		brick->hash_table[i] = sub_table;

		memset(sub_table, 0, PAGE_SIZE);
		for (j = 0; j < HASH_PER_PAGE; j++) {
			struct trans_logger_hash_anchor *start = &sub_table[j];

			init_rwsem(&start->hash_mutex);
			INIT_LIST_HEAD(&start->hash_anchor);
		}
	}

	atomic_set(&brick->hash_count, 0);
	spin_lock_init(&brick->replay_lock);
	INIT_LIST_HEAD(&brick->replay_list);
	INIT_LIST_HEAD(&brick->group_head);
	init_waitqueue_head(&brick->worker_event);
	init_waitqueue_head(&brick->caller_event);
	qq_init(&brick->q_phase[0], brick);
	qq_init(&brick->q_phase[1], brick);
	qq_init(&brick->q_phase[2], brick);
	qq_init(&brick->q_phase[3], brick);
	brick->q_phase[0].q_insert_info = "q0_ins";
	brick->q_phase[0].q_pushback_info = "q0_push";
	brick->q_phase[0].q_fetch_info = "q0_fetch";
	brick->q_phase[1].q_insert_info = "q1_ins";
	brick->q_phase[1].q_pushback_info = "q1_push";
	brick->q_phase[1].q_fetch_info = "q1_fetch";
	brick->q_phase[2].q_insert_info = "q2_ins";
	brick->q_phase[2].q_pushback_info = "q2_push";
	brick->q_phase[2].q_fetch_info = "q2_fetch";
	brick->q_phase[3].q_insert_info = "q3_ins";
	brick->q_phase[3].q_pushback_info = "q3_push";
	brick->q_phase[3].q_fetch_info = "q3_fetch";
	brick->new_input_nr = TL_INPUT_LOG1;
	brick->log_input_nr = TL_INPUT_LOG1;
	brick->old_input_nr = TL_INPUT_LOG1;
	add_to_group(&global_writeback, brick);
	return 0;
}

static
int trans_logger_brick_destruct(struct trans_logger_brick *brick)
{
	_free_pages(brick);
	CHECK_HEAD_EMPTY(&brick->replay_list);
	remove_from_group(&global_writeback, brick);
	return 0;
}

static
int trans_logger_output_construct(struct trans_logger_output *output)
{
	return 0;
}

static
int trans_logger_input_construct(struct trans_logger_input *input)
{
	INIT_LIST_HEAD(&input->pos_list);
	sema_init(&input->inf_mutex, 1);
	return 0;
}

static
int trans_logger_input_destruct(struct trans_logger_input *input)
{
	CHECK_HEAD_EMPTY(&input->pos_list);
	return 0;
}

/************************ static structs ***********************/

static struct trans_logger_brick_ops trans_logger_brick_ops = {
	.brick_switch = trans_logger_switch,
	.brick_statistics = trans_logger_statistics,
	.reset_statistics = trans_logger_reset_statistics,
};

static struct trans_logger_output_ops trans_logger_output_ops = {
	.xio_get_info = trans_logger_get_info,
	.aio_get = trans_logger_io_get,
	.aio_put = trans_logger_io_put,
	.aio_io = trans_logger_io_io,
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
	.brick_destruct = &trans_logger_brick_destruct,
};

/***************** module init stuff ************************/

int __init init_xio_trans_logger(void)
{
	XIO_INF("init_trans_logger()\n");
	return trans_logger_register_brick_type();
}

void exit_xio_trans_logger(void)
{
	XIO_INF("exit_trans_logger()\n");
	trans_logger_unregister_brick_type();
}
