/*
 * MARS Long Distance Replication Software
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
 */

/*  Copy brick (just for demonstration) */

//#define BRICK_DEBUGGING
//#define XIO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "xio.h"
#include "../lib/lib_limiter.h"

#ifndef READ
#define READ				0
#define WRITE				1
#endif

#define COPY_CHUNK			(PAGE_SIZE)
#define NR_COPY_REQUESTS		(32 * 1024 * 1024 / COPY_CHUNK)

#define STATES_PER_PAGE			(PAGE_SIZE / sizeof(struct copy_state))
#define MAX_SUB_TABLES			(NR_COPY_REQUESTS / STATES_PER_PAGE + (NR_COPY_REQUESTS % STATES_PER_PAGE ? 1 : 0)\
)
#define MAX_COPY_REQUESTS		(PAGE_SIZE / sizeof(struct copy_state *) * STATES_PER_PAGE)

#define GET_STATE(brick, index)						\
	((brick)->st[(index) / STATES_PER_PAGE][(index) % STATES_PER_PAGE])

/************************ own type definitions ***********************/

#include "xio_copy.h"

int xio_copy_overlap = 1;

int xio_copy_read_prio = XIO_PRIO_NORMAL;

int xio_copy_write_prio = XIO_PRIO_NORMAL;

int xio_copy_read_max_fly;

int xio_copy_write_max_fly;

#define is_read_limited(brick)						\
	(xio_copy_read_max_fly > 0 && atomic_read(&(brick)->copy_read_flight) >= xio_copy_read_max_fly)

#define is_write_limited(brick)						\
	(xio_copy_write_max_fly > 0 && atomic_read(&(brick)->copy_write_flight) >= xio_copy_write_max_fly)

/************************ own helper functions ***********************/

/* TODO:
 * The clash logic is untested / alpha stage (Feb. 2011).
 *
 * For now, the output is never used, so this cannot do harm.
 *
 * In order to get the output really working / enterprise grade,
 * some larger test effort should be invested.
 */
static inline
void _clash(struct copy_brick *brick)
{
	brick->trigger = true;
	set_bit(0, &brick->clash);
	atomic_inc(&brick->total_clash_count);
	wake_up_interruptible(&brick->event);
}

static inline
int _clear_clash(struct copy_brick *brick)
{
	int old;

	old = test_and_clear_bit(0, &brick->clash);
	return old;
}

/* Current semantics:
 *
 * All writes are always going to the original input A. They are _not_
 * replicated to B.
 *
 * In order to get B really uptodate, you have to replay the right
 * transaction logs there (at the right time).
 * [If you had no writes on A at all during the copy, of course
 * this is not necessary]
 *
 * When utilize_mode is on, reads can utilize the already copied
 * region from B, but only as long as this region has not been
 * invalidated by writes (indicated by low_dirty).
 *
 * TODO: implement replicated writes, together with some transaction
 * replay logic applying the transaction logs _only_ after
 * crashes during inconsistency caused by partial replication of writes.
 */
static
int _determine_input(struct copy_brick *brick, struct aio_object *aio)
{
	int rw;
	int below;
	int behind;
	loff_t io_end;

	if (!brick->utilize_mode || brick->low_dirty)
		return INPUT_A_IO;

	io_end = aio->io_pos + aio->io_len;
	below = io_end <= brick->copy_start;
	behind = !brick->copy_end || aio->io_pos >= brick->copy_end;
	rw = aio->io_may_write | aio->io_rw;
	if (rw) {
		if (!behind) {
			brick->low_dirty = true;
			if (!below) {
				_clash(brick);
				wake_up_interruptible(&brick->event);
			}
		}
		return INPUT_A_IO;
	}

	if (below)
		return INPUT_B_IO;

	return INPUT_A_IO;
}

#define GET_INDEX(pos)	  (((pos) / COPY_CHUNK) % NR_COPY_REQUESTS)
#define GET_OFFSET(pos)   ((pos) % COPY_CHUNK)

static
void __clear_aio(struct copy_brick *brick, struct aio_object *aio, int queue)
{
	struct copy_input *input;

	input = queue ? brick->inputs[INPUT_B_COPY] : brick->inputs[INPUT_A_COPY];
	GENERIC_INPUT_CALL(input, aio_put, aio);
}

static
void _clear_aio(struct copy_brick *brick, int index, int queue)
{
	struct copy_state *st = &GET_STATE(brick, index);
	struct aio_object *aio = st->table[queue];

	if (aio) {
		if (unlikely(st->active[queue])) {
			XIO_ERR("clearing active aio, index = %d queue = %d\n", index, queue);
			st->active[queue] = false;
		}
		__clear_aio(brick, aio, queue);
		st->table[queue] = NULL;
	}
}

static
void _clear_all_aio(struct copy_brick *brick)
{
	int i;

	for (i = 0; i < NR_COPY_REQUESTS; i++) {
		GET_STATE(brick, i).state = COPY_STATE_START;
		_clear_aio(brick, i, 0);
		_clear_aio(brick, i, 1);
	}
}

static
void _clear_state_table(struct copy_brick *brick)
{
	int i;

	for (i = 0; i < MAX_SUB_TABLES; i++) {
		struct copy_state *sub_table = brick->st[i];

		memset(sub_table, 0, PAGE_SIZE);
	}
}

static
void copy_endio(struct generic_callback *cb)
{
	struct copy_aio_aspect *aio_a;
	struct aio_object *aio;
	struct copy_brick *brick;
	struct copy_state *st;
	int index;
	int queue;
	int error = 0;

	LAST_CALLBACK(cb);
	aio_a = cb->cb_private;
	CHECK_PTR(aio_a, err);
	aio = aio_a->object;
	CHECK_PTR(aio, err);
	brick = aio_a->brick;
	CHECK_PTR(brick, err);

	queue = aio_a->queue;
	index = GET_INDEX(aio->io_pos);
	st = &GET_STATE(brick, index);

	if (unlikely(queue < 0 || queue >= 2)) {
		XIO_ERR("bad queue %d\n", queue);
		error = -EINVAL;
		goto exit;
	}
	st->active[queue] = false;
	if (unlikely(st->table[queue])) {
		XIO_ERR("table corruption at %d %d (%p => %p)\n", index, queue, st->table[queue], aio);
		error = -EEXIST;
		goto exit;
	}
	if (unlikely(cb->cb_error < 0)) {
		error = cb->cb_error;
		__clear_aio(brick, aio, queue);
		/* This is racy, but does no harm.
		 * Worst case just produces more error output.
		 */
		if (!brick->copy_error_count++)
			XIO_WRN("IO error %d on index %d, old state = %d\n", cb->cb_error, index, st->state);
	} else {
		if (unlikely(st->table[queue])) {
			XIO_ERR("overwriting index %d, state = %d\n", index, st->state);
			_clear_aio(brick, index, queue);
		}
		st->table[queue] = aio;
	}

exit:
	if (unlikely(error < 0)) {
		st->error = error;
		_clash(brick);
	}
	if (aio->io_rw)
		atomic_dec(&brick->copy_write_flight);
	else
		atomic_dec(&brick->copy_read_flight);
	brick->trigger = true;
	wake_up_interruptible(&brick->event);
	goto out_return;
err:
	XIO_FAT("cannot handle callback\n");
out_return:;
}

static
int _make_aio(struct copy_brick *brick,
	int index,
	int queue,
	void *data,
	loff_t pos,
	loff_t end_pos,
	int rw,
	int cs_mode)
{
	struct aio_object *aio;
	struct copy_aio_aspect *aio_a;
	struct copy_input *input;
	int offset;
	int len;
	int status = -EAGAIN;

	if (brick->clash || end_pos <= 0)
		goto done;

	aio = copy_alloc_aio(brick);
	status = -ENOMEM;

	aio_a = copy_aio_get_aspect(brick, aio);
	if (unlikely(!aio_a)) {
		XIO_FAT("cannot get own apsect\n");
		goto done;
	}

	aio_a->brick = brick;
	aio_a->queue = queue;
	aio->io_may_write = rw;
	aio->io_rw = rw;
	aio->io_data = data;
	aio->io_pos = pos;
	aio->io_cs_mode = cs_mode;
	offset = GET_OFFSET(pos);
	len = COPY_CHUNK - offset;
	if (pos + len > end_pos)
		len = end_pos - pos;
	aio->io_len = len;
	aio->io_prio = rw ?
		xio_copy_write_prio :
		xio_copy_read_prio;
	if (aio->io_prio < XIO_PRIO_HIGH || aio->io_prio > XIO_PRIO_LOW)
		aio->io_prio = brick->io_prio;

	SETUP_CALLBACK(aio, copy_endio, aio_a);

	input = queue ? brick->inputs[INPUT_B_COPY] : brick->inputs[INPUT_A_COPY];
	status = GENERIC_INPUT_CALL(input, aio_get, aio);
	if (unlikely(status < 0)) {
		XIO_ERR("status = %d\n", status);
		obj_free(aio);
		goto done;
	}
	if (unlikely(aio->io_len < len))
		XIO_DBG("shorten len %d < %d\n", aio->io_len, len);
	if (queue == 0) {
		GET_STATE(brick, index).len = aio->io_len;
	} else if (unlikely(aio->io_len < GET_STATE(brick, index).len)) {
		XIO_DBG("shorten len %d < %d at index %d\n", aio->io_len, GET_STATE(brick, index).len, index);
		GET_STATE(brick, index).len = aio->io_len;
	}

	GET_STATE(brick, index).active[queue] = true;
	if (rw)
		atomic_inc(&brick->copy_write_flight);
	else
		atomic_inc(&brick->copy_read_flight);
	GENERIC_INPUT_CALL(input, aio_io, aio);

done:
	return status;
}

static
void _update_percent(struct copy_brick *brick, bool force)
{
	if (force
	   || brick->copy_last > brick->copy_start + 8 * 1024 * 1024
	   || time_is_before_jiffies(brick->last_jiffies + 5 * HZ)
	   || (brick->copy_last == brick->copy_end && brick->copy_end > 0)) {
		brick->copy_start = brick->copy_last;
		brick->last_jiffies = jiffies;
		brick->power.percent_done = brick->copy_end > 0 ? brick->copy_start * 100 / brick->copy_end : 0;
		XIO_INF("'%s' copied %lld / %lld bytes (%d%%)\n",
			brick->brick_path,
			brick->copy_last,
			brick->copy_end,
			brick->power.percent_done);
	}
}

/* The heart of this brick.
 * State transition function of the finite automaton.
 * In case no progress is possible (e.g. preconditions not
 * yet true), the state is left as is (idempotence property:
 * calling this too often does no harm, just costs performance).
 */
static
int _next_state(struct copy_brick *brick, int index, loff_t pos)
{
	struct aio_object *aio0;
	struct aio_object *aio1;
	struct copy_state *st;
	char state;
	char next_state;
	bool do_restart = false;
	int progress = 0;
	int status;

	st = &GET_STATE(brick, index);
	next_state = st->state;

restart:
	state = next_state;

	do_restart = false;

	switch (state) {
	case COPY_STATE_RESET:
		/* This state is only entered after errors or
		 * in restarting situations.
		 */
		_clear_aio(brick, index, 1);
		_clear_aio(brick, index, 0);
		next_state = COPY_STATE_START;
		/* fallthrough */
	case COPY_STATE_START:
		/* This is the relgular starting state.
		 * It must be zero, automatically entered via memset()
		 */
		if (st->table[0] || st->table[1]) {
			XIO_ERR("index %d not startable\n", index);
			progress = -EPROTO;
			goto idle;
		}

		_clear_aio(brick, index, 1);
		_clear_aio(brick, index, 0);
		st->writeout = false;
		st->error = 0;

		if (brick->is_aborting ||
		    is_read_limited(brick))
			goto idle;

		status = _make_aio(brick, index, 0, NULL, pos, brick->copy_end, READ, brick->verify_mode ? 2 : 0);
		if (unlikely(status < 0)) {
			XIO_DBG("status = %d\n", status);
			progress = status;
			break;
		}

		next_state = COPY_STATE_READ1;
		if (!brick->verify_mode)
			break;

		next_state = COPY_STATE_START2;
		/* fallthrough */
	case COPY_STATE_START2:
		status = _make_aio(brick, index, 1, NULL, pos, brick->copy_end, READ, 2);
		if (unlikely(status < 0)) {
			XIO_DBG("status = %d\n", status);
			progress = status;
			break;
		}
		next_state = COPY_STATE_READ2;
		/* fallthrough */
	case COPY_STATE_READ2:
		aio1 = st->table[1];
		if (!aio1) { /*  idempotence: wait by unchanged state */
			goto idle;
		}
		/* fallthrough = > wait for both aios to appear */
	case COPY_STATE_READ1:
	case COPY_STATE_READ3:
		aio0 = st->table[0];
		if (!aio0) { /*  idempotence: wait by unchanged state */
			goto idle;
		}
		if (brick->copy_limiter) {
			int amount = (aio0->io_len - 1) / 1024 + 1;

			rate_limit_sleep(brick->copy_limiter, amount);
		}
		/*  on append mode: increase the end pointer dynamically */
		if (brick->append_mode > 0 && aio0->io_total_size && aio0->io_total_size > brick->copy_end)
			brick->copy_end = aio0->io_total_size;
		/*  do verify (when applicable) */
		aio1 = st->table[1];
		if (aio1 && state != COPY_STATE_READ3) {
			int len = aio0->io_len;
			bool ok;

			if (len != aio1->io_len) {
				ok = false;
			} else if (aio0->io_cs_mode) {
				static unsigned char null[sizeof(aio0->io_checksum)];

				ok = !memcmp(aio0->io_checksum, aio1->io_checksum, sizeof(aio0->io_checksum));
				if (ok)
					ok = memcmp(aio0->io_checksum, null, sizeof(aio0->io_checksum)) != 0;
			} else if (!aio0->io_data || !aio1->io_data) {
				ok = false;
			} else {
				ok = !memcmp(aio0->io_data, aio1->io_data, len);
			}

			_clear_aio(brick, index, 1);

			if (ok)
				brick->verify_ok_count++;
			else
				brick->verify_error_count++;

			if (ok || !brick->repair_mode) {
				/* skip start of writing, goto final treatment of writeout */
				next_state = COPY_STATE_CLEANUP;
				break;
			}
		}

		if (aio0->io_cs_mode > 1) { /*	re-read, this time with data */
			_clear_aio(brick, index, 0);
			status = _make_aio(brick, index, 0, NULL, pos, brick->copy_end, READ, 0);
			if (unlikely(status < 0)) {
				XIO_DBG("status = %d\n", status);
				progress = status;
				next_state = COPY_STATE_RESET;
				break;
			}
			next_state = COPY_STATE_READ3;
			break;
		}
		next_state = COPY_STATE_WRITE;
		/* fallthrough */
	case COPY_STATE_WRITE:
		if (is_write_limited(brick))
			goto idle;
		/* Obey ordering to get a strict "append" behaviour.
		 * We assume that we don't need to wait for completion
		 * of the previous write to avoid a sparse result file
		 * under all circumstances, i.e. we only assure that
		 * _starting_ the writes is in order.
		 * This is only correct when all lower bricks obey the
		 * order of io_io() operations.
		 * Currenty, bio and aio are obeying this. Be careful when
		 * implementing new IO bricks!
		 */
		if (st->prev >= 0 && !GET_STATE(brick, st->prev).writeout)
			goto idle;
		aio0 = st->table[0];
		if (unlikely(!aio0 || !aio0->io_data)) {
			XIO_ERR("src buffer for write does not exist, state %d at index %d\n", state, index);
			progress = -EILSEQ;
			break;
		}
		if (unlikely(brick->is_aborting)) {
			progress = -EINTR;
			break;
		}
		/* start writeout */
		status = _make_aio(brick, index, 1, aio0->io_data, pos, pos + aio0->io_len, WRITE, 0);
		if (unlikely(status < 0)) {
			XIO_DBG("status = %d\n", status);
			progress = status;
			next_state = COPY_STATE_RESET;
			break;
		}
		/* Attention! overlapped IO behind EOF could
		 * lead to temporary inconsistent state of the
		 * file, because the write order may be different from
		 * strict O_APPEND behaviour.
		 */
		if (xio_copy_overlap)
			st->writeout = true;
		next_state = COPY_STATE_WRITTEN;
		/* fallthrough */
	case COPY_STATE_WRITTEN:
		aio1 = st->table[1];
		if (!aio1) { /*  idempotence: wait by unchanged state */
			goto idle;
		}
		st->writeout = true;
		/* rechecking means to start over again.
		 * ATTENTIION! this may lead to infinite request
		 * submission loops, intentionally.
		 * TODO: implement some timeout means.
		 */
		if (brick->recheck_mode && brick->repair_mode) {
			next_state = COPY_STATE_RESET;
			break;
		}
		next_state = COPY_STATE_CLEANUP;
		/* fallthrough */
	case COPY_STATE_CLEANUP:
		_clear_aio(brick, index, 1);
		_clear_aio(brick, index, 0);
		next_state = COPY_STATE_FINISHED;
		/* fallthrough */
	case COPY_STATE_FINISHED:
		/* Indicate successful completion by remaining in this state.
		 * Restart of the finite automaton must be done externally.
		 */
		goto idle;
	default:
		XIO_ERR("illegal state %d at index %d\n", state, index);
		_clash(brick);
		progress = -EILSEQ;
	}

	do_restart = (state != next_state);

idle:
	if (unlikely(progress < 0)) {
		if (st->error >= 0)
			st->error = progress;
		XIO_DBG("progress = %d\n", progress);
		progress = 0;
		_clash(brick);
	} else if (do_restart) {
		goto restart;
	} else if (st->state != next_state) {
		progress++;
	}

	/*  save the resulting state */
	st->state = next_state;
	return progress;
}

static
int _run_copy(struct copy_brick *brick)
{
	int max;
	loff_t pos;
	loff_t limit = -1;

	short prev;
	int progress;

	if (unlikely(_clear_clash(brick))) {
		XIO_DBG("clash\n");
		if (atomic_read(&brick->copy_read_flight) + atomic_read(&brick->copy_write_flight) > 0) {
			/* wait until all pending copy IO has finished
			 */
			_clash(brick);
			XIO_DBG("re-clash\n");
			brick_msleep(100);
			return 0;
		}
		_clear_all_aio(brick);
		_clear_state_table(brick);
	}

	/* Do at most max iterations in the below loop
	 */
	max = NR_COPY_REQUESTS - atomic_read(&brick->io_flight) * 2;

	prev = -1;
	progress = 0;
	for (pos = brick->copy_last; pos < brick->copy_end || brick->append_mode > 1; pos = ((pos / COPY_CHUNK) + 1) * COPY_CHUNK) {
		int index = GET_INDEX(pos);
		struct copy_state *st = &GET_STATE(brick, index);

		if (max-- <= 0)
			break;
		st->prev = prev;
		prev = index;
		/*  call the finite state automaton */
		if (!(st->active[0] | st->active[1])) {
			progress += _next_state(brick, index, pos);
			limit = pos;
		}
	}

	/*  check the resulting state: can we advance the copy_last pointer? */
	if (likely(progress && !brick->clash)) {
		int count = 0;

		for (pos = brick->copy_last; pos <= limit; pos = ((pos / COPY_CHUNK) + 1) * COPY_CHUNK) {
			int index = GET_INDEX(pos);
			struct copy_state *st = &GET_STATE(brick, index);

			if (st->state != COPY_STATE_FINISHED)
				break;
			if (unlikely(st->error < 0)) {
				/* check for fatal consistency errors */
				if (st->error == -EMEDIUMTYPE) {
					brick->copy_error = st->error;
					brick->abort_mode = true;
					XIO_WRN("Consistency is violated\n");
				}
				if (!brick->copy_error) {
					brick->copy_error = st->error;
					XIO_WRN("IO error = %d\n", st->error);
				}
				if (brick->abort_mode)
					brick->is_aborting = true;
				break;
			}
			/*  rollover */
			st->state = COPY_STATE_START;
			count += st->len;
			/*  check contiguity */
			if (unlikely(GET_OFFSET(pos) + st->len != COPY_CHUNK))
				break;
		}
		if (count > 0) {
			brick->copy_last += count;
			get_lamport(&brick->copy_last_stamp);
			_update_percent(brick, false);
		}
	}
	return progress;
}

static
bool _is_done(struct copy_brick *brick)
{
	if (brick_thread_should_stop())
		brick->is_aborting = true;
	return brick->is_aborting &&
		atomic_read(&brick->copy_read_flight) + atomic_read(&brick->copy_write_flight) <= 0;
}

static int _copy_thread(void *data)
{
	struct copy_brick *brick = data;
	int rounds = 0;

	XIO_DBG("--------------- copy_thread %p starting\n", brick);
	brick->copy_error = 0;
	brick->copy_error_count = 0;
	brick->verify_ok_count = 0;
	brick->verify_error_count = 0;

	_update_percent(brick, true);

	xio_set_power_on_led((void *)brick, true);
	brick->trigger = true;

	while (!_is_done(brick)) {
		loff_t old_start = brick->copy_start;
		loff_t old_end = brick->copy_end;
		int progress = 0;

		if (old_end > 0) {
			progress = _run_copy(brick);
			if (!progress || ++rounds > 1000)
				rounds = 0;
		}

		wait_event_interruptible_timeout(brick->event,
						 progress > 0 ||
						 brick->trigger ||
						 brick->copy_start != old_start ||
						 brick->copy_end != old_end ||
						 _is_done(brick),
						 1 * HZ);
		brick->trigger = false;
	}

	/* check for fatal consistency errors */
	if (brick->copy_error == -EMEDIUMTYPE) {
		/* reset the whole area */
		brick->copy_start = 0;
		brick->copy_last = 0;
		XIO_WRN("resetting the full copy area\n");
	}
	_update_percent(brick, true);

	XIO_DBG("--------------- copy_thread terminating (%d read requests / %d write requests flying, copy_start = %lld copy_end = %lld)\n",
		 atomic_read(&brick->copy_read_flight),
		 atomic_read(&brick->copy_write_flight),
		 brick->copy_start,
		 brick->copy_end);

	_clear_all_aio(brick);
	xio_set_power_off_led((void *)brick, true);
	XIO_DBG("--------------- copy_thread done.\n");
	return 0;
}

/***************** own brick * input * output operations *****************/

static int copy_get_info(struct copy_output *output, struct xio_info *info)
{
	struct copy_input *input = output->brick->inputs[INPUT_B_IO];

	return GENERIC_INPUT_CALL(input, xio_get_info, info);
}

static int copy_io_get(struct copy_output *output, struct aio_object *aio)
{
	struct copy_input *input;
	int index;
	int status;

	index = _determine_input(output->brick, aio);
	input = output->brick->inputs[index];
	status = GENERIC_INPUT_CALL(input, aio_get, aio);
	if (status >= 0)
		atomic_inc(&output->brick->io_flight);
	return status;
}

static void copy_io_put(struct copy_output *output, struct aio_object *aio)
{
	struct copy_input *input;
	int index;

	index = _determine_input(output->brick, aio);
	input = output->brick->inputs[index];
	GENERIC_INPUT_CALL(input, aio_put, aio);
	if (atomic_dec_and_test(&output->brick->io_flight)) {
		output->brick->trigger = true;
		wake_up_interruptible(&output->brick->event);
	}
}

static void copy_io_io(struct copy_output *output, struct aio_object *aio)
{
	struct copy_input *input;
	int index;

	index = _determine_input(output->brick, aio);
	input = output->brick->inputs[index];
	GENERIC_INPUT_CALL(input, aio_io, aio);
}

static int copy_switch(struct copy_brick *brick)
{
	static int version;

	XIO_DBG("power.button = %d\n", brick->power.button);
	if (brick->power.button) {
		if (brick->power.on_led)
			goto done;
		xio_set_power_off_led((void *)brick, false);
		brick->is_aborting = false;
		if (!brick->thread) {
			brick->copy_last = brick->copy_start;
			get_lamport(&brick->copy_last_stamp);
			brick->thread = brick_thread_create(_copy_thread, brick, "xio_copy%d", version++);
			if (brick->thread) {
				brick->trigger = true;
			} else {
				xio_set_power_off_led((void *)brick, true);
				XIO_ERR("could not start copy thread\n");
			}
		}
	} else {
		if (brick->power.off_led)
			goto done;
		xio_set_power_on_led((void *)brick, false);
		if (brick->thread) {
			XIO_INF("stopping thread...\n");
			brick_thread_stop(brick->thread);
		}
	}
done:
	return 0;
}

/*************** informational * statistics **************/

static
char *copy_statistics(struct copy_brick *brick, int verbose)
{
	char *res = brick_string_alloc(1024);

	snprintf(res, 1024,
		 "copy_start = %lld "
		 "copy_last = %lld "
		 "copy_end = %lld "
		 "copy_error = %d "
		 "copy_error_count = %d "
		 "verify_ok_count = %d "
		 "verify_error_count = %d "
		 "low_dirty = %d "
		 "is_aborting = %d "
		 "clash = %lu | "
		 "total clash_count = %d | "
		 "io_flight = %d "
		 "copy_read_flight = %d "
		 "copy_write_flight = %d\n",
		 brick->copy_start,
		 brick->copy_last,
		 brick->copy_end,
		 brick->copy_error,
		 brick->copy_error_count,
		 brick->verify_ok_count,
		 brick->verify_error_count,
		 brick->low_dirty,
		 brick->is_aborting,
		 brick->clash,
		 atomic_read(&brick->total_clash_count),
		 atomic_read(&brick->io_flight),
		 atomic_read(&brick->copy_read_flight),
		 atomic_read(&brick->copy_write_flight));

	return res;
}

static
void copy_reset_statistics(struct copy_brick *brick)
{
	atomic_set(&brick->total_clash_count, 0);
}

/*************** object * aspect constructors * destructors **************/

static int copy_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct copy_aio_aspect *ini = (void *)_ini;

	(void)ini;
	return 0;
}

static void copy_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct copy_aio_aspect *ini = (void *)_ini;

	(void)ini;
}

XIO_MAKE_STATICS(copy);

/********************* brick constructors * destructors *******************/

static
void _free_pages(struct copy_brick *brick)
{
	int i;

	for (i = 0; i < MAX_SUB_TABLES; i++) {
		struct copy_state *sub_table = brick->st[i];

		if (!sub_table)
			continue;

		brick_block_free(sub_table, PAGE_SIZE);
	}
	brick_block_free(brick->st, PAGE_SIZE);
}

static int copy_brick_construct(struct copy_brick *brick)
{
	int i;

	brick->st = brick_block_alloc(0, PAGE_SIZE);
	memset(brick->st, 0, PAGE_SIZE);

	for (i = 0; i < MAX_SUB_TABLES; i++) {
		struct copy_state *sub_table;

		/*  this should be usually optimized away as dead code */
		if (unlikely(i >= MAX_SUB_TABLES)) {
			XIO_ERR("sorry, subtable index %d is too large.\n", i);
			_free_pages(brick);
			return -EINVAL;
		}

		sub_table = brick_block_alloc(0, PAGE_SIZE);
		brick->st[i] = sub_table;
		memset(sub_table, 0, PAGE_SIZE);
	}

	init_waitqueue_head(&brick->event);
	sema_init(&brick->mutex, 1);
	return 0;
}

static int copy_brick_destruct(struct copy_brick *brick)
{
	_free_pages(brick);
	return 0;
}

static int copy_output_construct(struct copy_output *output)
{
	return 0;
}

static int copy_output_destruct(struct copy_output *output)
{
	return 0;
}

/************************ static structs ***********************/

static struct copy_brick_ops copy_brick_ops = {
	.brick_switch = copy_switch,
	.brick_statistics = copy_statistics,
	.reset_statistics = copy_reset_statistics,
};

static struct copy_output_ops copy_output_ops = {
	.xio_get_info = copy_get_info,
	.aio_get = copy_io_get,
	.aio_put = copy_io_put,
	.aio_io = copy_io_io,
};

const struct copy_input_type copy_input_type = {
	.type_name = "copy_input",
	.input_size = sizeof(struct copy_input),
};

static const struct copy_input_type *copy_input_types[] = {
	&copy_input_type,
	&copy_input_type,
	&copy_input_type,
	&copy_input_type,
};

const struct copy_output_type copy_output_type = {
	.type_name = "copy_output",
	.output_size = sizeof(struct copy_output),
	.master_ops = &copy_output_ops,
	.output_construct = &copy_output_construct,
	.output_destruct = &copy_output_destruct,
};

static const struct copy_output_type *copy_output_types[] = {
	&copy_output_type,
};

const struct copy_brick_type copy_brick_type = {
	.type_name = "copy_brick",
	.brick_size = sizeof(struct copy_brick),
	.max_inputs = 4,
	.max_outputs = 1,
	.master_ops = &copy_brick_ops,
	.aspect_types = copy_aspect_types,
	.default_input_types = copy_input_types,
	.default_output_types = copy_output_types,
	.brick_construct = &copy_brick_construct,
	.brick_destruct = &copy_brick_destruct,
};

/***************** module init stuff ************************/

int __init init_xio_copy(void)
{
	XIO_INF("init_copy()\n");
	return copy_register_brick_type();
}

void exit_xio_copy(void)
{
	XIO_INF("exit_copy()\n");
	copy_unregister_brick_type();
}
