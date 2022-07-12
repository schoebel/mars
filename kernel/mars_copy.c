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


// Copy brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"
#include "lib_limiter.h"

#ifndef READ
#define READ  0
#define WRITE 1
#endif

#define COPY_CHUNK         (PAGE_SIZE)
#define NR_COPY_REQUESTS   (128 * 1024 * 1024 / COPY_CHUNK)

#define STATES_PER_PAGE    (PAGE_SIZE / sizeof(struct copy_state))
#define MAX_SUB_TABLES     (NR_COPY_REQUESTS / STATES_PER_PAGE + (NR_COPY_REQUESTS % STATES_PER_PAGE ? 1 : 0))

#define GET_STATE(brick,index)						\
	((brick)->st[(unsigned)(index) / STATES_PER_PAGE][(unsigned)(index) % STATES_PER_PAGE])

///////////////////////// own type definitions ////////////////////////

#include "mars_copy.h"

int mars_copy_overlap = 1;
EXPORT_SYMBOL_GPL(mars_copy_overlap);

/* Always leave at 1, disable only for throughput _testing_ */
int mars_copy_strict_write_order = 1;

int mars_copy_timeout = 180;

int mars_copy_read_prio = MARS_PRIO_NORMAL;
EXPORT_SYMBOL_GPL(mars_copy_read_prio);

int mars_copy_write_prio = MARS_PRIO_NORMAL;
EXPORT_SYMBOL_GPL(mars_copy_write_prio);

int mars_copy_read_max_fly = 32768;
EXPORT_SYMBOL_GPL(mars_copy_read_max_fly);

int mars_copy_write_max_fly = 32768;
EXPORT_SYMBOL_GPL(mars_copy_write_max_fly);

atomic_t global_copy_read_flight;
atomic_t global_copy_write_flight;

#define is_read_limited(brick)						\
	(mars_copy_read_max_fly > 0 && atomic_read(&global_copy_read_flight) >= mars_copy_read_max_fly)

#define is_write_limited(brick)						\
	(mars_copy_write_max_fly > 0 && atomic_read(&global_copy_write_flight) >= mars_copy_write_max_fly)

///////////////////////// own helper functions ////////////////////////

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
	set_bit(0, &brick->clash);
	atomic_inc(&brick->total_clash_count);
	WRITE_ONCE(brick->trigger, true);
	wake_up_interruptible(&brick->event);
}

static inline
int _clear_clash(struct copy_brick *brick)
{
	int old;
	old = test_and_clear_bit(0, &brick->clash);
	return old;
}

/* Current semantics (NOT REALLY IMPLEMENTED because OUTPUT IS NOT IN USE)
 *
 * All writes from the OUTPUT are always going to the original input A. They are _not_
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
struct copy_input *_determine_input(struct copy_brick *brick, struct mref_object *mref)
{
	struct copy_mref_aspect *mref_a;

	mref_a = copy_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get own aspect from %p %p\n",
			 brick, mref);
		return NULL;
	}
	/* TODO: implement the new logic, for the envisioned
	 * new use cases.
	 */
	return mref_a->input;
}

#define GET_INDEX(pos)    (((unsigned long)(pos) / COPY_CHUNK) % NR_COPY_REQUESTS)
#define GET_OFFSET(pos)   ((unsigned long)(pos) % COPY_CHUNK)

static
void __clear_mref(struct copy_brick *brick, struct mref_object *mref, unsigned queue)
{
	struct copy_input *input;

	input = queue ? brick->inputs[INPUT_B] : brick->inputs[INPUT_A];
	GENERIC_INPUT_CALL_VOID(input, mref_put, mref);
}

static
void _clear_mref(struct copy_brick *brick, unsigned index, unsigned queue)
{
	struct copy_state *st = &GET_STATE(brick, index);
	struct mref_object *mref = READ_ONCE(st->table[queue]);

	if (mref) {
		/* This should never happen */
		if (unlikely(READ_ONCE(st->active[queue]))) {
			WRITE_ONCE(st->active[queue], false);
			MARS_ERR("clearing active mref, index = %u queue = %u\n",
				 index, queue);
		}
		__clear_mref(brick, mref, queue);
		WRITE_ONCE(st->table[queue], NULL);
	}
}

static
void _clear_all_mref(struct copy_brick *brick)
{
	unsigned i;

	for (i = 0; i < NR_COPY_REQUESTS; i++) {
		GET_STATE(brick, i).state = COPY_STATE_START;
		_clear_mref(brick, i, 0);
		_clear_mref(brick, i, 1);
	}
}

static
void _clear_state_table(struct copy_brick *brick)
{
	unsigned i;

	for (i = 0; i < MAX_SUB_TABLES; i++) {
		struct copy_state *sub_table = brick->st[i];

		memset(sub_table, 0, PAGE_SIZE);
	}
	mb();
}

static
void copy_endio(struct generic_callback *cb)
{
	struct copy_mref_aspect *mref_a;
	struct mref_object *mref;
	struct copy_input *input;
	struct copy_brick *brick;
	struct copy_state *st;
	struct mref_object *old_mref;
	unsigned index;
	unsigned check_index;
	unsigned queue;
	int error = 0;

	LAST_CALLBACK(cb);
	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);
	brick = mref_a->brick;
	CHECK_PTR(brick, err);

	/* This is racy, but affects only a _hint_ for
	 * performance optimization.
	 */
	input = mref_a->input;
	if (input &&
	    (!input->check_hint || mref->ref_pos < input->check_hint))
		input->check_hint = mref->ref_pos;

	queue = mref_a->saved_queue;
	index = mref_a->saved_index;
	/* index paranoia */
	check_index = GET_INDEX(mref_a->orig_ref_pos);
	if (unlikely(check_index != index)) {
		/* This should not happen */
		MARS_ERR("index slippery %u != %u on queue=%u: mref=%p mref_a=%p cb=%p err=%d\n",
			 index, check_index,
			 queue,
			 mref, mref_a,
			 cb, cb->cb_error);
		error = -EEXIST;
		goto exit;
	}

	st = &GET_STATE(brick, index);

	MARS_IO("queue=%u index=%u pos=%lld state=%d err=%d\n",
		queue, index,
		mref->ref_pos,
		st->state,
		cb->cb_error);

	if (unlikely(queue >= 2)) {
		MARS_ERR("bad queue %u at %p %p state=%d err=%d\n",
			 queue,
			 cb, mref_a,
			 st->state,
			 cb->cb_error);
		error = -EINVAL;
		goto exit;
	}
	old_mref = READ_ONCE(st->table[queue]);
	if (unlikely(old_mref != mref)) {
		MARS_ERR("table corruption at index=%u queue=%u: %p => %p state=%d err=%d\n",
			 index, queue,
			 old_mref, mref,
			 st->state,
			 cb->cb_error);
		error = -EEXIST;
		goto exit;
	}
	if (unlikely(cb->cb_error < 0)) {
		error = cb->cb_error;
		/* This is racy, but does no harm.
		 * Worst case just produces more error output.
		 */
		if (!brick->copy_error_count++) {
			MARS_WRN("IO error on index=%u state=%d err=%d\n",
				 index,
				 st->state,
				 cb->cb_error);
		}
	}

exit:
	if (unlikely(error < 0)) {
		WRITE_ONCE(st->error, error);
		_clash(brick);
	}
	WRITE_ONCE(st->active[queue], false);
	if (mref->ref_flags & MREF_WRITE) {
		atomic_dec(&brick->copy_write_flight);
		atomic_dec(&global_copy_write_flight);
	} else {
		atomic_dec(&brick->copy_read_flight);
		atomic_dec(&global_copy_read_flight);
	}
	WRITE_ONCE(brick->trigger, true);
	wake_up_interruptible(&brick->event);
	return;

err:
	MARS_FAT("cannot handle callback\n");
}

static
int _make_mref(struct copy_brick *brick,
	       const unsigned index,
	       /* let the compiler check for 0 <= queue <= 1 */
	       const bool _queue,
	       void *data,
	       loff_t current_pos, loff_t end_pos,
	       __u32 flags)
{
	struct mref_object *mref;
	struct copy_mref_aspect *mref_a;
	struct copy_input *input;
	struct copy_state *st;
	struct mref_object *old_mref;
	loff_t diff;
	const unsigned queue = _queue;
	unsigned input_index;
	unsigned offset;
	unsigned max_len;
	unsigned len;
	int ref_len;
	int status = -EAGAIN;

	/* Does it make sense to create a new mref right here? */
	if (brick->clash)
		goto done;
	status = -EINVAL;
	if (current_pos < 0 || end_pos <= 0)
		goto done;
	diff = (end_pos - current_pos);
	if (diff <= 0)
		goto done;

	/* Some safeguards */
	if (unlikely(queue < 0 || queue >= 2)) {
		MARS_ERR("trying bad queue %d\n",
			 queue);
		goto done;
	}
	if (unlikely(index > NR_COPY_REQUESTS)) {
		MARS_ERR("trying bad index=%u at queue=%d pos=%lld+%lld flags=%d\n",
			 index, queue,
			 current_pos, diff, flags);
		goto done;
	}

	/* Check the state table */
	st = &GET_STATE(brick, index);
	old_mref = READ_ONCE(st->table[queue]);
	if (unlikely(old_mref)) {
		MARS_ERR("cannot overrride old_mref=%p at index=%u queue=%d pos=%lld+%lld flags=%d\n",
			 old_mref,
			 index, queue,
			 current_pos, diff, flags);
		status = -EEXIST;
		goto done;
	}

	/* Now create the new mref and remember in st->table[] */

	mref = copy_alloc_mref(brick);
	status = -ENOMEM;
	if (unlikely(!mref))
		goto done;

	mref_a = copy_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect from %p %p\n",
			 brick, mref);
		goto done;
	}

	/* Save some important values for the lifetime of
	 * of the mref object and the corresponding aspect instance.
	 */
	/*input = queue ? brick->inputs[INPUT_B] : brick->inputs[INPUT_A];*/
	input_index = INPUT_A + (queue * (INPUT_B - INPUT_A));
	input = brick->inputs[input_index];
	mref_a->input = input;
	mref_a->brick = brick;
	mref_a->orig_ref_pos = current_pos;
	mref_a->saved_queue = queue;
	mref_a->saved_index = index;

	/* Compute the start values for the new mref */
	mref->ref_flags = flags;
	mref->ref_data = data;
	mref->ref_pos = current_pos;
	offset = GET_OFFSET(current_pos);
	max_len = COPY_CHUNK - offset;
	/* higher end values than 2GiB may occur at big devices */
	if (diff > COPY_CHUNK)
		diff = COPY_CHUNK;
	len = diff;
	if (len > max_len) {
		len = max_len;
	}
	mref->ref_len = len;
	mref->ref_prio = (flags & MREF_WRITE) ?
		mars_copy_write_prio :
		mars_copy_read_prio;
	if (mref->ref_prio < MARS_PRIO_HIGH || mref->ref_prio > MARS_PRIO_LOW)
		mref->ref_prio = brick->io_prio;

	status = GENERIC_INPUT_CALL(input, mref_get, mref);
	if (unlikely(status < 0)) {
		MARS_ERR("mref_get %u status = %d\n",
			 len, status);
		mars_free_mref(mref);
		goto done;
	}
	/* In general, mref_get() may deliver a shorter buffer,
	 * and even EOF.
	 */
	WRITE_ONCE(st->len, len);
	ref_len = mref->ref_len;
	if (ref_len >= 0 && ref_len < len) {
		WRITE_ONCE(st->len, ref_len);
		MARS_DBG("shorten len %d < %u at queue=%d index=%u\n",
			 ref_len, len, queue, index);
	}
	SETUP_CALLBACK(mref, copy_endio, mref_a);

	/* Setup done.
	 * Start IO, somewhen triggering the callback.
	 */
	if (flags & MREF_WRITE) {
		atomic_inc(&brick->copy_write_flight);
		atomic_inc(&global_copy_write_flight);
	} else {
		atomic_inc(&brick->copy_read_flight);
		atomic_inc(&global_copy_read_flight);
	}
	WRITE_ONCE(st->table[queue], mref);
	WRITE_ONCE(st->active[queue], true);

	GENERIC_INPUT_CALL_VOID(input, mref_io, mref);

done:
	return status;
}

static
void _update_percent(struct copy_brick *brick, bool force)
{
	if (force
	   || brick->copy_last > brick->copy_start + 8 * 1024 * 1024
	   || (long long)jiffies > brick->last_jiffies + 5 * HZ
	   || (brick->copy_last == brick->copy_end && brick->copy_end > 0)) {
		brick->copy_start = brick->copy_last;
		brick->last_jiffies = jiffies;
		brick->power.percent_done = brick->copy_end > 0 ? brick->copy_start * 100 / brick->copy_end : 0;
		MARS_INF("'%s' copied %lld / %lld bytes (%d%%)\n", brick->brick_path, brick->copy_last, brick->copy_end, brick->power.percent_done);
	}
}

static inline
__u32 _make_flags(bool verify_mode, bool is_local)
{
	if (!verify_mode)
		return 0;

	if (is_local)
		return available_digest_mask | MREF_NODATA;

	return (usable_digest_mask & ~disabled_net_digests) | MREF_NODATA;
}


/* The heart of this brick.
 * State transition function of the finite automaton.
 * In case no progress is possible (e.g. preconditions not
 * yet true), the state is left as is (idempotence property:
 * calling this too often does no harm, just costs performance).
 */
static
int _next_state(struct copy_brick *brick, unsigned index, loff_t pos)
{
	struct mref_object *mref0;
	struct mref_object *mref1;
	struct copy_state *st;
	enum _copy_state state;
	enum _copy_state next_state;
	bool do_restart = false;
	int progress = 0;
	int status;

	st = &GET_STATE(brick, index);
	next_state = st->state;

restart:
	state = next_state;

	MARS_IO("ENTER index=%u state=%d pos=%lld table[0]=%p table[1]=%p active[0]=%d active[1]=%d writeout=%d prev=%d len=%u error=%d do_restart=%d\n",
		index,
		state,
		pos,
		READ_ONCE(st->table[0]),
		READ_ONCE(st->table[1]),
		READ_ONCE(st->active[0]),
		READ_ONCE(st->active[1]),
		st->writeout,
		st->prev,
		st->len,
		st->error,
		do_restart);

	do_restart = false;

	switch (state) {
	case COPY_STATE_RESET:
		/* This state is only entered after errors or
		 * in restarting situations.
		 */
		_clear_mref(brick, index, 1);
		_clear_mref(brick, index, 0);
		next_state = COPY_STATE_START;
		/* fallthrough */
	case COPY_STATE_START:
		/* This is the relgular starting state.
		 * It must be zero, automatically entered via memset()
		 */
		if ((unsigned long)READ_ONCE(st->table[0]) |
		    (unsigned long)READ_ONCE(st->table[1])) {
			MARS_ERR("index %u not startable at pos=%lld\n",
				 index, pos);
			progress = -EPROTO;
			goto idle;
		}

		st->writeout = false;
		WRITE_ONCE(st->error, 0);

		if (brick->is_aborting ||
		    is_read_limited(brick))
			goto idle;

		status = _make_mref(brick, index, 0, NULL,
				    pos, brick->copy_end,
				    _make_flags(brick->verify_mode, false));
		if (unlikely(status < 0)) {
			MARS_DBG("status = %d\n", status);
			progress = status;
			break;
		}

		next_state = COPY_STATE_READ1;
		if (!brick->verify_mode) {
			break;
		}

		next_state = COPY_STATE_START2;
		/* fallthrough */
	case COPY_STATE_START2:
		status = _make_mref(brick, index, 1, NULL,
				    pos, brick->copy_end,
				    _make_flags(true, true));
		if (unlikely(status < 0)) {
			MARS_DBG("status = %d\n", status);
			progress = status;
			break;
		}
		next_state = COPY_STATE_READ2;
		/* fallthrough */
	case COPY_STATE_READ2:
		if (READ_ONCE(st->active[1])) {
			/* idempotence: wait by unchanged state */
			goto idle;
		}
		/* wait for both mrefs to appear */
		/* fallthrough */
	case COPY_STATE_READ1:
	case COPY_STATE_READ3:
		if (READ_ONCE(st->active[0])) {
			/* idempotence: wait by unchanged state */
			goto idle;
		}
		mref0 = READ_ONCE(st->table[0]);
		if (brick->copy_limiter) {
			int amount = (mref0->ref_len - 1) / 1024 + 1;
			mars_limit_sleep(brick->copy_limiter, amount);
		}
		// on append mode: increase the end pointer dynamically
		if (brick->append_mode > 0 && mref0->ref_total_size && mref0->ref_total_size > brick->copy_end) {
			brick->copy_end = mref0->ref_total_size;
		}
		// do verify (when applicable)
		mref1 = READ_ONCE(st->table[1]);
		if (mref1 && state != COPY_STATE_READ3) { 
			int len = mref0->ref_len;
			bool ok;

			if (len != mref1->ref_len) {
				ok = false;
			} else if (mref0->ref_flags & MREF_CHKSUM_ANY) {
				static unsigned char null[sizeof(mref0->ref_checksum)];
				ok = !memcmp(mref0->ref_checksum, mref1->ref_checksum, sizeof(mref0->ref_checksum));
				if (ok)
					ok = memcmp(mref0->ref_checksum, null, sizeof(mref0->ref_checksum)) != 0;
			} else if (!mref0->ref_data || !mref1->ref_data) {
				ok = false;
			} else {
				ok = !memcmp(mref0->ref_data, mref1->ref_data, len);
			}

			_clear_mref(brick, index, 1);

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

		if ((mref0->ref_flags & MREF_CHKSUM_ANY) && (mref0->ref_flags & MREF_NODATA)) {
			/* re-read, this time with data */
			_clear_mref(brick, index, 0);
			status = _make_mref(brick, index, 0, NULL,
					    pos, brick->copy_end,
					    _make_flags(false, false));
			if (unlikely(status < 0)) {
				MARS_DBG("status = %d\n", status);
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
		 * order of ref_io() operations.
		 * Currenty, bio and aio are obeying this. Be careful when
		 * implementing new IO bricks!
		 */
		if (mars_copy_strict_write_order &&
		    st->prev >= 0 &&
		    !GET_STATE(brick, st->prev).writeout) {
			goto idle;
		}
		mref0 = READ_ONCE(st->table[0]);
		if (unlikely(!mref0 || !mref0->ref_data)) {
			MARS_ERR("src buffer for write does not exist, state %d at index %u\n",
				 state, index);
			progress = -EILSEQ;
			break;
		}
		if (unlikely(READ_ONCE(st->active[0]))) {
			MARS_ERR("src buffer for write is active, state %d at index %u\n",
				 state, index);
			progress = -EILSEQ;
			break;
		}
		if (unlikely(brick->is_aborting)) {
			progress = -EINTR;
			break;
		}
		/* start writeout */
		status = _make_mref(brick, index, 1, mref0->ref_data,
				    pos, pos + mref0->ref_len,
				    MREF_WRITE | MREF_MAY_WRITE);
		if (unlikely(status < 0)) {
			MARS_DBG("status = %d\n", status);
			progress = status;
			next_state = COPY_STATE_RESET;
			break;
		}
		/* Attention! overlapped IO behind EOF could
		 * lead to temporary inconsistent state of the
		 * file, because the write order may be different from
		 * strict O_APPEND behaviour.
		 */
		if (mars_copy_overlap)
			st->writeout = true;
		next_state = COPY_STATE_WRITTEN;
		/* fallthrough */
	case COPY_STATE_WRITTEN:
		if (READ_ONCE(st->active[1])) {
			/* idempotence: wait by unchanged state */
			MARS_IO("irrelevant\n");
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
		_clear_mref(brick, index, 1);
		_clear_mref(brick, index, 0);
		next_state = COPY_STATE_FINISHED;
		/* fallthrough */
	case COPY_STATE_FINISHED:
		/* Indicate successful completion by remaining in this state.
		 * Restart of the finite automaton must be done externally.
		 */
		goto idle;
	default:
		MARS_ERR("illegal state %d at index %u\n",
			 state, index);
		_clash(brick);
		progress = -EILSEQ;
	}

	do_restart = (state != next_state);

idle:
	if (unlikely(progress < 0)) {
		if (READ_ONCE(st->error) >= 0)
			WRITE_ONCE(st->error, progress);
		MARS_DBG("progress = %d\n", progress);
		progress = 0;
		_clash(brick);
	} else if (do_restart) {
		goto restart;
	} else if (st->state != next_state) {
		progress++;
	}

	MARS_IO("LEAVE index=%u state=%d next_state=%d table[0]=%p table[1]=%p active[0]=%d active[1]=%d writeout=%d prev=%d len=%u error=%d progress=%d\n",
		index,
		st->state,
		next_state,
		READ_ONCE(st->table[0]),
		READ_ONCE(st->table[1]),
		READ_ONCE(st->active[0]),
		READ_ONCE(st->active[1]),
		st->writeout,
		st->prev,
		st->len,
		st->error,
		progress);

	// save the resulting state
	st->state = next_state;
	return progress;
}

static
int _run_copy(struct copy_brick *brick, loff_t this_start)
{
	int all_max;
	int max;
	loff_t pos;
	short prev;
	int progress;

	if (unlikely(_clear_clash(brick))) {
		MARS_DBG("clash\n");
		if (atomic_read(&brick->copy_read_flight) + atomic_read(&brick->copy_write_flight) > 0) {
			/* wait until all pending copy IO has finished
			 */
			_clash(brick);
			MARS_DBG("re-clash\n");
			brick_msleep(100);
			return 0;
		}
		_clear_all_mref(brick);
		_clear_state_table(brick);
	}

	if (this_start < brick->copy_last)
		this_start = brick->copy_last;
	else if (this_start > brick->copy_dirty && brick->copy_dirty)
		this_start = brick->copy_dirty;

	/* Do at most max iterations in the below loop
	 */
	max = NR_COPY_REQUESTS - 1 - atomic_read(&brick->io_flight) * 2;
	if (unlikely(max < 32))
		max = 32;
	all_max = max;
	MARS_IO("max = %d\n", max);

	prev = -1;
	if (this_start > brick->copy_last) {
		if (this_start >= COPY_CHUNK)
			prev = GET_INDEX(this_start - COPY_CHUNK);
		max -= (this_start - brick->copy_last) / COPY_CHUNK;
		all_max = max;
	}
	progress = 0;
	for (pos = this_start;
	     pos < brick->copy_end || brick->append_mode > 1;
	     pos = ((pos / COPY_CHUNK) + 1) * COPY_CHUNK) {
		unsigned index = GET_INDEX(pos);
		struct copy_state *st = &GET_STATE(brick, index);
		int this_progress;

		if (max-- <= 0) {
			break;
		}
		st->prev = prev;
		prev = index;
		if (READ_ONCE(st->active[0]) & READ_ONCE(st->active[1]))
			break;

		// call the finite state automaton
		this_progress = _next_state(brick, index, pos);
		if (this_progress <= 0)
			break;

		progress += this_progress;
		if (pos > brick->copy_dirty)
			brick->copy_dirty = pos;
	}

	// check the resulting state: can we advance the copy_last pointer?
	if (this_start == brick->copy_last && progress && !brick->clash) {
		int count = 0;
		int error;

		max = all_max;
		for (pos = brick->copy_last;
		     pos < brick->copy_end;
		     pos = ((pos / COPY_CHUNK) + 1) * COPY_CHUNK) {
			unsigned len;
			unsigned index = GET_INDEX(pos);
			struct copy_state *st = &GET_STATE(brick, index);

			if (st->state != COPY_STATE_FINISHED) {
				break;
			}
			if (max-- <= 0) {
				break;
			}
			error = READ_ONCE(st->error);
			if (unlikely(error < 0)) {
				/* check for fatal consistency errors */
				if (error == -EMEDIUMTYPE) {
					brick->copy_error = error;
					brick->abort_mode = true;
					MARS_WRN("Consistency is violated\n");
				}
				if (!brick->copy_error) {
					brick->copy_error = error;
					MARS_WRN("IO error = %d\n", error);
				}
				if (brick->abort_mode) {
					brick->is_aborting = true;
				}
				break;
			}
			// rollover
			st->state = COPY_STATE_START;
			len = st->len;
			count += len;
			// check contiguity
			if (unlikely(GET_OFFSET(pos) + len != COPY_CHUNK)) {
				/* Short read detected: shorten the copy_end.
				 */
				brick->copy_end = pos + len;
				break;
			}
		}
		if (count > 0) {
			brick->copy_last += count;
			get_lamport(NULL, &brick->copy_last_stamp);
			MARS_IO("new copy_last += %d => %lld\n", count, brick->copy_last);
			_update_percent(brick, false);
		}
	}
	return progress;
}

static
bool _is_done(struct copy_brick *brick)
{
	if (!brick->power.led_on || brick_thread_should_stop())
		brick->is_aborting = true;
	return brick->is_aborting &&
		atomic_read(&brick->copy_read_flight) + atomic_read(&brick->copy_write_flight) <= 0;
}

static int _copy_thread(void *data)
{
	struct copy_brick *brick = data;
	struct lamport_time last_progress;
	int i;

	MARS_DBG("--------------- copy_thread %p starting\n", brick);
	brick->copy_error = 0;
	brick->copy_error_count = 0;
	brick->verify_ok_count = 0;
	brick->verify_error_count = 0;
	for (i = 0; i < COPY_INPUT_NR; i++)
		brick->inputs[i]->check_hint = 0;

	get_real_lamport(&last_progress);

	if (brick->copy_limiter)
			mars_limit_reset(brick->copy_limiter);
	_update_percent(brick, true);

	WRITE_ONCE(brick->trigger, true);

        while (!_is_done(brick)) {
		loff_t old_start = brick->copy_start;
		loff_t old_end = brick->copy_end;
		int progress = 0;
		loff_t check_hint;

		if (old_end > 0) {
			loff_t old_last = brick->copy_last;
			loff_t old_dirty = brick->copy_dirty;

			progress = _run_copy(brick, -1);

			/* This is racy, deliberately.
			 * Missing some events does no harm.
			 */
			for (i = 0; i < COPY_INPUT_NR; i++) {
				check_hint = brick->inputs[i]->check_hint;
				if (check_hint > 0) {
					brick->inputs[i]->check_hint = 0;
					progress += _run_copy(brick, check_hint);
				}
			}
			/* earlier resume working at the tail */
			if (brick->copy_last > old_last && old_dirty)
				progress += _run_copy(brick, old_dirty);
			/* abort when no progress is made for a longer time */
			if (progress > 0) {
				get_real_lamport(&last_progress);
			} else {
				struct lamport_time next_progress;

				get_real_lamport(&next_progress);
				next_progress.tv_sec -= mars_copy_timeout;
				if (lamport_time_compare(&next_progress, &last_progress) > 0)
					brick->is_aborting = true;
			}
		}

		wait_event_interruptible_timeout(brick->event,
						 progress > 0 ||
						 READ_ONCE(brick->trigger) ||
						 brick->copy_start != old_start ||
						 brick->copy_end != old_end ||
						 _is_done(brick),
						 1 * HZ);
		WRITE_ONCE(brick->trigger, false);
	}

	if (brick->copy_limiter)
			mars_limit_reset(brick->copy_limiter);

	/* check for fatal consistency errors */
	if (brick->copy_error == -EMEDIUMTYPE) {
		/* reset the whole area */
		brick->copy_start = 0;
		brick->copy_last = 0;
		brick->copy_dirty = 0;
		MARS_WRN("resetting the full copy area\n");
	}
	_update_percent(brick, true);

	MARS_DBG("--------------- copy_thread terminating (%d read requests / %d write requests flying, copy_start = %lld copy_end = %lld)\n",
		 atomic_read(&brick->copy_read_flight),
		 atomic_read(&brick->copy_write_flight),
		 brick->copy_start,
		 brick->copy_end);

	_clear_all_mref(brick);
	brick->terminated = true;
	mars_trigger();
	MARS_DBG("--------------- copy_thread done.\n");
	return 0;
}

////////////////// own brick / input / output operations //////////////////

static int copy_get_info(struct copy_output *output, struct mars_info *info)
{
	struct copy_input *input = output->brick->inputs[INPUT_B];

	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int copy_ref_get(struct copy_output *output, struct mref_object *mref)
{
	struct copy_input *input;
	int status;

	input = _determine_input(output->brick, mref);

	status = GENERIC_INPUT_CALL(input, mref_get, mref);
	if (status >= 0) {
		atomic_inc(&output->brick->io_flight);
	}
	return status;
}

static void copy_ref_put(struct copy_output *output, struct mref_object *mref)
{
	struct copy_brick *brick = output->brick;
	struct copy_input *input;

	input = _determine_input(brick, mref);

	GENERIC_INPUT_CALL_VOID(input, mref_put, mref);
	if (atomic_dec_and_test(&brick->io_flight)) {
		WRITE_ONCE(brick->trigger, true);
		wake_up_interruptible(&brick->event);
	}
}

static void copy_ref_io(struct copy_output *output, struct mref_object *mref)
{
	struct copy_input *input;

	input = _determine_input(output->brick, mref);

	GENERIC_INPUT_CALL_VOID(input, mref_io, mref);
}

static int copy_switch(struct copy_brick *brick)
{
	static int version = 0;

	MARS_DBG("power.button = %d\n", brick->power.button);
	if (brick->power.button && !brick->terminated) {
		if (brick->power.led_on || brick->thread)
			goto done;
		mars_power_led_off((void*)brick, false);
		brick->is_aborting = false;
		if (!brick->thread) {
			brick->copy_last = brick->copy_start;
			brick->copy_dirty = 0;
			brick->terminated = false;
			mars_power_led_on((void*)brick, true);
			get_lamport(NULL, &brick->copy_last_stamp);
			brick->thread = brick_thread_create(_copy_thread, brick, "mars_copy%d", version++);
			if (brick->thread) {
				WRITE_ONCE(brick->trigger, true);
			} else {
				mars_power_led_on((void*)brick, false);
				mars_power_led_off((void*)brick, true);
				MARS_ERR("could not start copy thread\n");
			}
		}
	} else {
		/* Tell thread to stop asynchronously */
		mars_power_led_on((void*)brick, false);
		if (brick->thread) {
			/* Notice: this will be reported by the thread */
			if (!brick->terminated)
				goto done;
			MARS_INF("stopping thread...\n");
			brick_thread_stop(brick->thread);
		}
		/* for safety, and when the thread was not started */
		mars_power_led_off((void*)brick, true);
		brick->terminated = false;
	}
done:
	return 0;
}


//////////////// informational / statistics ///////////////

static
char *copy_statistics(struct copy_brick *brick, int verbose)
{
	char *res = brick_string_alloc(1024);
        if (!res)
                return NULL;
	
	snprintf(res, 1024,
		 "copy_start = %lld "
		 "copy_last = %lld "
		 "copy_dirty = %lld "
		 "copy_end = %lld "
		 "check_hint[0] = %lld "
		 "check_hint[1] = %lld "
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
		 brick->copy_dirty,
		 brick->copy_end,
		 brick->inputs[0]->check_hint,
		 brick->inputs[1]->check_hint,
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

//////////////// object / aspect constructors / destructors ///////////////

static int copy_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct copy_mref_aspect *ini = (void*)_ini;

	(void)ini;
	return 0;
}

static void copy_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct copy_mref_aspect *ini = (void*)_ini;

	(void)ini;
}

MARS_MAKE_STATICS(copy);

////////////////////// brick constructors / destructors ////////////////////

static
void _free_pages(struct copy_brick *brick)
{
	unsigned i;

	for (i = 0; i < MAX_SUB_TABLES; i++) {
		struct copy_state *sub_table = brick->st[i];

		if (!sub_table) {
			continue;
		}

		brick_block_free(sub_table, PAGE_SIZE);
	}
	brick_block_free(brick->st, PAGE_SIZE);
}

static int copy_brick_construct(struct copy_brick *brick)
{
	unsigned i;

	brick->st = brick_block_alloc(0, PAGE_SIZE);
	memset(brick->st, 0, PAGE_SIZE);

	for (i = 0; i < MAX_SUB_TABLES; i++) {
		struct copy_state *sub_table;

		// this should be usually optimized away as dead code
		if (unlikely(i >= MAX_SUB_TABLES)) {
			MARS_ERR("sorry, subtable index %u is too large.\n", i);
			_free_pages(brick);
			return -EINVAL;
		}

		sub_table = brick_block_alloc(0, PAGE_SIZE);
		brick->st[i] = sub_table;
		memset(sub_table, 0, PAGE_SIZE);
	}

	init_waitqueue_head(&brick->event);
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

///////////////////////// static structs ////////////////////////

static struct copy_brick_ops copy_brick_ops = {
	.brick_switch = copy_switch,
        .brick_statistics = copy_statistics,
        .reset_statistics = copy_reset_statistics,
};

static struct copy_output_ops copy_output_ops = {
	.mars_get_info = copy_get_info,
	.mref_get = copy_ref_get,
	.mref_put = copy_ref_put,
	.mref_io = copy_ref_io,
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
EXPORT_SYMBOL_GPL(copy_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_copy(void)
{
	MARS_INF("init_copy()\n");
	return copy_register_brick_type();
}

void exit_mars_copy(void)
{
	MARS_INF("exit_copy()\n");
	copy_unregister_brick_type();
}
