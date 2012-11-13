// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

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

///////////////////////// own type definitions ////////////////////////

#include "mars_copy.h"

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
	brick->trigger = true;
	set_bit(0, &brick->clash);
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
int _determine_input(struct copy_brick *brick, struct mref_object *mref)
{
	int rw;
	int below;
	int behind;
	loff_t ref_end;

	if (!brick->utilize_mode || brick->low_dirty)
		return INPUT_A_IO;

	ref_end = mref->ref_pos + mref->ref_len;
	below = ref_end <= brick->copy_start;
	behind = !brick->copy_end || mref->ref_pos >= brick->copy_end;
	rw = mref->ref_may_write | mref->ref_rw;
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

#define GET_INDEX(pos)    (((pos) / COPY_CHUNK) % MAX_COPY_PARA)
#define GET_OFFSET(pos)   ((pos) % COPY_CHUNK)

static
void __clear_mref(struct copy_brick *brick, struct mref_object *mref, int queue)
{
	struct copy_input *input;
	input = queue ? brick->inputs[INPUT_B_COPY] : brick->inputs[INPUT_A_COPY];
	GENERIC_INPUT_CALL(input, mref_put, mref);
}

static
void _clear_mref(struct copy_brick *brick, int index, int queue)
{
	struct mref_object *mref = brick->st[index].table[queue];
	if (mref) {
		__clear_mref(brick, mref, queue);
		brick->st[index].table[queue] = NULL;
	}
}

static
void _clear_all_mref(struct copy_brick *brick)
{
	int i;
	for (i = 0; i < MAX_COPY_PARA; i++) {
		brick->st[i].state = COPY_STATE_START;
		_clear_mref(brick, i, 0);
		_clear_mref(brick, i, 1);
	}
}

static
void copy_endio(struct generic_callback *cb)
{
	struct copy_mref_aspect *mref_a;
	struct mref_object *mref;
	struct copy_brick *brick;
	struct copy_state *st;
	int index;
	int queue;
	int error = 0;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);
	brick = mref_a->brick;
	CHECK_PTR(brick, err);

	queue = mref_a->queue;
	index = GET_INDEX(mref->ref_pos);
	st = &brick->st[index];

	MARS_IO("queue = %d index = %d pos = %lld status = %d\n", queue, index, mref->ref_pos, cb->cb_error);
	if (unlikely(queue < 0 || queue >= 2)) {
		MARS_ERR("bad queue %d\n", queue);
		error = -EINVAL;
		goto exit;
	}
	if (unlikely(st->table[queue])) {
		MARS_ERR("table corruption at %d %d (%p => %p)\n", index, queue, st->table[queue], mref);
		error = -EEXIST;
		goto exit;
	}
	if (unlikely(cb->cb_error < 0)) {
		error = cb->cb_error;
		__clear_mref(brick, mref, queue);
		/* This is racy, but does no harm.
		 * Worst case just produces more error output.
		 */
		if (!brick->copy_error_count++) {
			MARS_WRN("IO error %d on index %d, old state = %d\n", cb->cb_error, index, st->state);
		}
	} else {
		if (unlikely(st->table[queue])) {
			MARS_ERR("overwriting index %d, state = %d\n", index, st->state);
			_clear_mref(brick, index, queue);
		}
		st->table[queue] = mref;
	}

exit:
	if (unlikely(error < 0)) {
		st->error = error;
		_clash(brick);
	}
	st->active[queue] = false;
	atomic_dec(&brick->copy_flight);
	brick->trigger = true;
	wake_up_interruptible(&brick->event);
	return;

err:
	MARS_FAT("cannot handle callback\n");
}

static
int _make_mref(struct copy_brick *brick, int index, int queue, void *data, loff_t pos, loff_t end_pos, int rw, int cs_mode)
{
	struct mref_object *mref;
	struct copy_mref_aspect *mref_a;
	struct copy_input *input;
	int offset;
	int len;
	int status = -EAGAIN;

	if (brick->clash || end_pos <= 0)
		goto done;

	mref = copy_alloc_mref(brick);
	status = -ENOMEM;
	if (unlikely(!mref))
		goto done;

	mref_a = copy_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get own apsect\n");
		goto done;
	}

	mref_a->brick = brick;
	mref_a->queue = queue;
	mref->ref_may_write = rw;
	mref->ref_rw = rw;
	mref->ref_data = data;
	mref->ref_pos = pos;
	mref->ref_cs_mode = cs_mode;
	offset = GET_OFFSET(pos);
	len = COPY_CHUNK - offset;
	if (pos + len > end_pos) {
		len = end_pos - pos;
	}
	mref->ref_len = len;
	mref->ref_prio = brick->io_prio;

	SETUP_CALLBACK(mref, copy_endio, mref_a);
	
	input = queue ? brick->inputs[INPUT_B_COPY] : brick->inputs[INPUT_A_COPY];
	status = GENERIC_INPUT_CALL(input, mref_get, mref);
	if (unlikely(status < 0)) {
		MARS_ERR("status = %d\n", status);
		mars_free_mref(mref);
		goto done;
	}
	if (unlikely(mref->ref_len < len)) {
		MARS_DBG("shorten len %d < %d\n", mref->ref_len, len);
	}
	if (queue == 0) {
		brick->st[index].len = mref->ref_len;
	} else if (unlikely(mref->ref_len < brick->st[index].len)) {
		MARS_DBG("shorten len %d < %d\n", mref->ref_len, brick->st[index].len);
		brick->st[index].len = mref->ref_len;
	}

	//MARS_IO("queue = %d index = %d pos = %lld len = %d rw = %d\n", queue, index, mref->ref_pos, mref->ref_len, rw);

	atomic_inc(&brick->copy_flight);
	brick->st[index].active[queue] = true;
	GENERIC_INPUT_CALL(input, mref_io, mref);

done:
	return status;
}

static
void _update_percent(struct copy_brick *brick)
{
	if (brick->copy_last > brick->copy_start + 8 * 1024 * 1024
	   || (long long)jiffies > brick->last_jiffies + 5 * HZ
	   || (brick->copy_last == brick->copy_end && brick->copy_end > 0)) {
		brick->copy_start = brick->copy_last;
		brick->last_jiffies = jiffies;
		brick->power.percent_done = brick->copy_end > 0 ? brick->copy_start * 100 / brick->copy_end : 0;
		MARS_INF("'%s' copied %lld / %lld bytes (%d%%)\n", brick->brick_path, brick->copy_last, brick->copy_end, brick->power.percent_done);
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
	struct mref_object *mref0;
	struct mref_object *mref1;
	struct copy_state *st;
	char state;
	char next_state;
	bool do_restart;
	int cs_mode;
	int progress = 0;
	int status;

	st = &brick->st[index];
	next_state = st->state;

restart:
	state = next_state;
	do_restart = false;

	MARS_IO("index = %d state = %d pos = %lld table[0]=%p table[1]=%p\n", index, state, pos, st->table[0], st->table[1]);

	switch (state) {
	case COPY_STATE_START:
		if (st->table[0] || st->table[1]) {
			MARS_ERR("index %d not startable\n", index);
			progress = -EPROTO;
			goto idle;
		}

		st->active[0] = false;
		st->active[1] = false;
		st->writeout = false;
		st->error = 0;
		if (brick->is_aborting)
			goto idle;

		_clear_mref(brick, index, 1);
		_clear_mref(brick, index, 0);

		cs_mode = 0;
		if (brick->verify_mode)
			cs_mode = 2;

		status = _make_mref(brick, index, 0, NULL, pos, brick->copy_end, READ, cs_mode);
		if (unlikely(status < 0)) {
			MARS_WRN("status = %d\n", status);
			progress = status;
			break;
		}

		next_state = COPY_STATE_READ1;
		if (!brick->verify_mode) {
			break;
		}

		next_state = COPY_STATE_READ2;
		status = _make_mref(brick, index, 1, NULL, pos, brick->copy_end, READ, cs_mode);
		if (unlikely(status < 0)) {
			MARS_WRN("status = %d\n", status);
			progress = status;
			break;
		}
		break;
	case COPY_STATE_READ2:
		mref1 = st->table[1];
		if (!mref1) { // idempotence: wait by unchanged state
			goto idle;
		}
		/* fallthrough */
	case COPY_STATE_READ1:
	case COPY_STATE_READ3:
		mref0 = st->table[0];
		if (!mref0) { // idempotence: wait by unchanged state
			goto idle;
		}
		if (brick->copy_limiter)
			mars_limit_sleep(brick->copy_limiter, mref0->ref_len);
		// on append mode: increase the end pointer dynamically
		if (brick->append_mode > 0 && mref0->ref_total_size && mref0->ref_total_size > brick->copy_end) {
			brick->copy_end = mref0->ref_total_size;
		}
		// do verify (when applicable)
		mref1 = st->table[1];
		if (mref1 && state != COPY_STATE_READ3) { 
			int len = mref0->ref_len;
			bool ok;

			if (len != mref1->ref_len) {
				ok = false;
			} else if (mref0->ref_cs_mode) {
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

		if (mref0->ref_cs_mode > 1) { // re-read, this time with data
			_clear_mref(brick, index, 0);
			next_state = COPY_STATE_START;
			status = _make_mref(brick, index, 0, NULL, pos, brick->copy_end, READ, 0);
			if (unlikely(status < 0)) {
				MARS_WRN("status = %d\n", status);
				progress = status;
				break;
			}
			next_state = COPY_STATE_READ3;
			break;
		}
		next_state = COPY_STATE_WRITE;
		/* fallthrough */
	case COPY_STATE_WRITE:
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
		if (st->prev >= 0 && !brick->st[st->prev].writeout) {
			goto idle;
		}
		mref0 = st->table[0];
		if (unlikely(!mref0 || !mref0->ref_data)) {
			MARS_ERR("src buffer for write does not exist, state %d at index %d\n", state, index);
			progress = -EILSEQ;
			break;
		}
		if (unlikely(brick->is_aborting)) {
			_clear_mref(brick, index, 1);
			_clear_mref(brick, index, 0);
			next_state = COPY_STATE_START;
			break;
		}
		/* start writeout */
		status = _make_mref(brick, index, 1, mref0->ref_data, pos, pos + mref0->ref_len, WRITE, 0);
		if (unlikely(status < 0)) {
			MARS_WRN("status = %d\n", status);
			progress = status;
			break;
		}
		st->writeout = true;
		next_state = COPY_STATE_WRITTEN;
		/* fallthrough */
	case COPY_STATE_WRITTEN:
		mref1 = st->table[1];
		if (!mref1) { // idempotence: wait by unchanged state
			MARS_IO("irrelevant\n");
			goto idle;
		}
		// rechecking means to start over again
		if (brick->recheck_mode && brick->repair_mode) {
			_clear_mref(brick, index, 1);
			_clear_mref(brick, index, 0);
			next_state = COPY_STATE_START;
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
		MARS_ERR("illegal state %d at index %d\n", state, index);
		_clash(brick);
		progress = -EILSEQ;
	}

	do_restart = (state != next_state);

idle:
	MARS_IO("index = %d next_state = %d pos = %lld table[0]=%p table[1]=%p\n", index, next_state, pos, st->table[0], st->table[1]);

	if (unlikely(progress < 0)) {
		st->error = progress;
		MARS_WRN("progress = %d\n", progress);
		progress = 0;
		_clash(brick);
	} else if (do_restart) {
		goto restart;
	} else if (st->state != next_state) {
		progress++;
	}
	// save the resulting state
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
		MARS_DBG("clash\n");
		if (atomic_read(&brick->copy_flight) > 0) {
			/* wait until all pending copy IO has finished
			 */
			_clash(brick);
			MARS_DBG("re-clash\n");
			brick_msleep(100);
			return 0;
		}
		_clear_all_mref(brick);
		memset(brick->st, 0, sizeof(brick->st));
	}

	/* Do at most max iterations in the below loop
	 */
	max = MAX_COPY_PARA - atomic_read(&brick->io_flight) * 2;
	MARS_IO("max = %d\n", max);

	prev = -1;
	progress = 0;
	for (pos = brick->copy_last; pos < brick->copy_end || brick->append_mode > 1; pos = ((pos / COPY_CHUNK) + 1) * COPY_CHUNK) {
		int index = GET_INDEX(pos);
		struct copy_state *st = &brick->st[index];
		if (max-- <= 0) {
			break;
		}
		st->prev = prev;
		prev = index;
		// call the finite state automaton
		if (!(st->active[0] | st->active[1])) {
			progress += _next_state(brick, index, pos);
			limit = pos;
		}
	}

	// check the resulting state: can we advance the copy_last pointer?
	if (likely(progress && !brick->clash)) {
		int count = 0;
		for (pos = brick->copy_last; pos <= limit; pos = ((pos / COPY_CHUNK) + 1) * COPY_CHUNK) {
			int index = GET_INDEX(pos);
			struct copy_state *st = &brick->st[index];
			if (st->state != COPY_STATE_FINISHED) {
				break;
			}
			st->state = COPY_STATE_START;
			if (unlikely(st->error < 0)) {
				if (!brick->copy_error) {
					brick->copy_error = st->error;
					MARS_WRN("IO error = %d\n", st->error);
				}
				if (brick->abort_mode) {
					brick->is_aborting = true;
				}
				break;
			}
			count += st->len;
			// check contiguity
			if (unlikely(GET_OFFSET(pos) + st->len != COPY_CHUNK)) {
				break;
			}
		}
		if (count > 0) {
			brick->copy_last += count;
			MARS_IO("new copy_last += %d => %lld\n", count, brick->copy_last);
			_update_percent(brick);
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
		atomic_read(&brick->copy_flight) <= 0;
}

static int _copy_thread(void *data)
{
	struct copy_brick *brick = data;
	int rounds = 0;

	MARS_DBG("--------------- copy_thread %p starting\n", brick);
	brick->copy_error = 0;
	brick->copy_error_count = 0;
	brick->verify_ok_count = 0;
	brick->verify_error_count = 0;
	mars_power_led_on((void*)brick, true);
	brick->trigger = true;

        while (!_is_done(brick)) {
		loff_t old_start = brick->copy_start;
		loff_t old_end = brick->copy_end;
		int progress = 0;
		if (old_end > 0) {
			progress = _run_copy(brick);
			if (!progress || ++rounds > 1000) {
				rounds = 0;
				schedule(); // yield
			}
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

	MARS_DBG("--------------- copy_thread terminating (%d requests flying, copy_start = %lld copy_end = %lld)\n", atomic_read(&brick->copy_flight), brick->copy_start, brick->copy_end);
	_clear_all_mref(brick);
	mars_power_led_off((void*)brick, true);
	MARS_DBG("--------------- copy_thread done.\n");
	return 0;
}

////////////////// own brick / input / output operations //////////////////

static int copy_get_info(struct copy_output *output, struct mars_info *info)
{
	struct copy_input *input = output->brick->inputs[INPUT_B_IO];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int copy_ref_get(struct copy_output *output, struct mref_object *mref)
{
	struct copy_input *input;
	int index;
	int status;
	index = _determine_input(output->brick, mref);
	input = output->brick->inputs[index];
	status = GENERIC_INPUT_CALL(input, mref_get, mref);
	if (status >= 0) {
		atomic_inc(&output->brick->io_flight);
	}
	return status;
}

static void copy_ref_put(struct copy_output *output, struct mref_object *mref)
{
	struct copy_input *input;
	int index;
	index = _determine_input(output->brick, mref);
	input = output->brick->inputs[index];
	GENERIC_INPUT_CALL(input, mref_put, mref);
	if (atomic_dec_and_test(&output->brick->io_flight)) {
		output->brick->trigger = true;
		wake_up_interruptible(&output->brick->event);
	}
}

static void copy_ref_io(struct copy_output *output, struct mref_object *mref)
{
	struct copy_input *input;
	int index;
	index = _determine_input(output->brick, mref);
	input = output->brick->inputs[index];
	GENERIC_INPUT_CALL(input, mref_io, mref);
}

static int copy_switch(struct copy_brick *brick)
{
	static int version = 0;

	MARS_DBG("power.button = %d\n", brick->power.button);
	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		brick->is_aborting = false;
		if (!brick->thread) {
			brick->copy_last = brick->copy_start;
			brick->thread = brick_thread_create(_copy_thread, brick, "mars_copy%d", version++);
			if (brick->thread) {
				brick->trigger = true;
			} else {
				mars_power_led_off((void*)brick, true);
				MARS_ERR("could not start copy thread\n");
			}
		}
	} else {
		mars_power_led_on((void*)brick, false);
		if (brick->thread) {
			MARS_INF("stopping thread...\n");
			brick_thread_stop(brick->thread);
			wake_up_interruptible(&brick->event);
		}
	}
	_update_percent(brick);
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
		 "copy_end = %lld "
		 "copy_error = %d "
		 "copy_error_count = %d "
		 "verify_ok_count = %d "
		 "verify_error_count = %d "
		 "low_dirty = %d "
		 "is_aborting = %d "
		 "clash = %lu | "
		 "io_flight = %d "
		 "copy_flight = %d\n",
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
		 atomic_read(&brick->io_flight),
		 atomic_read(&brick->copy_flight));

        return res;
}

static
void copy_reset_statistics(struct copy_brick *brick)
{
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

static int copy_brick_construct(struct copy_brick *brick)
{
	init_waitqueue_head(&brick->event);
	sema_init(&brick->mutex, 1);
	return 0;
}

static int copy_brick_destruct(struct copy_brick *brick)
{
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

void __exit exit_mars_copy(void)
{
	MARS_INF("exit_copy()\n");
	copy_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS copy brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_copy);
module_exit(exit_mars_copy);
#endif
