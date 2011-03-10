// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Copy brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kthread.h>

#include "mars.h"

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
 * When optimize_mode is on, reads can utilize the already copied
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

	if (!brick->optimize_mode || brick->low_dirty)
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

#define MAKE_INDEX(pos) (((pos) / PAGE_SIZE) % MAX_COPY_PARA)

static
void copy_endio(struct generic_callback *cb)
{
	struct copy_mref_aspect *mref_a;
	struct mref_object *mref;
	struct copy_brick *brick;
	int index;
	int queue;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);
	brick = mref_a->brick;
	CHECK_PTR(brick, err);

	queue = mref_a->queue;
	index = MAKE_INDEX(mref->ref_pos);
	MARS_IO("queue = %d index = %d pos = %lld status = %d\n", queue, index, mref->ref_pos, cb->cb_error);
	if (unlikely(queue < 0 || queue >= 2)) {
		MARS_ERR("bad queue %d\n", queue);
		_clash(brick);
		goto exit;
	}
	if (unlikely(brick->table[index][queue])) {
		MARS_ERR("table corruption at %d %d (%p => %p)\n", index, queue, brick->table[index], mref);
		_clash(brick);
		brick->state[index] = -EINVAL;
		goto exit;
	}
	if (unlikely(cb->cb_error < 0)) {
		MARS_ERR("IO error %d on index %d, old state =%d\n", cb->cb_error, index, brick->state[index]);
		brick->state[index] = cb->cb_error;
	} else if (likely(brick->state[index] > 0)) {
		brick->table[index][queue] = mref;
	}

exit:
	atomic_dec(&brick->copy_flight);
	brick->trigger = true;
	wake_up_interruptible(&brick->event);
	return;

err:
	MARS_FAT("cannot handle callback\n");
}

static
int _make_mref(struct copy_brick *brick, int index, int queue, void *data, loff_t pos, int rw)
{
	struct mref_object *mref;
	struct copy_mref_aspect *mref_a;
	struct copy_input *input;
	loff_t tmp_pos;
	int len;
	int status = -1;

	tmp_pos = brick->copy_end;
	if (brick->clash || !tmp_pos)
		goto done;

	mref = copy_alloc_mref(brick->outputs[0], &brick->mref_object_layout);
	status = -ENOMEM;
	if (unlikely(!mref))
		goto done;

	mref_a = copy_mref_get_aspect(brick->outputs[0], mref);
	if (unlikely(!mref_a)) {
		kfree(mref);
		goto done;
	}

	mref_a->brick = brick;
	mref_a->queue = queue;
	mref->ref_may_write = rw;
	mref->ref_rw = rw;
	mref->ref_data = data;
	mref->ref_pos = pos;
	len = PAGE_SIZE - (pos & (PAGE_SIZE-1));
	if (pos + len > tmp_pos) {
		len = tmp_pos - pos;
	}
	mref->ref_len = len;
	mref->ref_prio = MARS_PRIO_LOW;
	mref->_ref_cb.cb_private = mref_a;
	mref->_ref_cb.cb_fn = copy_endio;
	mref->ref_cb = &mref->_ref_cb;
	
	input = queue ? brick->inputs[INPUT_B_COPY] : brick->inputs[INPUT_A_COPY];
	status = GENERIC_INPUT_CALL(input, mref_get, mref);
	if (unlikely(status < 0)) {
		MARS_ERR("status = %d\n", status);
		mars_free_mref(mref);
		goto done;
	}

	MARS_IO("queue = %d index = %d pos = %lld len = %d rw = %d\n", queue, index, mref->ref_pos, mref->ref_len, rw);

	atomic_inc(&brick->copy_flight);
	GENERIC_INPUT_CALL(input, mref_io, mref);

done:
	return status;
}

static
void _clear_mref(struct copy_brick *brick, int index, int queue)
{
	struct mref_object *mref = brick->table[index][queue];
	if (mref) {
		struct copy_input *input;
		input = queue ? brick->inputs[INPUT_B_COPY] : brick->inputs[INPUT_A_COPY];
		GENERIC_INPUT_CALL(input, mref_put, mref);
		brick->table[index][queue] = NULL;
	}
}

static
void _update_percent(struct copy_brick *brick)
{
	if (brick->copy_start > brick->copy_last + 1024 * 1024 * 1024
	   || (long long)jiffies > brick->last_jiffies + 5 * HZ
	   || brick->copy_start == brick->copy_end) {
		brick->copy_last = brick->copy_start;
		brick->last_jiffies = jiffies;
		brick->power.percent_done = brick->copy_end > 0 ? brick->copy_start * 100 / brick->copy_end : 0;
		MARS_INF("'%s' copied %lld / %lld bytes (%lld%%)\n", brick->brick_name, brick->copy_last, brick->copy_end, brick->copy_end? brick->copy_last * 100 / brick->copy_end : 100);
	}
}

static
int _next_state(struct copy_brick *brick, loff_t pos)
{
	struct mref_object *mref1;
	struct mref_object *mref2;
	int index = MAKE_INDEX(pos);
	char state;
	char next_state;
	int i;
	int status;

	state = brick->state[index];
	next_state = -1;
	mref2 = NULL;
	status = 0;

	MARS_IO("index = %d state = %d pos = %lld\n", index, state, pos);

	switch (state) {
	case COPY_STATE_START:
		if (brick->table[index][0] || brick->table[index][1]) {
			MARS_ERR("index %d not startable\n", index);
			status = -EPROTO;
			goto done;
		}
		i = 0;
		next_state = COPY_STATE_READ1;
		if (brick->verify_mode) {
			i = 1;
			next_state = COPY_STATE_READ2;
		}
		for ( ; i >= 0; i--) {
			status = _make_mref(brick, index, i, NULL, pos, 0);
			if (status < 0) {
				break;
			}
		}
		break;
	case COPY_STATE_READ2:
		mref2 = brick->table[index][1];
		if (!mref2) {
			goto done;
		}
		/* fallthrough */
	case COPY_STATE_READ1:
		mref1 = brick->table[index][0];
		if (!mref1) {
			goto done;
		}
		if (mref2) {
			int len = mref1->ref_len;
			if (len == mref2->ref_len &&
			   !memcmp(mref1->ref_data, mref2->ref_data, len)) {
				/* skip start of writing, goto final treatment of writeout */
				next_state = COPY_STATE_WRITE;
				brick->state[index] = next_state;
				goto COPY_STATE_WRITE;
			}
			_clear_mref(brick, index, 1);
		}
		/* start writeout */
		next_state = COPY_STATE_WRITE;
		status = _make_mref(brick, index, 1, mref1->ref_data, pos, 1);
		
		break;
	case COPY_STATE_WRITE:
	COPY_STATE_WRITE:
		mref2 = brick->table[index][1];
		if (!mref2 || brick->copy_start != pos) {
			MARS_IO("irrelevant\n");
			goto done;
		}
		if (!brick->clash) {
			brick->copy_start += mref2->ref_len;
			MARS_IO("new copy_start = %lld\n", brick->copy_start);
			_update_percent(brick);
		}
		next_state = COPY_STATE_CLEANUP;
		/* fallthrough */
	case COPY_STATE_CLEANUP:
		_clear_mref(brick, index, 0);
		_clear_mref(brick, index, 1);
		next_state = COPY_STATE_START;
		break;
	default:
		MARS_ERR("illegal state %d at index %d\n", state, index);
		_clash(brick);
		status = -EILSEQ;
	}

	brick->state[index] = next_state;
	if (status < 0) {
		brick->state[index] = -1;
		MARS_ERR("status = %d\n", status);
		_clash(brick);
	}
	
done:
	return status;
}

static
void _run_copy(struct copy_brick *brick)
{
	int max;
	loff_t pos;
	int i;
	int status;

	if (_clear_clash(brick)) {
		MARS_DBG("clash\n");
		if (atomic_read(&brick->copy_flight)) {
			/* wait until all pending copy IO has finished
			 */
			_clash(brick);
			MARS_DBG("re-clash\n");
			msleep(50);
			return;
		}
		for (i = 0; i < MAX_COPY_PARA; i++) {
			brick->table[i][0] = NULL;
			brick->table[i][1] = NULL;
			brick->state[i] = COPY_STATE_START;
		}
	}

	max = MAX_COPY_PARA - atomic_read(&brick->io_flight) * 2;
	MARS_IO("max = %d\n", max);

	for (pos = brick->copy_start; pos < brick->copy_end; pos = ((pos / PAGE_SIZE) + 1) * PAGE_SIZE) {
		//MARS_IO("pos = %lld\n", pos);
		if (brick->clash || max-- <= 0)
			break;
		status = _next_state(brick, pos);
	}
}

static int _copy_thread(void *data)
{
	struct copy_brick *brick = data;

	MARS_DBG("--------------- copy_thread %p starting\n", brick);
	mars_power_led_on((void*)brick, true);
	brick->trigger = true;

        while (!kthread_should_stop()) {
		loff_t old_start = brick->copy_start;
		loff_t old_end = brick->copy_end;
		if (old_end > 0)
			_run_copy(brick);

		wait_event_interruptible_timeout(brick->event,
						 brick->trigger || brick->copy_start != old_start || brick->copy_end != old_end || kthread_should_stop(),

						 20 * HZ);
		brick->trigger = false;
	}

	MARS_DBG("--------------- copy_thread terminating\n");
	wait_event_interruptible_timeout(brick->event, !atomic_read(&brick->copy_flight), 300 * HZ);
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
		if (!brick->thread) {
			brick->copy_last = brick->copy_start;
			brick->thread = kthread_create(_copy_thread, brick, "mars_copy%d", version++);
			if (brick->thread) {
				get_task_struct(brick->thread);
				brick->trigger = true;
				wake_up_process(brick->thread);
			} else {
				mars_power_led_off((void*)brick, true);
				MARS_ERR("could not start copy thread\n");
			}
		}
	} else {
		mars_power_led_on((void*)brick, false);
		if (brick->thread) {
			kthread_stop_nowait(brick->thread);
			put_task_struct(brick->thread);
			brick->thread = NULL;
			wake_up_interruptible(&brick->event);
		}
	}
	_update_percent(brick);
	return 0;
}


//////////////// object / aspect constructors / destructors ///////////////

static int copy_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct copy_mref_aspect *ini = (void*)_ini;
	(void)ini;
	return 0;
}

static void copy_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
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
};

static struct copy_output_ops copy_output_ops = {
	.make_object_layout = copy_make_object_layout,
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
	.aspect_types = copy_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
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
	.default_input_types = copy_input_types,
	.default_output_types = copy_output_types,
	.brick_construct = &copy_brick_construct,
	.brick_destruct = &copy_brick_destruct,
};
EXPORT_SYMBOL_GPL(copy_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_copy(void)
{
	MARS_INF("init_copy()\n");
	return copy_register_brick_type();
}

static void __exit exit_copy(void)
{
	MARS_INF("exit_copy()\n");
	copy_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS copy brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_copy);
module_exit(exit_copy);
