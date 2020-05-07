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


/* Check brick
 * checks various semantic properties, uses watchdog to find lost callbacks.
 */

/* FIXME: this code has been unused for a long time, it is unlikly
 * to work at all.
 */

/* FIXME: improve this a lot!
 * Check really _anything_ in the interface which _could_ go wrong,
 * even by the silliest type of accident!
 */

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING
//#define STAT_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_check.h"

///////////////////////// own helper functions ////////////////////////

#define CHECK_ERR(output,fmt,args...)					\
	do {								\
		struct check_input *input = (output)->brick->inputs[0];	\
		struct generic_output *other = (void*)input->connect;	\
		if (other) {						\
			MARS_ERR("instance %d/%s: " fmt,		\
				 (output)->instance_nr,			\
				 other->type->type_name,		\
				 ##args);				\
		} else {						\
			MARS_ERR("instance %d: " fmt,			\
				 (output)->instance_nr,			\
				 ##args);				\
		}							\
	} while (0)

static void check_endio(struct generic_callback *cb)
{
	struct check_mref_aspect *mref_a;
	struct mref_object *mref;
	struct check_output *output;
	struct check_input *input;
	unsigned long flags;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, fatal);
	_CHECK(&mref_a->cb == cb, fatal);

	mref = mref_a->object;
	CHECK_PTR(mref, fatal);

	output = mref_a->output;
	CHECK_PTR(output, fatal);

	input = output->brick->inputs[0];
	CHECK_PTR(input, fatal);

	if (atomic_dec_and_test(&mref_a->callback_count)) {
		atomic_set(&mref_a->callback_count, 1);
		CHECK_ERR(output, "too many callbacks on %p\n", mref);
	}

#ifdef CHECK_LOCK
	traced_lock(&output->check_lock, flags);

	if (list_empty(&mref_a->mref_head)) {
		CHECK_ERR(output, "list entry missing on %p\n", mref);
	}
	list_del_init(&mref_a->mref_head);

	traced_unlock(&output->check_lock, flags);
#else
	(void)flags;
#endif

	mref_a->last_jiffies = jiffies;

	NEXT_CHECKED_CALLBACK(cb, fatal);

	return;
fatal:
	brick_msleep(60000);
	return;
}

#ifdef CHECK_LOCK
static void dump_mem(void *data, int len)
{
	int i;
	char *tmp;
	char *buf = brick_string_alloc(0);

	if (!buf)
		return;

	for (i = 0, tmp = buf; i < len; i++) {
		unsigned char byte = ((unsigned char*)data)[i];
		if (!(i % 8)) {
			if (tmp != buf) {
				say(-1, "%4d: %s\n", i, buf);
			}
			tmp = buf;
		}
		tmp += scnprintf(tmp, 1024 - i * 3, " %02x", byte);
	}
	if (tmp != buf) {
		say(-1, "%4d: %s\n", i, buf);
	}
	brick_string_free(buf);
}

static int check_watchdog(void *data)
{
	struct check_output *output = data;
	MARS_INF("watchdog has started.\n");
	while (!brick_thread_should_stop()) {
		struct list_head *h;
		unsigned long flags;
		unsigned long now;

		brick_msleep(5000);

		traced_lock(&output->check_lock, flags);

		now = jiffies;
		for (h = output->mref_anchor.next; h != &output->mref_anchor; h = h->next) {
			static int limit = 1;
			const int timeout = 30;
			struct check_mref_aspect *mref_a;
			struct mref_object *mref;
			unsigned long elapsed;

			mref_a = container_of(h, struct check_mref_aspect, mref_head);
			mref = mref_a->object;
			elapsed = now - mref_a->last_jiffies;
			if (elapsed > timeout * HZ && limit-- > 0) {
				struct generic_object_layout *object_layout;
				mref_a->last_jiffies = now + 600 * HZ;
				MARS_INF("================================\n");
				CHECK_ERR(output, "mref %p callback is missing for more than %d seconds.\n", mref, timeout);
				object_layout = mref->object_layout;
				dump_mem(mref, object_layout->size_hint);
				MARS_INF("================================\n");
			}
		}

		traced_unlock(&output->check_lock, flags);
	}
	return 0;
}
#endif

////////////////// own brick / input / output operations //////////////////

static int check_get_info(struct check_output *output, struct mars_info *info)
{
	struct check_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int check_ref_get(struct check_output *output, struct mref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mref_get, mref);
}

static void check_ref_put(struct check_output *output, struct mref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mref_put, mref);
}

static void check_ref_io(struct check_output *output, struct mref_object *mref)
{
	struct check_input *input = output->brick->inputs[0];
	struct check_mref_aspect *mref_a = check_mref_get_aspect(output->brick, mref);
	unsigned long flags;

	CHECK_PTR(mref_a, fatal);

	if (atomic_dec_and_test(&mref_a->call_count)) {
		atomic_set(&mref_a->call_count, 1);
		CHECK_ERR(output, "multiple parallel calls on %p\n", mref);
	}
	atomic_set(&mref_a->callback_count, 2);

#ifdef CHECK_LOCK
	traced_lock(&output->check_lock, flags);

	if (!list_empty(&mref_a->mref_head)) {
		CHECK_ERR(output, "list head not empty on %p\n", mref);
		list_del(&mref_a->mref_head);
	}
	list_add_tail(&mref_a->mref_head, &output->mref_anchor);

	traced_unlock(&output->check_lock, flags);
#else
	(void)flags;
#endif

	mref_a->last_jiffies = jiffies;
	if (!mref_a->installed) {
		mref_a->installed = true;
		mref_a->output = output;
		INSERT_CALLBACK(mref, &mref_a->cb, check_endio, mref_a);
	}

	GENERIC_INPUT_CALL(input, mref_io, mref);

	atomic_inc(&mref_a->call_count);
fatal: ;
}

//////////////// object / aspect constructors / destructors ///////////////

static int check_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct check_mref_aspect *ini = (void*)_ini;
#ifdef CHECK_LOCK
	INIT_LIST_HEAD(&ini->mref_head);
#endif
	ini->last_jiffies = jiffies;
	atomic_set(&ini->call_count, 2);
	atomic_set(&ini->callback_count, 1);
	ini->installed = false;
	return 0;
}

static void check_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct check_mref_aspect *ini = (void*)_ini;
	(void)ini;
#ifdef CHECK_LOCK
	if (!list_empty(&ini->mref_head)) {
		struct check_output *output = ini->output;
		if (output) {
			CHECK_ERR(output, "list head not empty on %p\n", ini->object);
			INIT_LIST_HEAD(&ini->mref_head);
		} else {
			CHECK_HEAD_EMPTY(&ini->mref_head);
		}
	}
#endif
}

MARS_MAKE_STATICS(check);

////////////////////// brick constructors / destructors ////////////////////

static int check_brick_construct(struct check_brick *brick)
{
	return 0;
}

static int check_output_construct(struct check_output *output)
{
	static int count = 0;
#ifdef CHECK_LOCK

	spin_lock_init(&output->check_lock);
	INIT_LIST_HEAD(&output->mref_anchor);
	output->watchdog = brick_thread_create(check_watchdog, output, "check_watchdog%d", output->instance_nr);
#endif
	output->instance_nr = ++count;
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct check_brick_ops check_brick_ops = {
};

static struct check_output_ops check_output_ops = {
	.mars_get_info = check_get_info,
	.mref_get = check_ref_get,
	.mref_put = check_ref_put,
	.mref_io = check_ref_io,
};

const struct check_input_type check_input_type = {
	.type_name = "check_input",
	.input_size = sizeof(struct check_input),
};

static const struct check_input_type *check_input_types[] = {
	&check_input_type,
};

const struct check_output_type check_output_type = {
	.type_name = "check_output",
	.output_size = sizeof(struct check_output),
	.master_ops = &check_output_ops,
	.output_construct = &check_output_construct,
};

static const struct check_output_type *check_output_types[] = {
	&check_output_type,
};

const struct check_brick_type check_brick_type = {
	.type_name = "check_brick",
	.brick_size = sizeof(struct check_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &check_brick_ops,
	.aspect_types = check_aspect_types,
	.default_input_types = check_input_types,
	.default_output_types = check_output_types,
	.brick_construct = &check_brick_construct,
};
EXPORT_SYMBOL_GPL(check_brick_type);

////////////////// module init stuff /////////////////////////

int __init init_mars_check(void)
{
	MARS_INF("init_check()\n");
	return check_register_brick_type();
}

void exit_mars_check(void)
{
	MARS_INF("exit_check()\n");
	check_unregister_brick_type();
}
