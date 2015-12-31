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


// Server brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "brick.h"
#include "mars.h"
#include "mars_bio.h"
//      remove_this
#ifndef __USE_COMPAT
#include "mars_aio.h"
#endif
//      end_remove_this
#include "mars_sio.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_server.h"

static struct mars_socket server_socket[NR_SOCKETS] = {};
static struct task_struct *server_threads[NR_SOCKETS] = {};

///////////////////////// own helper functions ////////////////////////


int cb_thread(void *data)
{
	struct server_brick *brick = data;
	struct mars_socket *sock = &brick->handler_socket;
	bool aborted = false;
	bool ok = mars_get_socket(sock);
	int status = -EINVAL;

	MARS_DBG("--------------- cb_thread starting on socket #%d, ok = %d\n", sock->s_debug_nr, ok);
	if (!ok)
		goto done;

	brick->cb_running = true;
	wake_up_interruptible(&brick->startup_event);

        while (!brick_thread_should_stop() || !list_empty(&brick->cb_read_list) || !list_empty(&brick->cb_write_list) || atomic_read(&brick->in_flight) > 0) {
		struct server_mref_aspect *mref_a;
		struct mref_object *mref;
		struct list_head *tmp;
		unsigned long flags;

		wait_event_interruptible_timeout(
			brick->cb_event,
			!list_empty(&brick->cb_read_list) ||
			!list_empty(&brick->cb_write_list),
			1 * HZ);

		spin_lock_irqsave(&brick->cb_lock, flags);
		tmp = brick->cb_write_list.next;
		if (tmp == &brick->cb_write_list) {
			tmp = brick->cb_read_list.next;
			if (tmp == &brick->cb_read_list) {
				spin_unlock_irqrestore(&brick->cb_lock, flags);
				brick_msleep(1000 / HZ);
				continue;
			}
		}
		list_del_init(tmp);
		spin_unlock_irqrestore(&brick->cb_lock, flags);

		mref_a = container_of(tmp, struct server_mref_aspect, cb_head);
		mref = mref_a->object;
		status = -EINVAL;
		CHECK_PTR(mref, err);

		status = 0;
		/* Report a remote error when consistency cannot be guaranteed,
		 * e.g. emergency mode during sync.
		 */
		if (brick->conn_brick && brick->conn_brick->mode_ptr && *brick->conn_brick->mode_ptr < 0
		    && mref->object_cb)
			mref->object_cb->cb_error = *brick->conn_brick->mode_ptr;
		if (!aborted) {
			down(&brick->socket_sem);
			status = mars_send_cb(sock, mref);
			up(&brick->socket_sem);
		}

	err:
		if (unlikely(status < 0) && !aborted) {
			aborted = true;
			MARS_WRN("cannot send response, status = %d\n", status);
			/* Just shutdown the socket and forget all pending
			 * requests.
			 * The _client_ is responsible for resending
			 * any lost operations.
			 */
			mars_shutdown_socket(sock);
		}

		if (mref_a->data) {
			brick_block_free(mref_a->data, mref_a->len);
			mref->ref_data = NULL;
		}
		if (mref_a->do_put) {
			GENERIC_INPUT_CALL(brick->inputs[0], mref_put, mref);
			atomic_dec(&brick->in_flight);
		} else {
			_mref_free(mref);
		}
	}

	mars_shutdown_socket(sock);
	mars_put_socket(sock);

done:
	MARS_DBG("---------- cb_thread terminating, status = %d\n", status);
	wake_up_interruptible(&brick->startup_event);
	return status;
}

static
void server_endio(struct generic_callback *cb)
{
	struct server_mref_aspect *mref_a;
	struct mref_object *mref;
	struct server_brick *brick;
	int rw;
	unsigned long flags;

	mref_a = cb->cb_private;
	CHECK_PTR(mref_a, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);
	LAST_CALLBACK(cb);
	if (unlikely(cb != &mref->_object_cb)) {
		MARS_ERR("bad cb pointer %p != %p\n", cb, &mref->_object_cb);
	}

	brick = mref_a->brick;
	if (unlikely(!brick)) {
		MARS_WRN("late IO callback -- cannot do anything\n");
		return;
	}

	rw = mref->ref_rw;

	spin_lock_irqsave(&brick->cb_lock, flags);
	if (rw) {
		list_add_tail(&mref_a->cb_head, &brick->cb_write_list);
	} else {
		list_add_tail(&mref_a->cb_head, &brick->cb_read_list);
	}
	spin_unlock_irqrestore(&brick->cb_lock, flags);

	wake_up_interruptible(&brick->cb_event);
	return;
err:
	MARS_FAT("cannot handle callback - giving up\n");
}

int server_io(struct server_brick *brick, struct mars_socket *sock, struct mars_cmd *cmd)
{
	struct mref_object *mref;
	struct server_mref_aspect *mref_a;
	int amount;
	int status = -ENOTRECOVERABLE;

	if (!brick->cb_running || !brick->handler_running || !mars_socket_is_alive(sock))
		goto done;

	mref = server_alloc_mref(brick);
	status = -ENOMEM;
	mref_a = server_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a)) {
		_mref_free(mref);
		goto done;
	}

	status = mars_recv_mref(sock, mref, cmd);
	if (status < 0) {
		_mref_free(mref);
		goto done;
	}
	
	mref_a->brick = brick;
	mref_a->data = mref->ref_data;
	mref_a->len = mref->ref_len;
	SETUP_CALLBACK(mref, server_endio, mref_a);

	amount = 0;
	if (!mref->ref_cs_mode < 2)
		amount = (mref->ref_len - 1) / 1024 + 1;
	mars_limit_sleep(&server_limiter, amount);
	
	status = GENERIC_INPUT_CALL(brick->inputs[0], mref_get, mref);
	if (unlikely(status < 0)) {
		MARS_WRN("mref_get execution error = %d\n", status);
		SIMPLE_CALLBACK(mref, status);
		status = 0; // continue serving requests
		goto done;
	}
	mref_a->do_put = true;
	atomic_inc(&brick->in_flight);
	GENERIC_INPUT_CALL(brick->inputs[0], mref_io, mref);

done:
	return status;
}

////////////////// own brick / input / output operations //////////////////

static int server_get_info(struct server_output *output, struct mars_info *info)
{
	struct server_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int server_ref_get(struct server_output *output, struct mref_object *mref)
{
	struct server_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mref_get, mref);
}

static void server_ref_put(struct server_output *output, struct mref_object *mref)
{
	struct server_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mref_put, mref);
}

static void server_ref_io(struct server_output *output, struct mref_object *mref)
{
	struct server_input *input = output->brick->inputs[0];
	GENERIC_INPUT_CALL(input, mref_io, mref);
}

int server_switch(struct server_brick *brick)
{
	struct mars_socket *sock = &brick->handler_socket;
	int status = 0;

	if (brick->power.button) {
		static int version = 0;
		bool ok;

		if (brick->power.led_on)
			goto done;

		ok = mars_get_socket(sock);
		if (unlikely(!ok)) {
			status = -ENOENT;
			goto err;
		}

		mars_power_led_off((void *)brick, false);

		brick->version = version++;
		brick->handler_thread = brick_thread_create(handler_thread, brick, "mars_handler%d", brick->version);
		if (unlikely(!brick->handler_thread)) {
			MARS_ERR("cannot create handler thread\n");
			status = -ENOENT;
			goto err;
		}

		mars_power_led_on((void *)brick, true);
	} else if (!brick->power.led_off) {
		struct task_struct *thread;
		mars_power_led_on((void *)brick, false);

		mars_shutdown_socket(sock);

		thread = brick->handler_thread;
		if (thread) {
			brick->handler_thread = NULL;
			brick->handler_running = false;
			MARS_DBG("#%d stopping handler thread....\n", sock->s_debug_nr);
			brick_thread_stop(thread);
		}

		mars_put_socket(sock);
		MARS_DBG("#%d socket s_count = %d\n", sock->s_debug_nr, atomic_read(&sock->s_count));

		mars_power_led_off((void *)brick, true);
	}
 err:
	if (unlikely(status < 0)) {
		mars_power_led_off((void *)brick, true);
		mars_shutdown_socket(sock);
		mars_put_socket(sock);
	}
done:
	return status;
}

//////////////// informational / statistics ///////////////

static
char *server_statistics(struct server_brick *brick, int verbose)
{
	char *res = brick_string_alloc(1024);
	
	snprintf(res, 1024,
		 "cb_running = %d "
		 "handler_running = %d "
		 "in_flight = %d\n",
		 brick->cb_running,
		 brick->handler_running,
		 atomic_read(&brick->in_flight));

        return res;
}

static
void server_reset_statistics(struct server_brick *brick)
{
}

//////////////// object / aspect constructors / destructors ///////////////

static int server_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct server_mref_aspect *ini = (void *)_ini;
	INIT_LIST_HEAD(&ini->cb_head);
	return 0;
}

static void server_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct server_mref_aspect *ini = (void *)_ini;
	CHECK_HEAD_EMPTY(&ini->cb_head);
}

MARS_MAKE_STATICS(server);

////////////////////// brick constructors / destructors ////////////////////

static int server_brick_construct(struct server_brick *brick)
{
	init_waitqueue_head(&brick->startup_event);
	init_waitqueue_head(&brick->cb_event);
	sema_init(&brick->socket_sem, 1);
	spin_lock_init(&brick->cb_lock);
	INIT_LIST_HEAD(&brick->cb_read_list);
	INIT_LIST_HEAD(&brick->cb_write_list);
	return 0;
}

static int server_brick_destruct(struct server_brick *brick)
{
	CHECK_HEAD_EMPTY(&brick->cb_read_list);
	CHECK_HEAD_EMPTY(&brick->cb_write_list);
	return 0;
}

static int server_output_construct(struct server_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct server_brick_ops server_brick_ops = {
	.brick_switch = server_switch,
        .brick_statistics = server_statistics,
        .reset_statistics = server_reset_statistics,
};

static struct server_output_ops server_output_ops = {
	.mars_get_info = server_get_info,
	.mref_get = server_ref_get,
	.mref_put = server_ref_put,
	.mref_io = server_ref_io,
};

const struct server_input_type server_input_type = {
	.type_name = "server_input",
	.input_size = sizeof(struct server_input),
};

static const struct server_input_type *server_input_types[] = {
	&server_input_type,
};

const struct server_output_type server_output_type = {
	.type_name = "server_output",
	.output_size = sizeof(struct server_output),
	.master_ops = &server_output_ops,
	.output_construct = &server_output_construct,
};

static const struct server_output_type *server_output_types[] = {
	&server_output_type,
};

const struct server_brick_type server_brick_type = {
	.type_name = "server_brick",
	.brick_size = sizeof(struct server_brick),
	.max_inputs = 1,
	.max_outputs = 0,
	.master_ops = &server_brick_ops,
	.aspect_types = server_aspect_types,
	.default_input_types = server_input_types,
	.default_output_types = server_output_types,
	.brick_construct = &server_brick_construct,
	.brick_destruct = &server_brick_destruct,
};

///////////////////////////////////////////////////////////////////////

// strategy layer

int server_show_statist = 0;

////////////////// module init stuff /////////////////////////

struct mars_limiter server_limiter = {
	.lim_max_rate = 0,
};

void exit_mars_server(void)
{
	int i;

	MARS_INF("exit_server()\n");
	server_unregister_brick_type();

	for (i = 0; i < NR_SOCKETS; i++) {
		if (server_threads[i]) {
			MARS_INF("stopping server thread %d...\n", i);
			brick_thread_stop(server_threads[i]);
		}
		MARS_INF("closing server socket %d...\n", i);
		mars_put_socket(&server_socket[i]);
	}
}

int __init init_mars_server(void)
{
	int i;

	MARS_INF("init_server()\n");

	for (i = 0; i < NR_SOCKETS; i++) {
		struct sockaddr_storage sockaddr = {};
		char tmp[64];
		int status;

		if (mars_translate_hostname)
			snprintf(tmp, sizeof(tmp), "%s:%d", my_id(), mars_net_default_port + i);
		else
			snprintf(tmp, sizeof(tmp), ":%d", mars_net_default_port + i);

		status = mars_create_sockaddr(&sockaddr, tmp);
		if (unlikely(status < 0)) {
			exit_mars_server();
			return status;
		}

		status = mars_create_socket(&server_socket[i], &sockaddr, NULL);
		if (unlikely(status < 0)) {
			MARS_ERR("could not create server socket %d, status = %d\n", i, status);
			exit_mars_server();
			return status;
		}

		server_threads[i] = brick_thread_create(server_thread, &server_socket[i], "mars_server_%d", i);
		if (unlikely(!server_threads[i] || IS_ERR(server_threads[i]))) {
			MARS_ERR("could not create server thread %d\n", i);
			exit_mars_server();
			return -ENOENT;
		}
	}

	return server_register_brick_type();
}
