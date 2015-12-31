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

/*  Server brick (just for demonstration) */

//#define BRICK_DEBUGGING
//#define XIO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "brick.h"
#include "xio.h"
#include "xio_bio.h"
/*	remove_this */
#ifndef __USE_COMPAT
#include "unused/xio_aio_user.h"
#endif
/*	end_remove_this */
#include "xio_sio.h"

/************************ own type definitions ***********************/

#include "xio_server.h"

static struct xio_socket server_socket[NR_SERVER_SOCKETS];
static struct task_struct *server_threads[NR_SERVER_SOCKETS];

/************************ own helper functions ***********************/

int cb_thread(void *data)
{
	struct server_brick *brick = data;
	struct xio_socket *sock = &brick->handler_socket;
	bool aborted = false;
	bool ok = xio_get_socket(sock);
	int status = -EINVAL;

	XIO_DBG("--------------- cb_thread starting on socket #%d, ok = %d\n", sock->s_debug_nr, ok);
	if (!ok)
		goto done;

	brick->cb_running = true;
	wake_up_interruptible(&brick->startup_event);

	while (!brick_thread_should_stop() || !list_empty(&brick->cb_read_list) || !list_empty(&brick->cb_write_list) || atomic_read(&brick->in_flight) > 0) {
		struct server_aio_aspect *aio_a;
		struct aio_object *aio;
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

		aio_a = container_of(tmp, struct server_aio_aspect, cb_head);
		aio = aio_a->object;
		status = -EINVAL;
		CHECK_PTR(aio, err);

		status = 0;
		/* Report a remote error when consistency cannot be guaranteed,
		 * e.g. emergency mode during sync.
		 */
		if (brick->conn_brick && brick->conn_brick->mode_ptr && *brick->conn_brick->mode_ptr < 0
		    && aio->object_cb)
			aio->object_cb->cb_error = *brick->conn_brick->mode_ptr;
		if (!aborted) {
			down(&brick->socket_sem);
			status = xio_send_cb(sock, aio);
			up(&brick->socket_sem);
		}

err:
		if (unlikely(status < 0) && !aborted) {
			aborted = true;
			XIO_WRN("cannot send response, status = %d\n", status);
			/* Just shutdown the socket and forget all pending
			 * requests.
			 * The _client_ is responsible for resending
			 * any lost operations.
			 */
			xio_shutdown_socket(sock);
		}

		if (aio_a->data) {
			brick_block_free(aio_a->data, aio_a->len);
			aio->io_data = NULL;
		}
		if (aio_a->do_put) {
			GENERIC_INPUT_CALL(brick->inputs[0], aio_put, aio);
			atomic_dec(&brick->in_flight);
		} else {
			obj_free(aio);
		}
	}

	xio_shutdown_socket(sock);
	xio_put_socket(sock);

done:
	XIO_DBG("---------- cb_thread terminating, status = %d\n", status);
	wake_up_interruptible(&brick->startup_event);
	return status;
}

static
void server_endio(struct generic_callback *cb)
{
	struct server_aio_aspect *aio_a;
	struct aio_object *aio;
	struct server_brick *brick;
	int rw;
	unsigned long flags;

	aio_a = cb->cb_private;
	CHECK_PTR(aio_a, err);
	aio = aio_a->object;
	CHECK_PTR(aio, err);
	LAST_CALLBACK(cb);
	if (unlikely(cb != &aio->_object_cb))
		XIO_ERR("bad cb pointer %p != %p\n", cb, &aio->_object_cb);

	brick = aio_a->brick;
	if (unlikely(!brick)) {
		XIO_WRN("late IO callback -- cannot do anything\n");
		goto out_return;
	}

	rw = aio->io_rw;

	spin_lock_irqsave(&brick->cb_lock, flags);
	if (rw)
		list_add_tail(&aio_a->cb_head, &brick->cb_write_list);
	else
		list_add_tail(&aio_a->cb_head, &brick->cb_read_list);
	spin_unlock_irqrestore(&brick->cb_lock, flags);

	wake_up_interruptible(&brick->cb_event);
	goto out_return;
err:
	XIO_FAT("cannot handle callback - giving up\n");
out_return:;
}

int server_io(struct server_brick *brick, struct xio_socket *sock, struct xio_cmd *cmd)
{
	struct aio_object *aio;
	struct server_aio_aspect *aio_a;
	int amount;
	int status = -ENOTRECOVERABLE;

	if (!brick->cb_running || !brick->handler_running || !xio_socket_is_alive(sock))
		goto done;

	aio = server_alloc_aio(brick);
	status = -ENOMEM;
	aio_a = server_aio_get_aspect(brick, aio);
	if (unlikely(!aio_a)) {
		obj_free(aio);
		goto done;
	}

	status = xio_recv_aio(sock, aio, cmd);
	if (status < 0) {
		obj_free(aio);
		goto done;
	}

	aio_a->brick = brick;
	aio_a->data = aio->io_data;
	aio_a->len = aio->io_len;
	SETUP_CALLBACK(aio, server_endio, aio_a);

	amount = 0;
	if (!aio->io_cs_mode < 2)
		amount = (aio->io_len - 1) / 1024 + 1;
	rate_limit_sleep(&server_limiter, amount);

	status = GENERIC_INPUT_CALL(brick->inputs[0], aio_get, aio);
	if (unlikely(status < 0)) {
		XIO_WRN("aio_get execution error = %d\n", status);
		SIMPLE_CALLBACK(aio, status);
		status = 0; /*	continue serving requests */
		goto done;
	}
	aio_a->do_put = true;
	atomic_inc(&brick->in_flight);
	GENERIC_INPUT_CALL(brick->inputs[0], aio_io, aio);

done:
	return status;
}

/***************** own brick * input * output operations *****************/

static int server_get_info(struct server_output *output, struct xio_info *info)
{
	struct server_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, xio_get_info, info);
}

static int server_io_get(struct server_output *output, struct aio_object *aio)
{
	struct server_input *input = output->brick->inputs[0];

	return GENERIC_INPUT_CALL(input, aio_get, aio);
}

static void server_io_put(struct server_output *output, struct aio_object *aio)
{
	struct server_input *input = output->brick->inputs[0];

	GENERIC_INPUT_CALL(input, aio_put, aio);
}

static void server_io_io(struct server_output *output, struct aio_object *aio)
{
	struct server_input *input = output->brick->inputs[0];

	GENERIC_INPUT_CALL(input, aio_io, aio);
}

int server_switch(struct server_brick *brick)
{
	struct xio_socket *sock = &brick->handler_socket;
	int status = 0;

	if (brick->power.button) {
		static int version;
		bool ok;

		if (brick->power.on_led)
			goto done;

		ok = xio_get_socket(sock);
		if (unlikely(!ok)) {
			status = -ENOENT;
			goto err;
		}

		xio_set_power_off_led((void *)brick, false);

		brick->version = version++;
		brick->handler_thread = brick_thread_create(handler_thread, brick, "xio_handler%d", brick->version);
		if (unlikely(!brick->handler_thread)) {
			XIO_ERR("cannot create handler thread\n");
			status = -ENOENT;
			goto err;
		}

		xio_set_power_on_led((void *)brick, true);
	} else if (!brick->power.off_led) {
		struct task_struct *thread;

		xio_set_power_on_led((void *)brick, false);

		xio_shutdown_socket(sock);

		thread = brick->handler_thread;
		if (thread) {
			brick->handler_thread = NULL;
			brick->handler_running = false;
			XIO_DBG("#%d stopping handler thread....\n", sock->s_debug_nr);
			brick_thread_stop(thread);
		}

		xio_put_socket(sock);
		XIO_DBG("#%d socket s_count = %d\n", sock->s_debug_nr, atomic_read(&sock->s_count));

		xio_set_power_off_led((void *)brick, true);
	}
err:
	if (unlikely(status < 0)) {
		xio_set_power_off_led((void *)brick, true);
		xio_shutdown_socket(sock);
		xio_put_socket(sock);
	}
done:
	return status;
}

/*************** informational * statistics **************/

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

/*************** object * aspect constructors * destructors **************/

static int server_aio_aspect_init_fn(struct generic_aspect *_ini)
{
	struct server_aio_aspect *ini = (void *)_ini;

	INIT_LIST_HEAD(&ini->cb_head);
	return 0;
}

static void server_aio_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct server_aio_aspect *ini = (void *)_ini;

	CHECK_HEAD_EMPTY(&ini->cb_head);
}

XIO_MAKE_STATICS(server);

/********************* brick constructors * destructors *******************/

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

/************************ static structs ***********************/

static struct server_brick_ops server_brick_ops = {
	.brick_switch = server_switch,
	.brick_statistics = server_statistics,
	.reset_statistics = server_reset_statistics,
};

static struct server_output_ops server_output_ops = {
	.xio_get_info = server_get_info,
	.aio_get = server_io_get,
	.aio_put = server_io_put,
	.aio_io = server_io_io,
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

/*********************************************************************/

/*  strategy layer */

int server_show_statist;

/***************** module init stuff ************************/

struct rate_limiter server_limiter = {
	.lim_max_rate = 0,
};

void exit_xio_server(void)
{
	int i;

	XIO_INF("exit_server()\n");
	server_unregister_brick_type();

	for (i = 0; i < NR_SERVER_SOCKETS; i++) {
		if (server_threads[i]) {
			XIO_INF("stopping server thread %d...\n", i);
			brick_thread_stop(server_threads[i]);
		}
		XIO_INF("closing server socket %d...\n", i);
		xio_put_socket(&server_socket[i]);
	}
}

int __init init_xio_server(void)
{
	int i;

	XIO_INF("init_server()\n");

	for (i = 0; i < NR_SERVER_SOCKETS; i++) {
		struct sockaddr_storage sockaddr = {};
		char tmp[64];
		int status;

		if (xio_translate_hostname)
			snprintf(tmp, sizeof(tmp), "%s:%d", my_id(), xio_net_default_port + i);
		else
			snprintf(tmp, sizeof(tmp), ":%d", xio_net_default_port + i);

		status = xio_create_sockaddr(&sockaddr, tmp);
		if (unlikely(status < 0)) {
			exit_xio_server();
			return status;
		}

		status = xio_create_socket(&server_socket[i], &sockaddr, NULL);
		if (unlikely(status < 0)) {
			XIO_ERR("could not create server socket %d, status = %d\n", i, status);
			exit_xio_server();
			return status;
		}

		server_threads[i] = brick_thread_create(server_thread, &server_socket[i], "xio_server_%d", i);
		if (unlikely(!server_threads[i] || IS_ERR(server_threads[i]))) {
			XIO_ERR("could not create server thread %d\n", i);
			exit_xio_server();
			return -ENOENT;
		}
	}

	return server_register_brick_type();
}
