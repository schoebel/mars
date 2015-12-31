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

/* MARS Light specific parts of xio_server
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define _STRATEGY
#include "brick.h"
#include "mars.h"
#include "mars_bio.h"
//	remove_this
#ifndef __USE_COMPAT
#include "mars_aio.h"
#endif
//	end_remove_this
#include "mars_sio.h"

#include "sy_old/strategy.h"

#include "mars_server.h"

static
int dummy_worker(struct mars_global *global, struct mars_dent *dent, bool prepare, bool direction)
{
	return 0;
}

static
int _set_server_sio_params(struct mars_brick *_brick, void *private)
{
	struct sio_brick *sio_brick = (void *)_brick;

	if (_brick->type != (void *)_sio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	sio_brick->o_direct = false;
	sio_brick->o_fdsync = false;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

//	remove_this
#ifndef __USE_COMPAT
static
int _set_server_aio_params(struct mars_brick *_brick, void *private)
{
	struct aio_brick *aio_brick = (void *)_brick;

	if (_brick->type == (void *)_sio_brick_type)
		return _set_server_sio_params(_brick, private);
	if (_brick->type != (void *)_aio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	aio_brick->o_creat = false;
	aio_brick->o_direct = false;
	aio_brick->o_fdsync = false;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}
#endif

//	end_remove_this
static
int _set_server_bio_params(struct mars_brick *_brick, void *private)
{
	struct bio_brick *bio_brick;

//	remove_this
#ifndef __USE_COMPAT
	if (_brick->type == (void *)_aio_brick_type)
		return _set_server_aio_params(_brick, private);
#endif
//	end_remove_this
	if (_brick->type == (void *)_sio_brick_type)
		return _set_server_sio_params(_brick, private);
	if (_brick->type != (void *)_bio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	bio_brick = (void *)_brick;
	bio_brick->ra_pages = 0;
	bio_brick->do_noidle = true;
	bio_brick->do_sync = true;
	bio_brick->do_unplug = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

int handler_thread(void *data)
{
	struct mars_global handler_global = {
		.dent_anchor = LIST_HEAD_INIT(handler_global.dent_anchor),
		.brick_anchor = LIST_HEAD_INIT(handler_global.brick_anchor),
		.global_power = {
			.button = true,
		},
		.main_event = __WAIT_QUEUE_HEAD_INITIALIZER(handler_global.main_event),
	};
	struct task_struct *thread = NULL;
	struct server_brick *brick = data;
	struct mars_socket *sock = &brick->handler_socket;
	bool ok = mars_get_socket(sock);
	unsigned long statist_jiffies = jiffies;
	int debug_nr;
	int status = -EINVAL;

	init_rwsem(&handler_global.dent_mutex);
	init_rwsem(&handler_global.brick_mutex);

	MARS_DBG("#%d --------------- handler_thread starting on socket %p\n", sock->s_debug_nr, sock);
	if (!ok)
		goto done;

	thread = brick_thread_create(cb_thread, brick, "mars_cb%d", brick->version);
	if (unlikely(!thread)) {
		MARS_ERR("cannot create cb thread\n");
		status = -ENOENT;
		goto done;
	}
	brick->cb_thread = thread;

	brick->handler_running = true;
	wake_up_interruptible(&brick->startup_event);

	while (!list_empty(&handler_global.brick_anchor) ||
	       mars_socket_is_alive(sock)) {
		struct mars_cmd cmd = {};

		handler_global.global_version++;

		if (!list_empty(&handler_global.brick_anchor)) {
			if (server_show_statist && !time_is_before_jiffies(statist_jiffies + 10 * HZ)) {
				show_statistics(&handler_global, "handler");
				statist_jiffies = jiffies;
			}
			if (!mars_socket_is_alive(sock) &&
			    atomic_read(&brick->in_flight) <= 0 &&
			    brick->conn_brick) {
				if (generic_disconnect((void *)brick->inputs[0]) >= 0)
					brick->conn_brick = NULL;
			}

			status = mars_kill_brick_when_possible(&handler_global,
				&handler_global.brick_anchor,
				false,
				NULL,
				true);
			MARS_DBG("kill handler bricks (when possible) = %d\n", status);
		}

		status = -EINTR;
		if (unlikely(!mars_global || !mars_global->global_power.button)) {
			MARS_DBG("system is not alive\n");
			goto clean;
		}
		if (unlikely(brick_thread_should_stop()))
			goto clean;
		if (unlikely(!mars_socket_is_alive(sock))) {
			/* Dont read any data anymore, the protocol
			 * may be screwed up completely.
			 */
			MARS_DBG("#%d is dead\n", sock->s_debug_nr);
			goto clean;
		}

		status = mars_recv_struct(sock, &cmd, mars_cmd_meta);
		if (unlikely(status < 0)) {
			MARS_WRN("#%d recv cmd status = %d\n", sock->s_debug_nr, status);
			goto clean;
		}

		if (unlikely(!brick->private_ptr || !mars_global || !mars_global->global_power.button)) {
			MARS_WRN("#%d system is not alive\n", sock->s_debug_nr);
			status = -EINTR;
			goto clean;
		}

		status = -EPROTO;
		switch (cmd.cmd_code & CMD_FLAG_MASK) {
		case CMD_NOP:
			status = 0;
			MARS_DBG("#%d got NOP operation\n", sock->s_debug_nr);
			break;
		case CMD_NOTIFY:
			status = 0;
			from_remote_trigger();
			break;
		case CMD_GETINFO:
		{
			struct mars_info info = {};

			status = GENERIC_INPUT_CALL(brick->inputs[0], mars_get_info, &info);
			if (status < 0)
				break;
			down(&brick->socket_sem);
			status = mars_send_struct(sock, &cmd, mars_cmd_meta);
			if (status >= 0)
				status = mars_send_struct(sock, &info, mars_info_meta);
			up(&brick->socket_sem);
			break;
		}
		case CMD_GETENTS:
		{
			status = -EINVAL;
			if (unlikely(!cmd.cmd_str1))
				break;

			status = mars_dent_work(&handler_global,
				"/mars",
				sizeof(struct mars_dent),
				light_checker,
				dummy_worker,
				&handler_global,
				3);

			down(&brick->socket_sem);
			status = mars_send_dent_list(sock, &handler_global.dent_anchor);
			up(&brick->socket_sem);

			if (status < 0) {
				MARS_WRN("#%d could not send dentry information, status = %d\n",
					sock->s_debug_nr,
					status);
			}

			mars_free_dent_all(&handler_global, &handler_global.dent_anchor);
			break;
		}
		case CMD_CONNECT:
		{
			struct mars_brick *prev;
			const char *path = cmd.cmd_str1;

			status = -EINVAL;
			CHECK_PTR(path, err);
			CHECK_PTR_NULL(_bio_brick_type, err);

			prev = make_brick_all(
				&handler_global,
				NULL,
				_set_server_bio_params,
				NULL,
				path,
				(const struct generic_brick_type *)_bio_brick_type,
				(const struct generic_brick_type *[]){},
				2, // start always
				path,
				(const char *[]){},
				0);
			if (likely(prev)) {
				status = generic_connect((void *)brick->inputs[0], (void *)prev->outputs[0]);
				if (unlikely(status < 0))
					MARS_ERR("#%d cannot connect to '%s'\n", sock->s_debug_nr, path);
				prev->killme = true;
				brick->conn_brick = prev;
			} else {
				MARS_ERR("#%d cannot find brick '%s'\n", sock->s_debug_nr, path);
			}

err:
			cmd.cmd_int1 = status;
			down(&brick->socket_sem);
			status = mars_send_struct(sock, &cmd, mars_cmd_meta);
			up(&brick->socket_sem);
			break;
		}
		case CMD_MREF:
		{
			status = server_io(brick, sock, &cmd);
			break;
		}
		case CMD_CB:
			MARS_ERR("#%d oops, as a server I should never get CMD_CB; something is wrong here - attack attempt??\n",
				sock->s_debug_nr);
			break;
		default:
			MARS_ERR("#%d unknown command %d\n", sock->s_debug_nr, cmd.cmd_code);
		}
clean:
		brick_string_free(cmd.cmd_str1);
		if (unlikely(status < 0)) {
			mars_shutdown_socket(sock);
			brick_msleep(1000);
		}
	}

	mars_shutdown_socket(sock);
	mars_put_socket(sock);

done:
	MARS_DBG("#%d handler_thread terminating, status = %d\n", sock->s_debug_nr, status);

	mars_kill_brick_all(&handler_global, &handler_global.brick_anchor, false);

	if (thread) {
		brick->cb_thread = NULL;
		brick->cb_running = false;
		MARS_DBG("#%d stopping callback thread....\n", sock->s_debug_nr);
		brick_thread_stop(thread);
	}

	debug_nr = sock->s_debug_nr;

	MARS_DBG("#%d done.\n", debug_nr);
	brick->killme = true;
	return status;
}

int server_thread(void *data)
{
	struct mars_global server_global = {
		.dent_anchor = LIST_HEAD_INIT(server_global.dent_anchor),
		.brick_anchor = LIST_HEAD_INIT(server_global.brick_anchor),
		.global_power = {
			.button = true,
		},
		.main_event = __WAIT_QUEUE_HEAD_INITIALIZER(server_global.main_event),
	};
	struct mars_socket *my_socket = data;
	char *id = my_id();
	int status = 0;

	init_rwsem(&server_global.dent_mutex);
	init_rwsem(&server_global.brick_mutex);

	MARS_INF("-------- server starting on host '%s' ----------\n", id);

	while (!brick_thread_should_stop() &&
	      (!mars_global || !mars_global->global_power.button)) {
		MARS_DBG("system did not start up\n");
		brick_msleep(5000);
	}

	MARS_INF("-------- server now working on host '%s' ----------\n", id);

	while (!brick_thread_should_stop() || !list_empty(&server_global.brick_anchor)) {
		struct server_brick *brick = NULL;
		struct mars_socket handler_socket = {};

		server_global.global_version++;

		if (server_show_statist)
			show_statistics(&server_global, "server");

		status = mars_kill_brick_when_possible(&server_global, &server_global.brick_anchor, false, NULL, true);
		MARS_DBG("kill server bricks (when possible) = %d\n", status);

		if (!mars_global || !mars_global->global_power.button) {
			brick_msleep(1000);
			continue;
		}

		status = mars_accept_socket(&handler_socket, my_socket);
		if (unlikely(status < 0 || !mars_socket_is_alive(&handler_socket))) {
			brick_msleep(500);
			if (status == -EAGAIN)
				continue; // without error message
			MARS_WRN("accept status = %d\n", status);
			brick_msleep(1000);
			continue;
		}
		handler_socket.s_shutdown_on_err = true;

		MARS_DBG("got new connection #%d\n", handler_socket.s_debug_nr);

		brick = (void *)mars_make_brick(&server_global, NULL, &server_brick_type, "handler", "handler");
		if (!brick) {
			MARS_ERR("cannot create server instance\n");
			mars_shutdown_socket(&handler_socket);
			mars_put_socket(&handler_socket);
			brick_msleep(2000);
			continue;
		}
		memcpy(&brick->handler_socket, &handler_socket, sizeof(struct mars_socket));

		/* TODO: check authorization.
		 */

		brick->power.button = true;
		status = server_switch(brick);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot switch on server brick, status = %d\n", status);
			goto err;
		}

		// further references are usually held by the threads
		mars_put_socket(&brick->handler_socket);

		/* fire and forget....
		 * the new instance is now responsible for itself.
		 */
		brick = NULL;
		brick_msleep(100);
		continue;

err:
		if (brick) {
			mars_shutdown_socket(&brick->handler_socket);
			mars_put_socket(&brick->handler_socket);
			status = mars_kill_brick((void *)brick);
			if (status < 0)
				BRICK_ERR("kill status = %d, giving up\n", status);
			brick = NULL;
		}
		brick_msleep(2000);
	}

	MARS_INF("-------- cleaning up ----------\n");

	mars_kill_brick_all(&server_global, &server_global.brick_anchor, false);

	//cleanup_mm();

	MARS_INF("-------- done status = %d ----------\n", status);
	return status;
}
