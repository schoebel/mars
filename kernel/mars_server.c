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
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define _STRATEGY
#include "mars.h"
#include "mars_bio.h"
#include "mars_aio.h"
#include "mars_sio.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_server.h"

#define NR_SOCKETS 3

static struct mars_socket server_socket[NR_SOCKETS] = {};
static struct task_struct *server_thread[NR_SOCKETS] = {};

atomic_t server_handler_count = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(server_handler_count);

///////////////////////// own helper functions ////////////////////////


static
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
		bool cork;
		unsigned long flags;
		
		wait_event_interruptible_timeout(
			brick->cb_event,
			!list_empty(&brick->cb_read_list) ||
			!list_empty(&brick->cb_write_list),
			1 * HZ);

		traced_lock(&brick->cb_lock, flags);
		tmp = brick->cb_write_list.next;
		if (tmp == &brick->cb_write_list) {
			tmp = brick->cb_read_list.next;
			if (tmp == &brick->cb_read_list) {
				traced_unlock(&brick->cb_lock, flags);
				brick_msleep(1000 / HZ);
				continue;
			}
		}
		list_del_init(tmp);
		cork = !list_empty(&brick->cb_write_list);
		traced_unlock(&brick->cb_lock, flags);

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
			status = mars_send_cb(sock, mref, cork);
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
			mars_free_mref(mref);
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

	traced_lock(&brick->cb_lock, flags);
	if (rw) {
		list_add_tail(&mref_a->cb_head, &brick->cb_write_list);
	} else {
		list_add_tail(&mref_a->cb_head, &brick->cb_read_list);
	}
	traced_unlock(&brick->cb_lock, flags);

	wake_up_interruptible(&brick->cb_event);
	return;
err:
	MARS_FAT("cannot handle callback - giving up\n");
}

static
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
	if (!mref)
		goto done;

	mref_a = server_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a)) {
		mars_free_mref(mref);
		goto done;
	}

	status = mars_recv_mref(sock, mref, cmd);
	if (status < 0) {
		mars_free_mref(mref);
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

static
void _clean_list(struct server_brick *brick, struct list_head *start)
{
	for (;;) {
		struct server_mref_aspect *mref_a;
		struct mref_object *mref;
		struct list_head *tmp = start->next;
		if (tmp == start)
			break;

		list_del_init(tmp);

		mref_a = container_of(tmp, struct server_mref_aspect, cb_head);
		mref_a->brick = NULL;
		mref = mref_a->object;
		if (!mref)
			continue;

		if (mref_a->do_put) {
			GENERIC_INPUT_CALL(brick->inputs[0], mref_put, mref);
			atomic_dec(&brick->in_flight);
		} else {
			mars_free_mref(mref);
		}
	}
}

static
int _set_server_sio_params(struct mars_brick *_brick, void *private)
{
	struct sio_brick *sio_brick = (void*)_brick;
	if (_brick->type != (void*)_sio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	sio_brick->o_direct = false;
	sio_brick->o_fdsync = false;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_server_aio_params(struct mars_brick *_brick, void *private)
{
	struct aio_brick *aio_brick = (void*)_brick;
	if (_brick->type == (void*)_sio_brick_type) {
		return _set_server_sio_params(_brick, private);
	}
	if (_brick->type != (void*)_aio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	aio_brick->o_creat = false;
	aio_brick->o_direct = false;
	aio_brick->o_fdsync = false;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int _set_server_bio_params(struct mars_brick *_brick, void *private)
{
	struct bio_brick *bio_brick;
	if (_brick->type == (void*)_aio_brick_type) {
		return _set_server_aio_params(_brick, private);
	}
	if (_brick->type == (void*)_sio_brick_type) {
		return _set_server_sio_params(_brick, private);
	}
	if (_brick->type != (void*)_bio_brick_type) {
		MARS_ERR("bad brick type\n");
		return -EINVAL;
	}
	bio_brick = (void*)_brick;
	bio_brick->ra_pages = 0;
	bio_brick->do_noidle = true;
	bio_brick->do_sync = true;
	bio_brick->do_unplug = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int dummy_worker(struct mars_global *global, struct mars_dent *dent, bool prepare, bool direction)
{
	return 0;
}

static
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
				if (mars_disconnect((void*)brick->inputs[0]) >= 0)
					brick->conn_brick = NULL;
			}

			status = mars_kill_brick_when_possible(&handler_global, &handler_global.brick_anchor, false, NULL, true);
			MARS_DBG("kill handler bricks (when possible) = %d\n", status);
		}

		status = -EINTR;
		if (unlikely(!mars_global || !mars_global->global_power.button)) {
			MARS_DBG("system is not alive\n");
			goto clean;
		}
		if (unlikely(brick_thread_should_stop())) {
			goto clean;
		}
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

		MARS_IO("#%d cmd = %d\n", sock->s_debug_nr, cmd.cmd_code);

		if (unlikely(!brick->global || !mars_global || !mars_global->global_power.button)) {
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
			if (status < 0) {
				break;
			}
			down(&brick->socket_sem);
			status = mars_send_struct(sock, &cmd, mars_cmd_meta, true);
			if (status >= 0) {
				status = mars_send_struct(sock, &info, mars_info_meta, false);
			}
			up(&brick->socket_sem);
			break;
		}
		case CMD_GETENTS:
		{
			char *path = cmd.cmd_str1 ? cmd.cmd_str1 : "/mars";

			status = mars_dent_work(
				&handler_global,
				path,
				sizeof(struct mars_dent),
				main_checker,
				dummy_worker,
				&handler_global,
				3);

			down(&brick->socket_sem);
			status = mars_send_dent_list(sock, &handler_global.dent_anchor);
			up(&brick->socket_sem);

			if (status < 0) {
				MARS_WRN("#%d could not send dentry information, status = %d\n", sock->s_debug_nr, status);
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
				(const struct generic_brick_type*)_bio_brick_type,
				(const struct generic_brick_type*[]){},
				2, // start always
				path,
				(const char *[]){},
				0);
			if (likely(prev)) {
				status = mars_connect((void *)brick->inputs[0], prev->outputs[0]);
				if (unlikely(status < 0)) {
					MARS_ERR("#%d cannot connect to '%s'\n", sock->s_debug_nr, path);
				}
				prev->killme = true;
				brick->conn_brick = prev;
			} else {
				MARS_ERR("#%d cannot find brick '%s'\n", sock->s_debug_nr, path);
			}
			
		err:
			cmd.cmd_int1 = status;
			down(&brick->socket_sem);
			status = mars_send_struct(sock, &cmd, mars_cmd_meta, false);
			up(&brick->socket_sem);
			break;
		}
		case CMD_MREF:
		{
#ifdef CONFIG_MARS_LOADAVG_LIMIT // quirk
			int my_load = (avenrun[0] + FIXED_1/200) >> FSHIFT;
			if (mars_max_loadavg && my_load >= mars_max_loadavg) {
				MARS_WRN("#%d loadavg %d too high (%d), aborting data traffic\n", sock->s_debug_nr, my_load, mars_max_loadavg);
				status = -EBUSY;
				break;
			}
#endif
			status = server_io(brick, sock, &cmd);
			break;
		}
		case CMD_CB:
			MARS_ERR("#%d oops, as a server I should never get CMD_CB; something is wrong here - attack attempt??\n", sock->s_debug_nr);
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
	atomic_dec(&server_handler_count);
	brick->killme = true;
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

static int server_switch(struct server_brick *brick)
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

		mars_power_led_off((void*)brick, false);

		brick->version = version++;
		brick->handler_thread = brick_thread_create(handler_thread, brick, "mars_handler%d", brick->version);
		if (unlikely(!brick->handler_thread)) {
			MARS_ERR("cannot create handler thread\n");
			status = -ENOENT;
			goto err;
		}

		mars_power_led_on((void*)brick, true);
	} else if (!brick->power.led_off) {
		struct task_struct *thread;
		mars_power_led_on((void*)brick, false);

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

		// do this only after _both_ threads have stopped...
		_clean_list(brick, &brick->cb_read_list);
		_clean_list(brick, &brick->cb_write_list);

		mars_power_led_off((void*)brick, true);
	}
 err:
	if (unlikely(status < 0)) {
		mars_power_led_off((void*)brick, true);
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
        if (!res)
                return NULL;
	
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
	struct server_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->cb_head);
	return 0;
}

static void server_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct server_mref_aspect *ini = (void*)_ini;
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
EXPORT_SYMBOL_GPL(server_brick_type);

///////////////////////////////////////////////////////////////////////

// strategy layer

int server_show_statist = 0;
EXPORT_SYMBOL_GPL(server_show_statist);

static int _server_thread(void *data)
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
		mars_limit(&server_limiter, 0);

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

		brick = (void*)mars_make_brick(&server_global, NULL, &server_brick_type, "handler", "handler");
		if (!brick) {
			MARS_ERR("cannot create server instance\n");
			mars_shutdown_socket(&handler_socket);
			mars_put_socket(&handler_socket);
			brick_msleep(2000);
			continue;
		}
		memcpy(&brick->handler_socket, &handler_socket, sizeof(struct mars_socket));

		atomic_inc(&server_handler_count);

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
			status = mars_kill_brick((void*)brick);
			if (status < 0) {
				BRICK_ERR("kill status = %d, giving up\n", status);
			}
			brick = NULL;
			atomic_dec(&server_handler_count);
		}
		brick_msleep(2000);
	}

	MARS_INF("-------- cleaning up ----------\n");

	mars_kill_brick_all(&server_global, &server_global.brick_anchor, false);

	//cleanup_mm();

	MARS_INF("-------- done status = %d ----------\n", status);
	return status;
}

////////////////// module init stuff /////////////////////////

struct mars_limiter server_limiter = {
	.lim_max_rate = 0,
};
EXPORT_SYMBOL_GPL(server_limiter);

void exit_mars_server(void)
{
	int i;

	MARS_INF("exit_server()\n");
	server_unregister_brick_type();

	for (i = 0; i < NR_SOCKETS; i++) {
		if (server_thread[i]) {
			MARS_INF("stopping server thread %d...\n", i);
			brick_thread_stop(server_thread[i]);
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
		char tmp[16];
		int status;

		sprintf(tmp, ":%d", mars_net_default_port + i);
		status = mars_create_sockaddr(&sockaddr, tmp);
		if (unlikely(status < 0)) {
			exit_mars_server();
			return status;
		}

		status = mars_create_socket(&server_socket[i], &sockaddr, true);
		if (unlikely(status < 0)) {
			MARS_ERR("could not create server socket %d, status = %d\n", i, status);
			exit_mars_server();
			return status;
		}

		server_thread[i] = brick_thread_create(_server_thread, &server_socket[i], "mars_server_%d", i);
		if (unlikely(!server_thread[i] || IS_ERR(server_thread[i]))) {
			MARS_ERR("could not create server thread %d\n", i);
			exit_mars_server();
			return -ENOENT;
		}
	}

	return server_register_brick_type();
}
