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

struct server_cookie {
	struct mars_socket server_socket;
	struct mars_tcp_params *server_params;
	int port_nr;
	int thread_nr;
};

static struct server_cookie server_cookie[MARS_TRAFFIC_MAX] = {
	[MARS_TRAFFIC_META] = {
		.server_params = &mars_tcp_params[MARS_TRAFFIC_META],
	},
	[MARS_TRAFFIC_REPLICATION] = {
		.server_params = &mars_tcp_params[MARS_TRAFFIC_REPLICATION],
	},
	[MARS_TRAFFIC_SYNC] = {
		.server_params = &mars_tcp_params[MARS_TRAFFIC_SYNC],
	},
};

static struct task_struct *server_thread[MARS_TRAFFIC_MAX] = {};

atomic_t server_handler_count = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(server_handler_count);

///////////////////////// own helper functions ////////////////////////

#define HANDLER_LIMIT 1024

int handler_limit = HANDLER_LIMIT;
int handler_nr = HANDLER_LIMIT;
static struct semaphore handler_limit_sem = __SEMAPHORE_INITIALIZER(handler_limit_sem, HANDLER_LIMIT);

#define DENT_LIMIT 2
#define DENT_RETRY 5

int dent_limit = DENT_LIMIT;
int dent_nr = DENT_LIMIT;
static struct semaphore dent_limit_sem = __SEMAPHORE_INITIALIZER(dent_limit_sem, DENT_LIMIT);
int dent_retry = DENT_RETRY;

static
void change_sem(struct semaphore *sem, int *limit, int *nr)
{
	if (unlikely(*nr < *limit)) {
		up(sem);
		(*nr)++;
	} else if (unlikely(*nr > *limit)) {
		if (!down_trylock(sem))
			(*nr)--;
	}
}

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
		
		wait_event_interruptible_timeout(
			brick->cb_event,
			!list_empty(&brick->cb_read_list) ||
			!list_empty(&brick->cb_write_list),
			1 * HZ);

		mutex_lock(&brick->cb_mutex);
		tmp = brick->cb_write_list.next;
		if (tmp == &brick->cb_write_list) {
			tmp = brick->cb_read_list.next;
			if (tmp == &brick->cb_read_list) {
				mutex_unlock(&brick->cb_mutex);
				brick_yield();
				continue;
			}
		}
		list_del_init(tmp);
		cork = !list_empty(&brick->cb_write_list);
		mutex_unlock(&brick->cb_mutex);

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
			mref->ref_flags |= enabled_net_compressions;
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

		if (mref_a->do_put) {
			GENERIC_INPUT_CALL_VOID(brick->inputs[0], mref_put, mref);
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

	mutex_lock(&brick->cb_mutex);
	if (mref->ref_flags & MREF_WRITE) {
		list_add_tail(&mref_a->cb_head, &brick->cb_write_list);
	} else {
		list_add_tail(&mref_a->cb_head, &brick->cb_read_list);
	}
	mutex_unlock(&brick->cb_mutex);

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
	mref_a->brick = brick;
	mref_a->first_data = mref->ref_data;

	status = mars_recv_mref(sock, mref, cmd);
	if (status < 0) {
		mars_free_mref(mref);
		goto done;
	}

	if (!mref_a->first_data) {
		mref_a->first_data = mref->ref_data;
		mref_a->first_len = mref->ref_len;
	}
	SETUP_CALLBACK(mref, server_endio, mref_a);

	amount = 0;
	if (!(mref->ref_flags & MREF_NODATA))
		amount = (mref->ref_len - 1) / 1024 + 1;
	mars_limit_sleep(&server_limiter, amount);
	
	status = GENERIC_INPUT_CALL(brick->inputs[0], mref_get, mref);
	if (unlikely(status < 0)) {
		MARS_WRN("mref_get execution error = %d\n", status);
		SIMPLE_CALLBACK(mref, status);
		status = 0; // continue serving requests
		goto done;
	}
	if (!mref_a->first_data) {
		mref_a->first_data = mref->ref_data;
		mref_a->first_len = mref->ref_len;
	}
	mref_a->do_put = true;
	atomic_inc(&brick->in_flight);

	GENERIC_INPUT_CALL_VOID(brick->inputs[0], mref_io, mref);

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
			GENERIC_INPUT_CALL_VOID(brick->inputs[0], mref_put, mref);
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
	bio_brick->do_sync = true;
	bio_brick->do_unplug = true;
	MARS_INF("name = '%s' path = '%s'\n", _brick->brick_name, _brick->brick_path);
	return 1;
}

static
int handler_thread(void *data)
{
	struct mars_global *handler_global = alloc_mars_global();
	struct task_struct *thread = NULL;
	struct server_brick *brick = data;
	char *cb_name;
	struct mars_socket *sock = &brick->handler_socket;
	bool ok = mars_get_socket(sock);
	unsigned long statist_jiffies = jiffies;
	int debug_nr;
	int old_proto_level = 0;
	int status = -EINVAL;

	MARS_DBG("#%d --------------- handler_thread starting on socket %p\n", sock->s_debug_nr, sock);
	if (!ok)
		goto done;

	cb_name = brick_strdup(brick->brick_path);
	/* naming convention: mars_c instead of mars_h */
	cb_name[5] = 'c';
	thread = brick_thread_create(cb_thread,
				     brick,
				     cb_name);
	brick_string_free(cb_name);
	if (unlikely(!thread)) {
		MARS_ERR("cannot create cb thread\n");
		status = -ENOENT;
		goto done;
	}
	brick->cb_thread = thread;

	brick->handler_running = true;
	wake_up_interruptible(&brick->startup_event);

        while (!list_empty(&handler_global->brick_anchor) ||
	       mars_socket_is_alive(sock)) {
		struct mars_cmd cmd = {};

		handler_global->global_version++;

		if (!list_empty(&handler_global->brick_anchor)) {
			if (server_show_statist && !time_is_before_jiffies(statist_jiffies + 10 * HZ)) {
				show_statistics(handler_global, "handler");
				statist_jiffies = jiffies;
			}
			if (!mars_socket_is_alive(sock) &&
			    atomic_read(&brick->in_flight) <= 0 &&
			    brick->conn_brick) {
				if (mars_disconnect((void*)brick->inputs[0]) >= 0)
					brick->conn_brick = NULL;
			}

			status = mars_kill_brick_when_possible(handler_global,
							       NULL, true);
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
		if (down_trylock(&handler_limit_sem)) {
			MARS_DBG("#%d handler limit reached\n", sock->s_debug_nr);
			status = -EUSERS;
			goto clean;
		}

		status = mars_recv_cmd(sock, &cmd);
		if (unlikely(status < 0)) {
			MARS_WRN("#%d recv cmd status = %d\n", sock->s_debug_nr, status);
			goto clean_unlock;
		}

		MARS_IO("#%d cmd = %d\n", sock->s_debug_nr, cmd.cmd_code);

		if (unlikely(!brick->global || !mars_global || !mars_global->global_power.button)) {
			MARS_WRN("#%d system is not alive\n", sock->s_debug_nr);
			status = -EINTR;
			goto clean_unlock;
		}

		status = -EPROTO;
		switch (cmd.cmd_code & CMD_FLAG_MASK) {
		case CMD_NOP:
			status = 0;
			MARS_DBG("#%d got NOP operation\n", sock->s_debug_nr);
			break;
		case CMD_NOTIFY:
			status = 0;
			mars_remote_trigger(MARS_TRIGGER_LOCAL | MARS_TRIGGER_FROM_REMOTE);
			break;
		case CMD_GETINFO:
		{
			struct mars_info info = {};
			status = GENERIC_INPUT_CALL(brick->inputs[0], mars_get_info, &info);
			if (status < 0) {
				break;
			}
			down(&brick->socket_sem);
			status = mars_send_cmd(sock, &cmd, true);
			old_proto_level = sock->s_common_proto_level;
			if (status >= 0) {
				status = mars_send_struct(sock, &info, mars_info_meta, false);
			}
			up(&brick->socket_sem);
			break;
		}
		case CMD_GETENTS:
		{
			const char *path = cmd.cmd_str1 ? cmd.cmd_str1 : "/mars";
			int max_retry = dent_retry;

			while (down_trylock(&dent_limit_sem)) {
				if (max_retry-- <= 0) {
					MARS_DBG("#%d dent limit reached\n", sock->s_debug_nr);
					status = -EUSERS;
					goto clean_unlock;
				}
				brick_msleep(200);
			}

			/* New protocol.
			 * We cannot send/recv intermediate cmds at the
			 * old protocol.
			 * For compatibility, the old protocol must be
			 * used until the fist cmd response has been sent.
			 */
			if (sock->s_common_proto_level > 0 &&
			    old_proto_level > 0) {
				/* send Lamport stamp of local /mars status */
				get_lamport(NULL, &cmd.cmd_stamp);
				down(&brick->socket_sem);
				status = mars_send_cmd(sock, &cmd, true);
				old_proto_level = sock->s_common_proto_level;
				if (unlikely(status < 0)) {
					MARS_WRN("#%d could not send inter_cmd, status = %d\n",
						 sock->s_debug_nr, status);
				}
				up(&brick->socket_sem);
			}

			status = mars_get_dent_list(
				handler_global,
				path,
				sizeof(struct mars_dent),
				main_checker,
				3);

			up(&dent_limit_sem);

			/* Looks strange, but is needed for not triggering
			 * a masked bug in old MARS versions during mixed
			 * updates.
			 */
			if (sock->s_common_proto_level >= 2)
				old_proto_level = sock->s_common_proto_level;

			down(&brick->socket_sem);
			status = mars_send_dent_list(handler_global, sock);
			up(&brick->socket_sem);

			if (status < 0) {
				MARS_WRN("#%d could not send dentry information, status = %d\n", sock->s_debug_nr, status);
			}

			mars_free_dent_all(handler_global);
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
				handler_global,
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
			status = mars_send_cmd(sock, &cmd, false);
			old_proto_level = sock->s_common_proto_level;
			up(&brick->socket_sem);
			break;
		}
		case CMD_MREF:
		{
			status = server_io(brick, sock, &cmd);
			break;
		}
		case CMD_CB:
			MARS_ERR("#%d oops, as a server I should never get CMD_CB; something is wrong here - attack attempt??\n", sock->s_debug_nr);
			break;
		case CMD_PUSH_LINK:
		{
			/* TODO: better security
			 */
			status = 0;
			if (unlikely(!cmd.cmd_str1 || !cmd.cmd_str2))
				break;
			/* Confine to /mars/ and /dev/ */
			if (unlikely(strncmp(cmd.cmd_str2, "/mars/", 6) ||
				     (cmd.cmd_str1[0] == '/' &&
				      strncmp(cmd.cmd_str1, "/mars/", 6) &&
				      strncmp(cmd.cmd_str1, "/dev/", 5)))) {
				MARS_ERR("Invalid push attempt '%s' -> '%s'\n",
					 cmd.cmd_str2,
					 cmd.cmd_str1);
				printk(KERN_ALERT "Invalid MARS push attempt '%s' -> '%s'\n",
					 cmd.cmd_str2,
					 cmd.cmd_str1);
				status = -EPERM;
				break;
			}
			invalidate_user_cache();

			status =
				ordered_symlink(cmd.cmd_str1,
						cmd.cmd_str2,
						&cmd.cmd_stamp);
			if (status >= 0) {
				if (!strncmp(cmd.cmd_str2,
					     "/mars/ips/ip-", 13))
					launch_peer(cmd.cmd_str2 + 13,
						    NULL,
						    NULL,
						    false);
			}
			break;
		}
		case CMD_PUSH_CHECK:
		{
			struct kstat probe;

			status = mars_stat(cmd.cmd_str2, &probe, true);
			if (status < 0) {
				invalidate_user_cache();
				launch_peer(cmd.cmd_str1, NULL, NULL, true);
			}
			status = 0;
			break;
		}
		default:
			MARS_ERR("#%d unknown command %d\n", sock->s_debug_nr, cmd.cmd_code);
		}
	clean_unlock:
		up(&handler_limit_sem);
	clean:
		brick_string_free(cmd.cmd_str1);
		brick_string_free(cmd.cmd_str2);
		if (unlikely(status < 0)) {
			mars_shutdown_socket(sock);
			brick_msleep(100);
		}
	}

	mars_shutdown_socket(sock);
	mars_put_socket(sock);

 done:
	MARS_DBG("#%d handler_thread terminating, status = %d\n", sock->s_debug_nr, status);

	mars_kill_brick_all(handler_global, &handler_global->brick_anchor, false);

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
	free_mars_global(handler_global);
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

	GENERIC_INPUT_CALL_VOID(input, mref_put, mref);
}

static void server_ref_io(struct server_output *output, struct mref_object *mref)
{
	struct server_input *input = output->brick->inputs[0];

	GENERIC_INPUT_CALL_VOID(input, mref_io, mref);
}

static int server_switch(struct server_brick *brick)
{
	struct mars_socket *sock = &brick->handler_socket;
	int status = 0;

	if (brick->power.button) {
		bool ok;

		if (brick->power.led_on)
			goto done;

		ok = mars_get_socket(sock);
		if (unlikely(!ok)) {
			status = -ENOENT;
			goto err;
		}

		mars_power_led_off((void*)brick, false);

		brick->handler_thread =
			brick_thread_create(handler_thread,
					    brick,
					    brick->brick_path);
		if (unlikely(!brick->handler_thread)) {
			MARS_ERR("cannot create handler thread\n");
			status = -ENOENT;
			goto err;
		}

		mars_power_led_on((void*)brick, true);
	} else if (!brick->power.led_off) {
		struct task_struct *thread;
		int nr_retry;
		int success;

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

		/* Safeguard against hanging threads.
		 */
		nr_retry = 0;
	retry:
		success = mutex_trylock(&brick->cb_mutex);
		if (!success) {
			brick_msleep(100);
			if (nr_retry++ < 100)
				goto retry;
			MARS_ERR("thread '%s' seems to hang\n",
				 current->comm);
			goto done;
		}
		_clean_list(brick, &brick->cb_read_list);
		_clean_list(brick, &brick->cb_write_list);
		mutex_unlock(&brick->cb_mutex);

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
	struct server_mref_aspect *mref_a = (void *)_ini;

	INIT_LIST_HEAD(&mref_a->cb_head);
	return 0;
}

/* This is responsible for _safe_ transition to deallocate state.
 */
static void server_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct server_mref_aspect *mref_a = (void *)_ini;
	void *first_data;
	int first_len;

	/* For safety, do not leave dangling pointers.
	 * We don't want to win any micro-benchmarks here.
	 * We need to ensure geo-redundancy over long distances.
	 * When unsure, test via poisoning, independently at page
	 * granularity and at brick / object / aspect level.
	 */
	first_data = mref_a->first_data;
	first_len = mref_a->first_len;
	if (first_data && first_len) {
		struct mref_object *mref = mref_a->object;

		mref_a->first_data = NULL;
		/* Prevent double free.
		 * Some callee might have allocated, and already freed
		 * via mref_data. This might have happened upon another
		 * thread / interrupt / callback / etc.
		 * Network transports / compression / etc may introduce
		 * further parallelism, independently from all of this.
		 * Be sure to deallocate the original address, since
		 * some address arithmetic might have happened
		 * somewhere else (e.g. sector-wise / packet fragments / etc).
		 * All of this might have happened below your ass,
		 * where you cannot see it, because we cannot know which
		 * which other (future) brick instances we are / were
		 * (re)connected during our unknown brick lifetime
		 * (which might range from milliseconds to months).
		 */
		if (mref && mref->ref_data) {
			mref->ref_data = NULL;
			brick_block_free(first_data, first_len);
		}
	}

	CHECK_HEAD_EMPTY(&mref_a->cb_head);
}

MARS_MAKE_STATICS(server);

////////////////////// brick constructors / destructors ////////////////////

static int server_brick_construct(struct server_brick *brick)
{
	init_waitqueue_head(&brick->startup_event);
	init_waitqueue_head(&brick->cb_event);
	sema_init(&brick->socket_sem, 1);
	mutex_init(&brick->cb_mutex);
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

static int port_thread(void *data)
{
	struct mars_global *server_global = alloc_mars_global();
	struct server_cookie *cookie = data;
	struct mars_socket *my_socket = &cookie->server_socket;
	struct mars_tcp_params *my_params = cookie->server_params;
	char *id = my_id();
	int status = 0;

	MARS_INF("-------- port %d thread starting on host '%s' ----------\n",
		 cookie->port_nr, id);

        while (!brick_thread_should_stop() &&
	      (!mars_global || !mars_global->global_power.button)) {
		MARS_DBG("system did not start up\n");
		brick_msleep(1000);
	}

	MARS_INF("-------- port %d thread now working on host '%s' ----------\n",
		 cookie->port_nr, id);

        while (!brick_thread_should_stop() ||
	       !list_empty(&server_global->brick_anchor)) {
		struct server_brick *brick = NULL;
		const char *ini_path;
		struct mars_socket handler_socket = {};

		change_sem(&handler_limit_sem, &handler_limit, &handler_nr);
		change_sem(&dent_limit_sem, &dent_limit, &dent_nr);

		server_global->global_version++;
		mars_limit(&server_limiter, 0);

		if (server_show_statist)
			show_statistics(server_global, "server");

		status = mars_kill_brick_when_possible(server_global,
						       NULL, true);
		MARS_DBG("kill server bricks (when possible) = %d\n", status);

		if (!mars_global || !mars_global->global_power.button) {
			brick_msleep(200);
			continue;
		}

		status = mars_accept_socket(&handler_socket,
					    my_socket,
					    my_params);
		if (unlikely(status < 0 ||
			     !mars_socket_is_alive(&handler_socket))) {
			brick_msleep(200);
			if (status == -EAGAIN)
				continue; // without error message
			MARS_WRN("accept status = %d\n", status);
			continue;
		}
		handler_socket.s_shutdown_on_err = true;

		MARS_DBG("got new connection #%d\n", handler_socket.s_debug_nr);

		ini_path = path_make("mars_h:%d.%d",
				     cookie->port_nr,
				     ++cookie->thread_nr);
		brick = (void*)mars_make_brick(server_global, NULL,
					       &server_brick_type,
					       ini_path,
					       ini_path);
		brick_string_free(ini_path);
		if (!brick) {
			MARS_ERR("cannot create server instance\n");
			mars_shutdown_socket(&handler_socket);
			mars_put_socket(&handler_socket);
			brick_msleep(200);
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
		brick_msleep(200);
	}

	MARS_INF("-------- cleaning up ----------\n");

	mars_kill_brick_all(server_global, &server_global->brick_anchor, false);

	//cleanup_mm();

	MARS_INF("-------- port %d thread done status = %d ----------\n",
		 cookie->port_nr, status);
	free_mars_global(server_global);
	return status;
}

////////////////// module init stuff /////////////////////////

struct mars_limiter server_limiter = {
	/* Let all be zero */
};
EXPORT_SYMBOL_GPL(server_limiter);

void exit_mars_server(void)
{
	int i;

	MARS_INF("exit_server()\n");
	server_unregister_brick_type();

	for (i = 0; i < MARS_TRAFFIC_MAX; i++) {
		if (server_thread[i]) {
			MARS_INF("stopping server thread %d...\n", i);
			brick_thread_stop(server_thread[i]);
		}
		MARS_INF("closing server socket %d...\n", i);
		mars_put_socket(&server_cookie[i].server_socket);
	}
}

int __init init_mars_server(void)
{
	int i;

	MARS_INF("init_server()\n");

	for (i = 0; i < MARS_TRAFFIC_MAX; i++) {
		struct sockaddr_storage sockaddr = {};
		char tmp[16];
		int port_nr = mars_net_default_port + i;
		int status;

		server_cookie[i].port_nr = port_nr;
		sprintf(tmp, ":%d", port_nr);
		status = mars_create_sockaddr(&sockaddr, tmp);
		if (unlikely(status < 0)) {
			exit_mars_server();
			return status;
		}

		status = mars_create_socket(&server_cookie[i].server_socket,
					    &sockaddr,
					    server_cookie[i].server_params,
					    true);
		if (unlikely(status < 0)) {
			MARS_ERR("could not create server socket port=%d, status = %d\n",
				 port_nr, status);
			exit_mars_server();
			return status;
		}

		server_thread[i] = brick_thread_create(port_thread,
						       &server_cookie[i],
						       "mars_port:%d",
						       port_nr);
		if (unlikely(!server_thread[i] || IS_ERR(server_thread[i]))) {
			MARS_ERR("could not create server thread %d\n", i);
			exit_mars_server();
			return -ENOENT;
		}
	}

	return server_register_brick_type();
}
