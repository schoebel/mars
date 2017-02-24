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


// Client brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_client.h"

#define CLIENT_HASH_MAX (PAGE_SIZE / sizeof(struct list_head))

int mars_client_abort = 10;
EXPORT_SYMBOL_GPL(mars_client_abort);

///////////////////////// own helper functions ////////////////////////

static atomic_t sender_count = ATOMIC_INIT(0);

static int thread_count = 0;

static void _kill_thread(struct client_threadinfo *ti, const char *name)
{
	if (ti->thread) {
		MARS_DBG("stopping %s thread\n", name);
		brick_thread_stop(ti->thread);
		ti->thread = NULL;
	}
}

static void _kill_socket(struct client_output *output)
{
	output->brick->connection_state = 1;
	if (mars_socket_is_alive(&output->socket)) {
		MARS_DBG("shutdown socket\n");
		mars_shutdown_socket(&output->socket);
	}
	_kill_thread(&output->receiver, "receiver");
	output->recv_error = 0;
	MARS_DBG("close socket\n");
	mars_put_socket(&output->socket);
}

static int _request_info(struct client_output *output)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_GETINFO,
	};
	int status;
	
	MARS_DBG("\n");
	status = mars_send_struct(&output->socket, &cmd, mars_cmd_meta);
	if (unlikely(status < 0)) {
		MARS_DBG("send of getinfo failed, status = %d\n", status);
	}
	return status;
}

static int receiver_thread(void *data);

static int _connect(struct client_output *output, const char *str)
{
	struct sockaddr_storage sockaddr = {};
	int status;

	if (unlikely(!output->path)) {
		output->path = brick_strdup(str);
		status = -ENOMEM;
		if (!output->path) {
			MARS_DBG("no mem\n");
			goto done;
		}
		status = -EINVAL;
		output->host = strchr(output->path, '@');
		if (!output->host) {
			brick_string_free(output->path);
			output->path = NULL;
			MARS_ERR("parameter string '%s' contains no remote specifier with '@'-syntax\n", str);
			goto done;
		}
		*output->host++ = '\0';
	}

	if (unlikely(output->receiver.thread)) {
		MARS_WRN("receiver thread unexpectedly not dead\n");
		_kill_thread(&output->receiver, "receiver");
	}

	status = mars_create_sockaddr(&sockaddr, output->host);
	if (unlikely(status < 0)) {
		MARS_DBG("no sockaddr, status = %d\n", status);
		goto done;
	}
	
	status = mars_create_socket(&output->socket, &sockaddr, false);
	if (unlikely(status < 0)) {
		MARS_DBG("no socket, status = %d\n", status);
		goto really_done;
	}
	output->socket.s_shutdown_on_err = true;
	output->socket.s_send_abort = mars_client_abort;
	output->socket.s_recv_abort = mars_client_abort;

	output->receiver.thread = brick_thread_create(receiver_thread, output, "mars_receiver%d", thread_count++);
	if (unlikely(!output->receiver.thread)) {
		MARS_ERR("cannot start receiver thread, status = %d\n", status);
		status = -ENOENT;
		goto done;
	}


	{
		struct mars_cmd cmd = {
			.cmd_code = CMD_CONNECT,
			.cmd_str1 = output->path,
		};

		status = mars_send_struct(&output->socket, &cmd, mars_cmd_meta);
		if (unlikely(status < 0)) {
			MARS_DBG("send of connect failed, status = %d\n", status);
			goto done;
		}
	}
	if (status >= 0) {
		status = _request_info(output);
	}

done:
	if (status < 0) {
		MARS_INF("cannot connect to remote host '%s' (status = %d) -- retrying\n", output->host ? output->host : "NULL", status);
		_kill_socket(output);
	}
really_done:
	return status;
}

////////////////// own brick / input / output operations //////////////////

static int client_get_info(struct client_output *output, struct mars_info *info)
{
	int status;

	output->got_info = false;
	output->get_info = true;
	wake_up_interruptible(&output->event);
	
	wait_event_interruptible_timeout(output->info_event, output->got_info, 60 * HZ);
	status = -ETIME;
	if (output->got_info && info) {
		memcpy(info, &output->info, sizeof(*info));
		status = 0;
	}

//done:
	return status;
}

static int client_ref_get(struct client_output *output, struct mref_object *mref)
{
	int maxlen;

	if (mref->ref_initialized) {
		_mref_get(mref);
		return mref->ref_len;
	}

#if 1
	/* Limit transfers to page boundaries.
	 * Currently, this is more restrictive than necessary.
	 * TODO: improve performance by doing better when possible.
	 * This needs help from the server in some efficient way.
	 */
	maxlen = PAGE_SIZE - (mref->ref_pos & (PAGE_SIZE-1));
	if (mref->ref_len > maxlen)
		mref->ref_len = maxlen;
#endif

	if (!mref->ref_data) { // buffered IO
		struct client_mref_aspect *mref_a = client_mref_get_aspect(output->brick, mref);
		if (!mref_a)
			return -EILSEQ;

		mref->ref_data = brick_block_alloc(mref->ref_pos, (mref_a->alloc_len = mref->ref_len));
		if (!mref->ref_data)
			return -ENOMEM;

		mref_a->do_dealloc = true;
		mref->ref_flags = 0;
	}

	_mref_get_first(mref);
	return 0;
}

static void client_ref_put(struct client_output *output, struct mref_object *mref)
{
	struct client_mref_aspect *mref_a;
	if (!_mref_put(mref))
		return;
	mref_a = client_mref_get_aspect(output->brick, mref);
	if (mref_a && mref_a->do_dealloc) {
		brick_block_free(mref->ref_data, mref_a->alloc_len);
	}
	client_free_mref(mref);
}

static
void _hash_insert(struct client_output *output, struct client_mref_aspect *mref_a)
{
	struct mref_object *mref = mref_a->object;
	int hash_index;

	mutex_lock(&output->mutex);
	list_del(&mref_a->io_head);
	list_add_tail(&mref_a->io_head, &output->mref_list);
	list_del(&mref_a->hash_head);
	mref->ref_id = ++output->last_id;
	hash_index = mref->ref_id % CLIENT_HASH_MAX;
	list_add_tail(&mref_a->hash_head, &output->hash_table[hash_index]);
	mutex_unlock(&output->mutex);
}

static void client_ref_io(struct client_output *output, struct mref_object *mref)
{
	struct client_mref_aspect *mref_a;
	int error = -EINVAL;

	mref_a = client_mref_get_aspect(output->brick, mref);
	if (unlikely(!mref_a)) {
		goto error;
	}

	while (output->brick->max_flying > 0 && atomic_read(&output->fly_count) > output->brick->max_flying) {
		MARS_IO("sleeping request pos = %lld len = %d rw = %d (flying = %d)\n", mref->ref_pos, mref->ref_len, mref->ref_rw, atomic_read(&output->fly_count));
#ifdef IO_DEBUGGING
		brick_msleep(3000);
#else
		brick_msleep(1000 * 2 / HZ);
#endif
	}

	atomic_inc(&mars_global_io_flying);
	atomic_inc(&output->fly_count);
	_mref_get(mref);

	mref_a->submit_jiffies = jiffies;
	_hash_insert(output, mref_a);

	MARS_IO("added request id = %d pos = %lld len = %d rw = %d (flying = %d)\n", mref->ref_id, mref->ref_pos, mref->ref_len, mref->ref_rw, atomic_read(&output->fly_count));

	wake_up_interruptible(&output->event);

	return;

error:
	MARS_ERR("IO error = %d\n", error);
	SIMPLE_CALLBACK(mref, error);
	client_ref_put(output, mref);
}

static
int receiver_thread(void *data)
{
	struct client_output *output = data;
	int status = 0;

        while (!brick_thread_should_stop()) {
		struct mars_cmd cmd = {};
		struct list_head *tmp;
		struct client_mref_aspect *mref_a = NULL;
		struct mref_object *mref = NULL;

		if (output->recv_error) {
			/* The protocol may be out of sync.
			 * Consume some data to avoid distributed deadlocks.
			 */
			(void)mars_recv_raw(&output->socket, &cmd, 0, sizeof(cmd));
			wake_up_interruptible(&output->event);
			brick_msleep(100);
			status = output->recv_error;
			continue;
		}

		status = mars_recv_struct(&output->socket, &cmd, mars_cmd_meta);
		MARS_IO("got cmd = %d status = %d\n", cmd.cmd_code, status);
		if (status <= 0)
			goto done;

		switch (cmd.cmd_code & CMD_FLAG_MASK) {
		case CMD_NOTIFY:
			mars_trigger();
			break;
		case CMD_CONNECT:
			if (cmd.cmd_int1 < 0) {
				status = cmd.cmd_int1;
				MARS_ERR("at remote side: brick connect failed, remote status = %d\n", status);
				goto done;
			}
			break;
		case CMD_CB:
		{
			int hash_index = cmd.cmd_int1 % CLIENT_HASH_MAX;

			mutex_lock(&output->mutex);
			for (tmp = output->hash_table[hash_index].next; tmp != &output->hash_table[hash_index]; tmp = tmp->next) {
				struct mref_object *tmp_mref;
				mref_a = container_of(tmp, struct client_mref_aspect, hash_head);
				tmp_mref = mref_a->object;
				if (unlikely(!tmp_mref)) {
					mutex_unlock(&output->mutex);
					MARS_ERR("bad internal mref pointer\n");
					status = -EBADR;
					goto done;
				}
				if (tmp_mref->ref_id == cmd.cmd_int1) {
					mref = tmp_mref;
					list_del_init(&mref_a->hash_head);
					list_del_init(&mref_a->io_head);
					break;
				}
			}
			mutex_unlock(&output->mutex);

			if (unlikely(!mref)) {
				MARS_WRN("got unknown id = %d for callback\n", cmd.cmd_int1);
				status = -EBADR;
				goto done;
			}

			MARS_IO("got callback id = %d, old pos = %lld len = %d rw = %d\n", mref->ref_id, mref->ref_pos, mref->ref_len, mref->ref_rw);

			status = mars_recv_cb(&output->socket, mref, &cmd);
			MARS_IO("new status = %d, pos = %lld len = %d rw = %d\n", status, mref->ref_pos, mref->ref_len, mref->ref_rw);
			if (unlikely(status < 0)) {
				MARS_WRN("interrupted data transfer during callback, status = %d\n", status);
				_hash_insert(output, mref_a);
				goto done;
			}

			SIMPLE_CALLBACK(mref, mref->_object_cb.cb_error);

			client_ref_put(output, mref);

			atomic_dec(&output->fly_count);
			atomic_dec(&mars_global_io_flying);
			break;
		}
		case CMD_GETINFO:
			status = mars_recv_struct(&output->socket, &output->info, mars_info_meta);
			if (status < 0) {
				MARS_WRN("got bad info from remote side, status = %d\n", status);
				goto done;
			}
			output->got_info = true;
			wake_up_interruptible(&output->info_event);
			break;
		default:
			MARS_ERR("got bad command %d from remote side, terminating.\n", cmd.cmd_code);
			status = -EBADR;
			goto done;
		}
	done:
		brick_string_free(cmd.cmd_str1);
		if (unlikely(status < 0)) {
			if (!output->recv_error) {
				MARS_DBG("signalling status = %d\n", status);
				output->recv_error = status;
			}
			wake_up_interruptible(&output->event);
			brick_msleep(100);
		}
	}

	if (status < 0) {
		MARS_WRN("receiver thread terminated with status = %d, recv_error = %d\n", status, output->recv_error);
	}

	mars_shutdown_socket(&output->socket);
	wake_up_interruptible(&output->receiver.run_event);
	return status;
}

static
void _do_resubmit(struct client_output *output)
{
	mutex_lock(&output->mutex);
	if (!list_empty(&output->wait_list)) {
		struct list_head *first = output->wait_list.next;
		struct list_head *last = output->wait_list.prev;
		struct list_head *old_start = output->mref_list.next;
#define list_connect __list_del // the original routine has a misleading name: in reality it is more general
		list_connect(&output->mref_list, first);
		list_connect(last, old_start);
		INIT_LIST_HEAD(&output->wait_list);
		MARS_IO("done re-submit %p %p\n", first, last);
	}
	mutex_unlock(&output->mutex);
}

static
void _do_timeout(struct client_output *output, struct list_head *anchor, bool force)
{
	struct client_brick *brick = output->brick;
	struct list_head *tmp;
	struct list_head *next;
	LIST_HEAD(tmp_list);
	int rounds = 0;
	long io_timeout = brick->power.io_timeout;

	if (io_timeout <= 0)
		io_timeout = global_net_io_timeout;
	
	if (!mars_net_is_alive)
		force = true;
	
	if (!force && io_timeout <= 0) {
		output->socket.s_send_abort = mars_client_abort;
		output->socket.s_recv_abort = mars_client_abort;
		return;
	}

	output->socket.s_send_abort = 1;
	output->socket.s_recv_abort = 1;

	io_timeout *= HZ;
	
	mutex_lock(&output->mutex);
	for (tmp = anchor->next, next = tmp->next; tmp != anchor; tmp = next, next = tmp->next) {
		struct client_mref_aspect *mref_a;

		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		
		if (!force &&
		    !time_is_before_jiffies(mref_a->submit_jiffies + io_timeout)) {
			continue;
		}
		
		list_del_init(&mref_a->hash_head);
		list_del_init(&mref_a->io_head);
		list_add_tail(&mref_a->tmp_head, &tmp_list);
	}
	mutex_unlock(&output->mutex);

	while (!list_empty(&tmp_list)) {
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;
		
		tmp = tmp_list.next;
		list_del_init(tmp);
		mref_a = container_of(tmp, struct client_mref_aspect, tmp_head);
		mref = mref_a->object;

		if (!rounds++) {
			MARS_WRN("timeout after %ld: signalling IO error at pos = %lld len = %d\n",
				 io_timeout,
				 mref->ref_pos,
				 mref->ref_len);
		}

		atomic_inc(&output->timeout_count);

		SIMPLE_CALLBACK(mref, -ETIME);

		client_ref_put(output, mref);

		atomic_dec(&output->fly_count);
		atomic_dec(&mars_global_io_flying);
	}
}

static int sender_thread(void *data)
{
	struct client_output *output = data;
	struct client_brick *brick = output->brick;
	bool do_kill = false;
	int status = 0;

	output->receiver.restart_count = 0;

	if (atomic_inc_return(&sender_count) == 1)
		mars_limit_reset(&client_limiter);

        while (brick->power.button && !brick_thread_should_stop()) {
		struct list_head *tmp = NULL;
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;

		if (brick->power.io_timeout > 0) {
			_do_timeout(output, &output->wait_list, false);
			_do_timeout(output, &output->mref_list, false);
		}

		if (unlikely(output->recv_error != 0 || !mars_socket_is_alive(&output->socket))) {
			MARS_DBG("recv_error = %d do_kill = %d\n", output->recv_error, do_kill);
			if (do_kill) {
				do_kill = false;
				_kill_socket(output);
				brick_msleep(3000);
			}

			status = _connect(output, brick->brick_name);
			MARS_IO("connect status = %d\n", status);
			if (unlikely(status < 0)) {
				brick_msleep(3000);
				_do_timeout(output, &output->wait_list, false);
				_do_timeout(output, &output->mref_list, false);
				continue;
			}
			brick->connection_state = 2;
			do_kill = true;
			/* Re-Submit any waiting requests
			 */
			MARS_IO("re-submit\n");
			_do_resubmit(output);
		}
		
		wait_event_interruptible_timeout(output->event,
						 !list_empty(&output->mref_list) ||
						 output->get_info ||
						 output->recv_error != 0 ||
						 !brick->power.button ||
						 brick_thread_should_stop(),
						 1 * HZ);

		if (unlikely(!brick->power.button || brick_thread_should_stop()))
			break;

		if (unlikely(output->recv_error != 0)) {
			MARS_DBG("recv_error = %d\n", output->recv_error);
			brick_msleep(1000);
			continue;
		}
		
		if (output->get_info) {
			status = _request_info(output);
			if (status >= 0) {
				output->get_info = false;
			} else {
				MARS_WRN("cannot get info, status = %d\n", status);
				brick_msleep(1000);
			}
		}

		/* Grab the next mref from the queue
		 */
		mutex_lock(&output->mutex);
		if (list_empty(&output->mref_list)) {
			mutex_unlock(&output->mutex);
			continue;
		}
		tmp = output->mref_list.next;
		list_del(tmp);
		list_add(tmp, &output->wait_list);
		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		mutex_unlock(&output->mutex);

		mref = mref_a->object;

		if (brick->limit_mode) {
			int amount = 0;
			if (mref->ref_cs_mode < 2)
				amount = (mref->ref_len - 1) / 1024 + 1;
			mars_limit_sleep(&client_limiter, amount);
		}

		MARS_IO("sending mref, id = %d pos = %lld len = %d rw = %d\n", mref->ref_id, mref->ref_pos, mref->ref_len, mref->ref_rw);

		status = mars_send_mref(&output->socket, mref);
		MARS_IO("status = %d\n", status);
		if (unlikely(status < 0)) {
			// retry submission on next occasion..
			MARS_WRN("sending failed, status = %d\n", status);

			if (do_kill) {
				do_kill = false;
				_kill_socket(output);
			}
			_hash_insert(output, mref_a);
			brick_msleep(1000);
			continue;
		}
	}
//done:
	if (status < 0) {
		MARS_WRN("sender thread terminated with status = %d\n", status);
	}

	if (do_kill) {
		_kill_socket(output);
	}

	/* Signal error on all pending IO requests.
	 * We have no other chance (except probably delaying
	 * this until destruction which is probably not what
	 * we want).
	 */
	_do_timeout(output, &output->wait_list, true);
	_do_timeout(output, &output->mref_list, true);

	if (!atomic_dec_return(&sender_count))
		mars_limit_reset(&client_limiter);

	wake_up_interruptible(&output->sender.run_event);
	MARS_DBG("sender terminated\n");
	return status;
}

static int client_switch(struct client_brick *brick)
{
	struct client_output *output = brick->outputs[0];
	int status = 0;

	if (brick->power.button) {
		if (brick->power.led_on)
			goto done;
		mars_power_led_off((void*)brick, false);
		if (!output->sender.thread) {
			brick->connection_state = 1;
			output->sender.thread = brick_thread_create(sender_thread, output, "mars_sender%d", thread_count++);
			if (unlikely(!output->sender.thread)) {
				MARS_ERR("cannot start sender thread\n");
				status = -ENOENT;
				goto done;
			}
		}
		if (output->sender.thread) {
			mars_power_led_on((void*)brick, true);
		}
	} else {
		if (brick->power.led_off)
			goto done;
		mars_power_led_on((void*)brick, false);
		_kill_thread(&output->sender, "sender");
		brick->connection_state = 0;
		if (!output->sender.thread) {
			mars_power_led_off((void*)brick, !output->sender.thread);
		}
	}
done:
	return status;
}


//////////////// informational / statistics ///////////////

static
char *client_statistics(struct client_brick *brick, int verbose)
{
	struct client_output *output = brick->outputs[0];
	char *res = brick_string_alloc(1024);
        if (!res)
                return NULL;

	snprintf(res, 1024,
		 "#%d socket "
		 "max_flying = %d "
		 "io_timeout = %d | "
		 "timeout_count = %d "
		 "fly_count = %d\n",
		 output->socket.s_debug_nr,
		 brick->max_flying,
		 brick->power.io_timeout,
		 atomic_read(&output->timeout_count),
		 atomic_read(&output->fly_count));
	
        return res;
}

static
void client_reset_statistics(struct client_brick *brick)
{
	struct client_output *output = brick->outputs[0];
	atomic_set(&output->timeout_count, 0);
}

//////////////// object / aspect constructors / destructors ///////////////

static int client_mref_aspect_init_fn(struct generic_aspect *_ini)
{
	struct client_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	INIT_LIST_HEAD(&ini->hash_head);
	INIT_LIST_HEAD(&ini->tmp_head);
	return 0;
}

static void client_mref_aspect_exit_fn(struct generic_aspect *_ini)
{
	struct client_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->io_head);
	CHECK_HEAD_EMPTY(&ini->hash_head);
}

MARS_MAKE_STATICS(client);

////////////////////// brick constructors / destructors ////////////////////

static int client_brick_construct(struct client_brick *brick)
{
	return 0;
}

static int client_output_construct(struct client_output *output)
{
	int i;

	output->hash_table = brick_block_alloc(0, PAGE_SIZE);
	if (unlikely(!output->hash_table)) {
		MARS_ERR("cannot allocate hash table\n");
		return -ENOMEM;
	}

	for (i = 0; i < CLIENT_HASH_MAX; i++) {
		INIT_LIST_HEAD(&output->hash_table[i]);
	}
	mutex_init(&output->mutex);
	INIT_LIST_HEAD(&output->mref_list);
	INIT_LIST_HEAD(&output->wait_list);
	init_waitqueue_head(&output->event);
	init_waitqueue_head(&output->sender.run_event);
	init_waitqueue_head(&output->receiver.run_event);
	init_waitqueue_head(&output->info_event);
	return 0;
}

static int client_output_destruct(struct client_output *output)
{
	if (output->path) {
		brick_string_free(output->path);
		output->path = NULL;
	}
	brick_block_free(output->hash_table, PAGE_SIZE);
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct client_brick_ops client_brick_ops = {
	.brick_switch = client_switch,
        .brick_statistics = client_statistics,
        .reset_statistics = client_reset_statistics,
};

static struct client_output_ops client_output_ops = {
	.mars_get_info = client_get_info,
	.mref_get = client_ref_get,
	.mref_put = client_ref_put,
	.mref_io = client_ref_io,
};

const struct client_input_type client_input_type = {
	.type_name = "client_input",
	.input_size = sizeof(struct client_input),
};

static const struct client_input_type *client_input_types[] = {
	&client_input_type,
};

const struct client_output_type client_output_type = {
	.type_name = "client_output",
	.output_size = sizeof(struct client_output),
	.master_ops = &client_output_ops,
	.output_construct = &client_output_construct,
	.output_destruct = &client_output_destruct,
};

static const struct client_output_type *client_output_types[] = {
	&client_output_type,
};

const struct client_brick_type client_brick_type = {
	.type_name = "client_brick",
	.brick_size = sizeof(struct client_brick),
	.max_inputs = 0,
	.max_outputs = 1,
	.master_ops = &client_brick_ops,
	.aspect_types = client_aspect_types,
	.default_input_types = client_input_types,
	.default_output_types = client_output_types,
	.brick_construct = &client_brick_construct,
};
EXPORT_SYMBOL_GPL(client_brick_type);

////////////////// module init stuff /////////////////////////

struct mars_limiter client_limiter = {
	.lim_max_rate = 0,
};
EXPORT_SYMBOL_GPL(client_limiter);

int global_net_io_timeout = CONFIG_MARS_NETIO_TIMEOUT;
EXPORT_SYMBOL_GPL(global_net_io_timeout);

int __init init_mars_client(void)
{
	MARS_INF("init_client()\n");
	_client_brick_type = (void*)&client_brick_type;
	return client_register_brick_type();
}

void exit_mars_client(void)
{
	MARS_INF("exit_client()\n");
	client_unregister_brick_type();
}
