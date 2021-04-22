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


//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/jiffies.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_client.h"

#define CLIENT_HASH_MAX (PAGE_SIZE / sizeof(struct list_head))

#define CLIENT_HASH_FN(x)			\
	((unsigned long)(x) % CLIENT_HASH_MAX)

int mars_client_info_timeout = 0;

int mars_client_abort = 10;

int max_client_channels = 2;

int max_client_bulk = 16;

///////////////////////// own helper functions ////////////////////////

static atomic_t sender_count = ATOMIC_INIT(0);

static int thread_count = 0;

static
void _do_resubmit(struct client_channel *ch)
{
	struct client_output *output = ch->output;

	mutex_lock(&output->mutex);
	if (!list_empty(&ch->wait_list)) {
		struct list_head *first = ch->wait_list.next;
		struct list_head *last = ch->wait_list.prev;
		struct list_head *old_start = output->mref_list.next;
#define list_connect __list_del // the original routine has a misleading name: in reality it is more general
		list_connect(&output->mref_list, first);
		list_connect(last, old_start);
		INIT_LIST_HEAD(&ch->wait_list);
	}
	mutex_unlock(&output->mutex);
}

static
void _kill_thread(struct client_threadinfo *ti, const char *name)
{
	struct task_struct *thread = ti->thread;
	if (thread) {
		MARS_DBG("stopping %s thread\n", name);
		ti->thread = NULL;
		brick_thread_stop(thread);
	}
}

static
void _kill_channel(struct client_channel *ch)
{
	MARS_DBG("channel = %p\n", ch);
	if (mars_socket_is_alive(&ch->socket)) {
		MARS_DBG("shutdown socket\n");
		mars_shutdown_socket(&ch->socket);
	}
	_kill_thread(&ch->receiver, "receiver");
	if (ch->is_open) {
		MARS_DBG("close socket\n");
		mars_put_socket(&ch->socket);
	}
	ch->recv_error = 0;
	ch->is_used = false;
	ch->is_open = false;
	ch->is_connected = false;
	/* Re-Submit any waiting requests
	 */
	_do_resubmit(ch);
}

static inline
void _kill_all_channels(struct client_bundle *bundle)
{
	int i;
	// first pass: shutdown in parallel without waiting
	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		struct client_channel *ch =&bundle->channel[i];
		if (mars_socket_is_alive(&ch->socket)) {
			MARS_DBG("shutdown socket %d\n", i);
			mars_shutdown_socket(&ch->socket);
		}
	}
	// separate pass (may wait)
	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		_kill_channel(&bundle->channel[i]);
	}
}

static
int receiver_thread(void *data);

static
int _setup_channel(struct client_bundle *bundle, int ch_nr)
{
	struct client_channel *ch = &bundle->channel[ch_nr];
	struct sockaddr_storage sockaddr = {};
	int status;

	ch->ch_nr = ch_nr;
	if (unlikely(ch->receiver.thread)) {
		MARS_WRN("receiver thread %d unexpectedly not dead\n", ch_nr);
		_kill_thread(&ch->receiver, "receiver");
	}

	status = mars_create_sockaddr(&sockaddr, bundle->host);
	if (unlikely(status < 0)) {
		MARS_DBG("no sockaddr, status = %d\n", status);
		goto done;
	}

	if (!bundle->params) {
		struct sockaddr_in *_sockaddr = (void*)&sockaddr;

		int offset = (int)ntohs(_sockaddr->sin_port) - mars_net_default_port;

		if (offset < 0 || offset >= MARS_TRAFFIC_MAX)
			offset = 0;
		bundle->params = &mars_tcp_params[offset];
	}

	status = mars_create_socket(&ch->socket,
				    &sockaddr,
				    bundle->params,
				    false);
	if (unlikely(status < 0)) {
		MARS_DBG("no socket, status = %d\n", status);
		goto really_done;
	}
	ch->socket.s_shutdown_on_err = true;
	ch->socket.s_send_abort = mars_client_abort;
	ch->socket.s_recv_abort = mars_client_abort;
	ch->is_open = true;

	ch->receiver.thread = brick_thread_create(receiver_thread, ch, "mars_receiver%d.%d.%d", bundle->thread_count, ch_nr, ch->thread_count++);
	if (unlikely(!ch->receiver.thread)) {
		MARS_ERR("cannot start receiver thread %d, status = %d\n", ch_nr, status);
		status = -ENOENT;
		goto done;
	}
	ch->is_used = true;

done:
	if (status < 0) {
		MARS_INF("cannot connect channel %d to remote host '%s' (status = %d) -- retrying\n",
			 ch_nr,
			 bundle->host ? bundle->host : "NULL",
			 status);
		_kill_channel(ch);
	}

really_done:
	return status;
}

static
void _kill_bundle(struct client_bundle *bundle)
{
	MARS_DBG("\n");
	_kill_thread(&bundle->sender, "sender");
	_kill_all_channels(bundle);
}

static
void _maintain_bundle(struct client_bundle *bundle)
{
	int i;

	/* Re-open _any_ failed channel, even old ones.
	 * Reason: the number of channels might change during operation.
	 */
	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		struct client_channel *ch = &bundle->channel[i];

		if (!ch->is_used ||
		    (!ch->recv_error && mars_socket_is_alive(&ch->socket)))
			continue;

		MARS_DBG("killing channel %d\n", i);
		_kill_channel(ch);
		/* Re-setup including connect optiona is done later.
		 */
	}
}

static
struct client_channel *_get_channel(struct client_bundle *bundle, int min_channel, int max_channel)
{
	struct client_channel *res;
	long best_space;
	int best_channel;
	int i;

	if (unlikely(max_channel <= 0 || max_channel > MAX_CLIENT_CHANNELS))
		max_channel = MAX_CLIENT_CHANNELS;
	if (unlikely(min_channel < 0 || min_channel >= max_channel)) {
		min_channel = max_channel - 1;
		if (unlikely(min_channel < 0))
			min_channel = 0;
	}

	/* Fast path.
	 * Speculate that the next channel is already usable,
	 * and that it has enough room.
	 */
	best_channel = bundle->old_channel + 1;
	if (best_channel >= max_channel)
		best_channel = min_channel;
	res = &bundle->channel[best_channel];
	if (res->is_connected && !res->recv_error && mars_socket_is_alive(&res->socket)) {
		res->current_space = mars_socket_send_space_available(&res->socket);
		if (res->current_space > (PAGE_SIZE + PAGE_SIZE / 4))
			goto found;
	}

	/* Slow path. Do all the teady work.
	 */
	_maintain_bundle(bundle);

	res = NULL;
	best_space = -1;
	best_channel = -1;
	for (i = min_channel; i < max_channel; i++) {
		struct client_channel *ch = &bundle->channel[i];
		long this_space;

		// create new channels when necessary
		if (unlikely(!ch->is_open)) {
			int status;
			// only create one new channel at a time
			status = _setup_channel(bundle, i);
			MARS_DBG("setup channel %d status=%d\n", i, status);
			if (unlikely(status < 0))
				continue;

			this_space = mars_socket_send_space_available(&ch->socket);
			ch->current_space = this_space;
			/* Always prefer the newly opened channel */
			res = ch;
			best_channel = i;
			break;
		}

		// select the best usable channel
		this_space = mars_socket_send_space_available(&ch->socket);
		ch->current_space = this_space;
		if (this_space > best_space) {
			best_space = this_space;
			best_channel = i;
			res = ch;
		}
	}

	if (unlikely(!res)) {
		MARS_WRN("cannot setup communication channel '%s' @%s\n",
			 bundle->path,
			 bundle->host);
		goto done;
	}

	// send initial connect command
	if (unlikely(!res->is_connected)) {
		struct mars_cmd cmd = {
			.cmd_code = CMD_CONNECT,
			.cmd_str1 = bundle->path,
		};
		int status = mars_send_cmd(&res->socket, &cmd, false);
		MARS_DBG("send CMD_CONNECT status = %d\n", status);
		if (unlikely(status < 0)) {
			MARS_WRN("connect '%s' @%s on channel %d failed, status = %d\n",
				 bundle->path,
				 bundle->host,
				 best_channel,
				 status);
			_kill_channel(res);
			res = NULL;
			goto done;
		}
		res->is_connected = true;
	}

found:
	bundle->old_channel = best_channel;

 done:
	return res;
}

static
int _request_info(struct client_channel *ch)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_GETINFO,
	};
	int status;
	
	MARS_DBG("\n");
	status = mars_send_cmd(&ch->socket, &cmd, false);
	MARS_DBG("send CMD_GETINFO status = %d\n", status);
	if (unlikely(status < 0)) {
		MARS_DBG("send of getinfo failed, status = %d\n", status);
	}
	return status;
}

static int sender_thread(void *data);

static
int _setup_bundle(struct client_bundle *bundle, const char *str)
{
	int status = -ENOMEM;

	MARS_DBG("\n");
	_kill_bundle(bundle);
	brick_string_free(bundle->path);

	bundle->path = brick_strdup(str);

	status = -EINVAL;
	bundle->host = strchr(bundle->path, '@');
	if (unlikely(!bundle->host)) {
		brick_string_free(bundle->path);
		MARS_ERR("parameter string '%s' contains no remote specifier with '@'-syntax\n", str);
		goto done;
	}
	*bundle->host++ = '\0';

	bundle->thread_count = thread_count++;
	bundle->sender.thread = brick_thread_create(sender_thread, bundle, "mars_sender%d", bundle->thread_count);
	if (unlikely(!bundle->sender.thread)) {
		MARS_ERR("cannot start sender thread for '%s' @%s\n",
			 bundle->path,
			 bundle->host);
		status = -ENOENT;
		goto done;
	}

	status = 0;

done:
	MARS_DBG("status = %d\n", status);
	return status;
}

static
long _compute_timeout(struct client_brick *brick, bool for_info)
{
	long io_timeout = brick->power.io_timeout;

	if (io_timeout <= 0)
		io_timeout = global_net_io_timeout;
	if (for_info && io_timeout > mars_client_info_timeout)
		io_timeout = mars_client_info_timeout;
	
	return io_timeout;
}

////////////////// own brick / input / output operations //////////////////

static int client_get_info(struct client_output *output, struct mars_info *info)
{
	struct client_brick *brick = output->brick;
	long io_timeout = _compute_timeout(brick, true);
	int status;

	if (!brick->power.led_on) {
		if (output->got_info)
			return 0;
		output->get_info = true;
		wake_up_interruptible_all(&output->bundle.sender_event);
		goto timeout;
	}

	output->get_info = true;
	wake_up_interruptible_all(&output->bundle.sender_event);
	
	wait_event_interruptible_timeout(output->info_event, output->got_info, io_timeout * HZ);
timeout:
	status = -ETIME;
	if (output->got_info) {
		status = 0;
		if (info) {
			memcpy(info, &output->info, sizeof(*info));
			output->got_info = false;
			output->get_info = true;
		}
	}
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
void _hash_insert(struct client_output *output,
		  struct client_mref_aspect *mref_a,
		  bool refresh_completed)
{
	struct mref_object *mref = mref_a->object;
	int ref_id;
	unsigned int hash_index;

	mutex_lock(&output->mutex);
	if (refresh_completed)
		mref_a->has_completed = false;
	list_del(&mref_a->io_head);
	list_add_tail(&mref_a->io_head, &output->mref_list);
	list_del(&mref_a->hash_head);
	ref_id = READ_ONCE(mref->ref_id);
	while (!ref_id) {
		/* This may wrap around without harm */
		ref_id = READ_ONCE(output->last_id) + 1;
		WRITE_ONCE(output->last_id, ref_id);
		WRITE_ONCE(mref->ref_id, ref_id);
	}
	hash_index = CLIENT_HASH_FN(ref_id);
	list_add_tail(&mref_a->hash_head, &output->hash_table[hash_index]);
	mutex_unlock(&output->mutex);
}

static void client_ref_io(struct client_output *output, struct mref_object *mref)
{
	struct client_brick *brick = output->brick;
	struct client_mref_aspect *mref_a;
	int error = -EINVAL;

	mref_a = client_mref_get_aspect(brick, mref);
	if (unlikely(!mref_a))
		goto fatal;

	while (brick->max_flying > 0 &&
	       atomic_read(&brick->fly_count) > brick->max_flying) {
		MARS_IO("sleeping request pos = %lld len = %d flags = %ux (flying = %d)\n",
			mref->ref_pos, mref->ref_len, mref->ref_flags,
			atomic_read(&output->fly_count));
#ifdef IO_DEBUGGING
		brick_msleep(3000);
#else
		brick_msleep(1000 * 2 / HZ);
#endif
	}

	if (!(brick->power.led_on & brick->power.button))
		goto error;

	atomic_inc(&mars_global_io_flying);
	atomic_inc(&brick->fly_count);
	_mref_get(mref);

	mref_a->submit_jiffies = jiffies;

	_hash_insert(output, mref_a, true);

	MARS_IO("added request id = %d pos = %lld len = %d flags = %ux (flying = %d)\n",
		mref->ref_id, mref->ref_pos, mref->ref_len, mref->ref_flags,
		atomic_read(&output->fly_count));

	wake_up_interruptible_all(&output->bundle.sender_event);

	return;

error:
	MARS_ERR("IO submission on dead instance\n");
	mref_a->has_completed = true;
	error = -ESHUTDOWN;
	SIMPLE_CALLBACK(mref, error);
	return;

 fatal:
	MARS_ERR("FATAL error = %d\n", error);
}

static
int receiver_thread(void *data)
{
	struct client_channel *ch = data;
	struct client_output *output = ch->output;
	struct client_brick *brick = output->brick;
	int status = 0;

	atomic_inc(&brick->receiver_count);
        while (brick->power.button && !brick_thread_should_stop()) {
		struct mars_cmd cmd = {};
		struct list_head *tmp;

		if (ch->recv_error) {
			/* The protocol may be out of sync.
			 * Consume some data to avoid distributed deadlocks.
			 */
			(void)mars_recv_raw(&ch->socket, &cmd, 0, sizeof(cmd));
			brick_msleep(100);
			status = ch->recv_error;
			continue;
		}

		status = mars_recv_cmd(&ch->socket, &cmd);
		MARS_IO("got cmd = %d status = %d\n", cmd.cmd_code, status);
		if (status <= 0) {
			if (brick->power.button &&
			    !mars_socket_is_alive(&ch->socket)) {
				MARS_DBG("socket is dead\n");
				brick_msleep(1000);
				continue;
			}
			goto done;
		}

		switch (cmd.cmd_code & CMD_FLAG_MASK) {
		case CMD_NOP:
			break;
		case CMD_NOTIFY:
			mars_trigger();
			break;
		case CMD_CONNECT:
			if (cmd.cmd_int1 < 0) {
				status = cmd.cmd_int1;
				MARS_ERR("remote brick connect '%s' @%s failed, remote status = %d\n",
					 output->bundle.path,
					 output->bundle.host,
					 status);
				goto done;
			}
			break;
		case CMD_CB:
		{
			struct mref_object *mref = NULL;
			struct client_mref_aspect *mref_a = NULL;
			unsigned long id = READ_ONCE(cmd.cmd_int1);
			unsigned int hash_index = CLIENT_HASH_FN(id);
			bool had_completed = false;

			mutex_lock(&output->mutex);
			for (tmp = output->hash_table[hash_index].next; tmp != &output->hash_table[hash_index]; tmp = tmp->next) {
				struct mref_object *tmp_mref;
				struct client_mref_aspect *tmp_mref_a;

				tmp_mref_a = container_of(tmp, struct client_mref_aspect, hash_head);
				/* Treat any non-members of io lists as absent.
				 * This may happen during re-assignment to another io list.
				 */
				if (unlikely(list_empty(&tmp_mref_a->io_head)))
					continue;

				tmp_mref = tmp_mref_a->object;
				CHECK_PTR(tmp_mref, err);
				if (READ_ONCE(tmp_mref->ref_id) != cmd.cmd_int1)
					continue;

				mref_a = tmp_mref_a;
				mref = tmp_mref;
				list_del_init(&mref_a->hash_head);
				list_del_init(&mref_a->io_head);
				/* Networking produces inherent races between re-submission and
				 * completion. Compensate them here.
				 */
				had_completed = mref_a->has_completed;
				mref_a->has_completed = true;
				break;

			err:
				mutex_unlock(&output->mutex);
				status = -EBADR;
				goto done;
			}
			mutex_unlock(&output->mutex);

			if (unlikely(!mref || !mref_a)) {
				MARS_WRN("got unknown callback id %d on '%s' @%s\n",
					 cmd.cmd_int1,
					 output->bundle.path,
					 output->bundle.host);
				// try to consume the corresponding payload
				mref = client_alloc_mref(output->brick);
				status = mars_recv_cb(&ch->socket, mref, &cmd);
				client_free_mref(mref);
				goto done;
			}

			MARS_IO("got callback id = %d, old pos = %lld len = %d flags = %ux\n",
				mref->ref_id, mref->ref_pos, mref->ref_len,
				mref->ref_flags);

			status = mars_recv_cb(&ch->socket, mref, &cmd);
			MARS_IO("new status = %d, pos = %lld len = %d flags = %ux\n",
				status, mref->ref_pos, mref->ref_len,
				mref->ref_flags);
			if (unlikely(status < 0)) {
				MARS_WRN("interrupted data transfer during callback on '%s' @%s, status = %d\n",
					 output->bundle.path,
					 output->bundle.host,
					 status);
				if (had_completed)
					goto has_finished;
				_hash_insert(output, mref_a, true);
				goto done;
			}

			if (mref->_object_cb.cb_error < 0) {
				MARS_DBG("ERROR %d\n", mref->_object_cb.cb_error);
			}
			if (!had_completed) {
				SIMPLE_CALLBACK(mref, mref->_object_cb.cb_error);
			}

		has_finished:
			client_ref_put(output, mref);

			atomic_dec(&output->brick->fly_count);
			atomic_dec(&mars_global_io_flying);
			break;
		}
		case CMD_GETINFO:
			status = mars_recv_struct(&ch->socket, &output->info, mars_info_meta);
			if (status < 0) {
				MARS_WRN("got bad info from remote '%s' @%s, status = %d\n",
					 output->bundle.path,
					 output->bundle.host,
					 status);
				goto done;
			}
			output->got_info = true;
			wake_up_interruptible_all(&output->info_event);
			break;
		default:
			MARS_ERR("got bad command %d from remote '%s' @%s, terminating.\n",
				 cmd.cmd_code,
				 output->bundle.path,
				 output->bundle.host);
			status = -EBADR;
			goto done;
		}
	done:
		brick_string_free(cmd.cmd_str1);
		brick_string_free(cmd.cmd_str2);
		if (unlikely(status < 0)) {
			if (!ch->recv_error) {
				MARS_DBG("signalling recv_error = %d\n", status);
				ch->recv_error = status;
			}
			brick_msleep(100);
		}
		// wake up sender in any case
		wake_up_interruptible_all(&output->bundle.sender_event);
	}

	if (unlikely(status < 0)) {
		MARS_WRN("receiver thread '%s' @%s terminated with status = %d\n",
			 output->bundle.path,
			 output->bundle.host,
			 status);
	}

	mars_shutdown_socket(&ch->socket);
	atomic_dec(&brick->receiver_count);
	mars_trigger();
	return status;
}

static
void _do_timeout(struct client_output *output, struct list_head *anchor, int *rounds, bool force)
{
	struct client_brick *brick = output->brick;
	struct list_head *tmp;
	struct list_head *prev;
	LIST_HEAD(tmp_list);
	long io_timeout = _compute_timeout(brick, false);
	int i;

	if (list_empty(anchor))
		return;

	if (!mars_net_is_alive)
		force = true;
	
	if (!force && io_timeout <= 0) {
		for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
			struct client_channel *ch = &output->bundle.channel[i];

			ch->socket.s_send_abort = mars_client_abort;
			ch->socket.s_recv_abort = mars_client_abort;
		}
		return;
	}

	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		struct client_channel *ch = &output->bundle.channel[i];

		ch->socket.s_send_abort = 1;
		ch->socket.s_recv_abort = 1;
	}

	io_timeout *= HZ;
	
	mutex_lock(&output->mutex);
	for (tmp = anchor->prev, prev = tmp->prev; tmp != anchor; tmp = prev, prev = tmp->prev) {
		struct client_mref_aspect *mref_a;

		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		
		if (!force &&
		    !time_is_before_jiffies(mref_a->submit_jiffies + io_timeout)) {
			break;
		}
		/* Race compensation: skip already completed requests */
		if (mref_a->has_completed)
			continue;
		
		list_del_init(&mref_a->hash_head);
		list_del_init(&mref_a->io_head);
		mref_a->has_completed = true;
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

		if (unlikely(!(*rounds)++)) {
			MARS_WRN("'%s' @%s timeout after %ld: signalling IO error at pos = %lld len = %d\n",
				 output->bundle.path,
				 output->bundle.host,
				 io_timeout,
				 mref->ref_pos,
				 mref->ref_len);
		}

		atomic_inc(&brick->timeout_count);

		SIMPLE_CALLBACK(mref, -ETIME);

		client_ref_put(output, mref);

		atomic_dec(&brick->fly_count);
		atomic_dec(&mars_global_io_flying);
	}
}

static
void _do_timeout_all(struct client_output *output, bool force)
{
	int rounds = 0;
	int i;
	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		struct client_channel *ch = &output->bundle.channel[i];

		if (!ch->is_used)
			continue;
		_do_timeout(output, &ch->wait_list, &rounds, force);
	}
	_do_timeout(output, &output->mref_list, &rounds, force);
	if (unlikely(rounds > 0)) {
		MARS_WRN("'%s' @%s had %d timeouts, force = %d\n",
			 output->bundle.path,
			 output->bundle.host,
			 rounds,
			 force);
	}
}

static int sender_thread(void *data)
{
	struct client_bundle *bundle = data;
	struct client_output *output = container_of(bundle, struct client_output, bundle);
	struct client_brick *brick = output->brick;
	struct client_channel *ch = NULL;
	bool do_timeout = false;
	bool cork = false;
	bool old_cork = false;
	int ch_skip = max_client_bulk;
	int status = -ESHUTDOWN;

	if (atomic_inc_return(&sender_count) == 1)
		mars_limit_reset(&client_limiter);
	atomic_inc(&brick->sender_count);

        while (brick->power.button && !brick_thread_should_stop()) {
		struct list_head *tmp = NULL;
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;
		int min_nr;
		int max_nr;

		// timeouting is a rather expensive operation, don't do it too often
		if (do_timeout) {
			do_timeout = false;
			_maintain_bundle(&output->bundle);
			_do_timeout_all(output, false);
		}

		wait_event_interruptible_timeout(output->bundle.sender_event,
						 !list_empty(&output->mref_list) ||
						 output->get_info,
						 2 * HZ);


		if (output->get_info) {
			if (ch && old_cork) {
				/* flush old buffer */
				old_cork = false;
				mars_send_raw(&ch->socket, NULL, 0, false);
			}
			ch = _get_channel(bundle, 0, 1);
			if (unlikely(!ch)) {
				do_timeout = true;
				brick_msleep(1000);
				continue;
			}
			status = _request_info(ch);
			if (unlikely(status < 0)) {
				MARS_WRN("cannot send info request '%s' @%s, status = %d\n",
					 output->bundle.path,
					 output->bundle.host,
					 status);
				do_timeout = true;
				brick_msleep(1000);
				continue;
			}
			output->get_info = false;
		}

		/* Grab the next mref from the queue
		 */
		mutex_lock(&output->mutex);
		tmp = output->mref_list.next;
		if (tmp == &output->mref_list) {
			mutex_unlock(&output->mutex);
			MARS_DBG("empty %d %d\n", output->get_info, brick_thread_should_stop());
			do_timeout = true;
			continue;
		}
		list_del_init(tmp);
		// notice: hash_head remains in its list!
		cork = !list_empty(&output->mref_list);
		mutex_unlock(&output->mutex);

		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		mref = mref_a->object;

		/* Limiting is not inteded for production, only for testing */
		if (brick->limit_mode) {
			int amount = (mref->ref_len - 1) / 1024 + 1;

			mars_limit_sleep(&client_limiter, amount);
		}

		// try to spread reads over multiple channels....
		min_nr = 0;
		max_nr = max_client_channels;
		if (!(mref->ref_flags & MREF_WRITE)) {
			/* optionally separate reads from writes */
			if (brick->separate_reads && max_nr > 1)
				min_nr = 1;
		} else if (!brick->allow_permuting_writes) {
			max_nr = 1;
		}
		if (!ch || ch->recv_error ||
		    !mars_socket_is_alive(&ch->socket))
			do_timeout = true;
		if (do_timeout || ch->ch_nr >= max_nr || --ch_skip < 0) {
			if (ch && old_cork) {
				/* flush old buffer */
				old_cork = false;
				mars_send_raw(&ch->socket, NULL, 0, false);
			}
			ch = _get_channel(bundle, min_nr, max_nr);
			if (unlikely(!ch)) {
				// notice: this will re-assign hash_head without harm
				_hash_insert(output, mref_a, false);
				brick_msleep(1000);
				continue;
			}
			/* estimate: add some headroom for overhead */
			ch_skip = ch->current_space / PAGE_SIZE +
				ch->current_space / (PAGE_SIZE * 8);
			if (ch_skip > max_client_bulk)
				ch_skip = max_client_bulk;
		}

		mutex_lock(&output->mutex);
		list_add_tail(tmp, &ch->wait_list);
		// notice: hash_head is already there!
		mutex_unlock(&output->mutex);

		mref->ref_flags |= enabled_net_compressions;

		status = mars_send_mref(&ch->socket, mref, cork);
		old_cork = cork;
		if (unlikely(status < 0)) {
			_hash_insert(output, mref_a, false);
			do_timeout = true;
			ch = NULL;
			// retry submission on next occasion..
			MARS_WRN("mref send '%s' @%s failed, status = %d\n",
				 output->bundle.path,
				 output->bundle.host,
				 status);

			brick_msleep(100);
			continue;
		}
	}

	if (unlikely(status < 0)) {
		MARS_WRN("sender thread '%s' @%s terminated with status = %d\n",
			 output->bundle.path,
			 output->bundle.host,
			 status);
	}

	_kill_all_channels(bundle);

	/* Signal error on all pending IO requests.
	 * We have no other chance (except probably delaying
	 * this until destruction which is probably not what
	 * we want).
	 */
	_do_timeout_all(output, true);

	if (!atomic_dec_return(&sender_count))
		mars_limit_reset(&client_limiter);

	wake_up_interruptible_all(&output->bundle.sender_event);
	MARS_DBG("sender terminated\n");
	atomic_dec(&brick->sender_count);
	return status;
}

static int client_switch(struct client_brick *brick)
{
	struct client_output *output = brick->outputs[0];
	int status = 0;

	if (brick->power.button) {
		int socket_count = 0;
		int i;

		for (i = 0; i < MAX_CLIENT_CHANNELS; i++)
			if (output->bundle.channel[i].is_connected)
				socket_count++;
		brick->socket_count = socket_count;
		if (brick->power.led_on)
			goto done;
		mars_power_led_off((void*)brick, false);
		if (!output->bundle.sender.thread) {
			status = _setup_bundle(&output->bundle, brick->brick_name);
			if (likely(status >= 0)) {
				brick->connection_state = 1;
			}
		}
		if (output->bundle.sender.thread && !output->get_info) {
			client_get_info(output, NULL);
		}
		mars_power_led_on((void*)brick, output->got_info);
	} else {
		brick->socket_count = 0;
		if (brick->power.led_off)
			goto done;
		mars_power_led_on((void*)brick, false);
		if (atomic_read(&brick->sender_count))
			goto done;
		_kill_bundle(&output->bundle);
		if (atomic_read(&brick->receiver_count))
			goto done;
		_do_timeout_all(output, true);
		output->got_info = false;
		brick->connection_state = 0;
		mars_power_led_off((void*)brick, !output->bundle.sender.thread);
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
	int socket_count = 0;
	int i;

        if (!res)
                return NULL;

	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		struct client_channel *ch = &output->bundle.channel[i];
		if (mars_socket_is_alive(&ch->socket))
			socket_count++;
	}
	snprintf(res, 1024,
		 "get_info = %d "
		 "got_info = %d "
		 "socket_count = %d "
		 "max_flying = %d "
		 "io_timeout = %d | "
		 "timeout_count = %d "
		 "fly_count = %d\n",
		 output->get_info,
		 output->got_info,
		 socket_count,
		 brick->max_flying,
		 brick->power.io_timeout,
		 atomic_read(&brick->timeout_count),
		 atomic_read(&brick->fly_count));
	
        return res;
}

static
void client_reset_statistics(struct client_brick *brick)
{
	atomic_set(&brick->timeout_count, 0);
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

	for (i = 0; i < MAX_CLIENT_CHANNELS; i++) {
		struct client_channel *ch = &output->bundle.channel[i];
		ch->output = output;
		INIT_LIST_HEAD(&ch->wait_list);
	}

	init_waitqueue_head(&output->bundle.sender_event);
	mutex_init(&output->mutex);
	INIT_LIST_HEAD(&output->mref_list);
	init_waitqueue_head(&output->info_event);
	return 0;
}

static int client_output_destruct(struct client_output *output)
{
	brick_string_free(output->bundle.path);
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
	/* Let all be zero */
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
