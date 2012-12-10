// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

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

///////////////////////// own helper functions ////////////////////////

static int thread_count = 0;

static void _kill_thread(struct client_threadinfo *ti)
{
	if (ti->thread) {
		brick_thread_stop(ti->thread);
	}
}

static void _kill_socket(struct client_output *output)
{
	if (mars_socket_is_alive(&output->socket)) {
		MARS_DBG("shutdown socket\n");
		mars_shutdown_socket(&output->socket);
	}
	_kill_thread(&output->receiver);
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

	output->receiver.thread = brick_thread_create(receiver_thread, output, "mars_receiver%d", thread_count++);
	if (unlikely(!output->receiver.thread)) {
		MARS_ERR("cannot start receiver thread, status = %d\n", status);
		status = -ENOENT;
		output->receiver.terminated = true;
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
	status = -EIO;
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

static void client_ref_io(struct client_output *output, struct mref_object *mref)
{
	struct client_mref_aspect *mref_a;
	int hash_index;
	unsigned long flags;
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

	traced_lock(&output->lock, flags);
	mref_a->submit_jiffies = jiffies;
	mref->ref_id = ++output->last_id;
	list_add_tail(&mref_a->io_head, &output->mref_list);
	traced_unlock(&output->lock, flags);

	hash_index = mref->ref_id % CLIENT_HASH_MAX;
	traced_lock(&output->hash_lock[hash_index], flags);
	list_add_tail(&mref_a->hash_head, &output->hash_table[hash_index]);
	traced_unlock(&output->hash_lock[hash_index], flags);

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

        while (status >= 0 && mars_socket_is_alive(&output->socket) && !brick_thread_should_stop()) {
		struct mars_cmd cmd = {};
		struct list_head *tmp;
		struct client_mref_aspect *mref_a = NULL;
		struct mref_object *mref = NULL;
		unsigned long flags;

		status = mars_recv_struct(&output->socket, &cmd, mars_cmd_meta);
		MARS_IO("got cmd = %d status = %d\n", cmd.cmd_code, status);
		if (status < 0)
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

			traced_lock(&output->hash_lock[hash_index], flags);
			for (tmp = output->hash_table[hash_index].next; tmp != &output->hash_table[hash_index]; tmp = tmp->next) {
				struct mref_object *tmp_mref;
				mref_a = container_of(tmp, struct client_mref_aspect, hash_head);
				tmp_mref = mref_a->object;
				if (unlikely(!tmp_mref)) {
					traced_unlock(&output->hash_lock[hash_index], flags);
					MARS_ERR("bad internal mref pointer\n");
					status = -EBADR;
					goto done;
				}
				if (tmp_mref->ref_id == cmd.cmd_int1) {
					mref = tmp_mref;
					break;
				}
			}
			traced_unlock(&output->hash_lock[hash_index], flags);

			if (!mref) {
				MARS_ERR("got unknown id = %d for callback\n", cmd.cmd_int1);
				status = -EBADR;
				goto done;
			}

			MARS_IO("got callback id = %d, old pos = %lld len = %d rw = %d\n", mref->ref_id, mref->ref_pos, mref->ref_len, mref->ref_rw);

			status = mars_recv_cb(&output->socket, mref, &cmd);
			MARS_IO("new status = %d, pos = %lld len = %d rw = %d\n", status, mref->ref_pos, mref->ref_len, mref->ref_rw);
			if (status < 0) {
				MARS_WRN("interrupted data transfer during callback, status = %d\n", status);
				goto done;
			}

			traced_lock(&output->hash_lock[hash_index], flags);
			list_del_init(&mref_a->hash_head);
			traced_unlock(&output->hash_lock[hash_index], flags);

			traced_lock(&output->lock, flags);
			list_del_init(&mref_a->io_head);
			traced_unlock(&output->lock, flags);

			SIMPLE_CALLBACK(mref, 0);

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
	}

	if (status < 0) {
		MARS_WRN("receiver thread terminated with status = %d\n", status);
	}

	mars_shutdown_socket(&output->socket);
	output->receiver.terminated = true;
	wake_up_interruptible(&output->receiver.run_event);
	return status;
}

static
void _do_resubmit(struct client_output *output)
{
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
}

static
void _do_timeout(struct client_output *output, struct list_head *anchor, bool force)
{
	struct client_brick *brick = output->brick;
	int rounds = 0;
	int io_timeout = brick->io_timeout;
	if (io_timeout <= 0)
		io_timeout = global_net_io_timeout;

	while (!list_empty(anchor)) {
		struct list_head *tmp;
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;
		int hash_index;
		unsigned long flags;

		traced_lock(&output->lock, flags);
		tmp = anchor->next;
		traced_unlock(&output->lock, flags);
		
		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		mref = mref_a->object;

		if (!force &&
		    mars_net_is_alive &&
		    (io_timeout <= 0 || !time_is_before_jiffies(mref_a->submit_jiffies + io_timeout * HZ))) {
			break;
		}

		if (!rounds++) {
			MARS_WRN("timeout after %d: signalling IO error at pos = %lld len = %d\n",
				 io_timeout,
				 mref->ref_pos,
				 mref->ref_len);
		}
		atomic_inc(&output->timeout_count);

		hash_index = mref->ref_id % CLIENT_HASH_MAX;
	
		traced_lock(&output->hash_lock[hash_index], flags);
		list_del_init(&mref_a->hash_head);
		traced_unlock(&output->hash_lock[hash_index], flags);
	
		traced_lock(&output->lock, flags);
		list_del_init(&mref_a->io_head);
		traced_unlock(&output->lock, flags);
	
		SIMPLE_CALLBACK(mref, -ENOTCONN);

		client_ref_put(output, mref);

		atomic_dec(&output->fly_count);
		atomic_dec(&mars_global_io_flying);
	}
}

static int sender_thread(void *data)
{
	struct client_output *output = data;
	struct client_brick *brick = output->brick;
	unsigned long flags;
	bool do_kill = false;
	int status = 0;

	output->receiver.restart_count = 0;

        while (!brick_thread_should_stop()) {
		struct list_head *tmp = NULL;
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;
		bool do_resubmit = false;

		if (unlikely(!mars_socket_is_alive(&output->socket))) {
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
			do_kill = true;
			do_resubmit = true;
		}

		if (do_resubmit) {
			/* Re-Submit any waiting requests
			 */
			MARS_IO("re-submit\n");
			traced_lock(&output->lock, flags);
			_do_resubmit(output);
			traced_unlock(&output->lock, flags);
			_do_timeout(output, &output->mref_list, false);
		}

		wait_event_interruptible_timeout(output->event, !list_empty(&output->mref_list) || output->get_info || brick_thread_should_stop(), 1 * HZ);
		
		if (output->get_info) {
			status = _request_info(output);
			if (status >= 0) {
				output->get_info = false;
			} else {
				MARS_WRN("cannot get info, status = %d\n", status);
				brick_msleep(1000);
			}
		}

		if (list_empty(&output->mref_list))
			continue;

		traced_lock(&output->lock, flags);
		tmp = output->mref_list.next;
		traced_unlock(&output->lock, flags);
		
		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
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
			brick_msleep(3000);
			continue;
		}

		// all ok, remember in-flight mrefs
		traced_lock(&output->lock, flags);
		list_del(tmp);
		list_add(tmp, &output->wait_list);
		traced_unlock(&output->lock, flags);
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

	output->sender.terminated = true;
	wake_up_interruptible(&output->sender.run_event);
	MARS_DBG("sender terminated\n");
	return status;
}

static int client_switch(struct client_brick *brick)
{
	struct client_output *output = brick->outputs[0];
	int status = 0;

	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		if (output->sender.terminated) {
			output->sender.terminated = false;
			output->sender.thread = brick_thread_create(sender_thread, output, "mars_sender%d", thread_count++);
			if (unlikely(!output->sender.thread)) {
				MARS_ERR("cannot start sender thread\n");
				output->sender.terminated = true;
				status = -ENOENT;
				goto done;
			}
		}
		if (!output->sender.terminated) {
			mars_power_led_on((void*)brick, true);
		}
	} else {
		mars_power_led_on((void*)brick, false);
		_kill_thread(&output->sender);
		wait_event_interruptible_timeout(output->sender.run_event, output->sender.terminated, 10 * HZ);
		if (output->sender.terminated) {
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
		 brick->io_timeout,
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
	for (i = 0; i < CLIENT_HASH_MAX; i++) {
		spin_lock_init(&output->hash_lock[i]);
		INIT_LIST_HEAD(&output->hash_table[i]);
	}
	spin_lock_init(&output->lock);
	INIT_LIST_HEAD(&output->mref_list);
	INIT_LIST_HEAD(&output->wait_list);
	init_waitqueue_head(&output->event);
	init_waitqueue_head(&output->sender.run_event);
	init_waitqueue_head(&output->receiver.run_event);
	init_waitqueue_head(&output->info_event);
	output->sender.terminated = true;
	output->receiver.terminated = true;
	return 0;
}

static int client_output_destruct(struct client_output *output)
{
	if (output->path) {
		brick_string_free(output->path);
		output->path = NULL;
	}
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

void __exit exit_mars_client(void)
{
	MARS_INF("exit_client()\n");
	client_unregister_brick_type();
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS client brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_client);
module_exit(exit_mars_client);
#endif
