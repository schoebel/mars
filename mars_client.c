// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Client brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kthread.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_client.h"

///////////////////////// own helper functions ////////////////////////

static int thread_count = 0;

static void _kill_thread(struct client_threadinfo *ti)
{
	if (ti->thread) {
		MARS_INF("stopping thread...\n");
		kthread_stop(ti->thread);
		put_task_struct(ti->thread);
		ti->thread = NULL;
	}
}

static void _kill_socket(struct client_output *output)
{
	if (output->socket) {
		MARS_DBG("shutdown socket\n");
		mars_shutdown_socket(output->socket);
	}
	_kill_thread(&output->receiver);
	if (output->socket) {
		MARS_DBG("close socket\n");
		mars_put_socket(output->socket);
		output->socket = NULL;
	}
}

static int _request_info(struct client_output *output)
{
	struct mars_cmd cmd = {
		.cmd_code = CMD_GETINFO,
	};
	int status;
	
	MARS_DBG("\n");
	status = mars_send_struct(output->socket, &cmd, mars_cmd_meta);
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

	_kill_socket(output);
			
	status = mars_create_sockaddr(&sockaddr, output->host);
	if (unlikely(status < 0)) {
		MARS_DBG("no sockaddr, status = %d\n", status);
		goto done;
	}
	
	output->socket = mars_create_socket(&sockaddr, false);
	if (unlikely(IS_ERR(output->socket))) {
		status = PTR_ERR(output->socket);
		output->socket = NULL;
		if (status == -EINPROGRESS) {
			MARS_DBG("operation is in progress....\n");
			goto really_done; // give it a chance next time
		}
		MARS_DBG("no socket, status = %d\n", status);
		goto done;
	}

	output->receiver.thread = kthread_create(receiver_thread, output, "mars_receiver%d", thread_count++);
	if (unlikely(IS_ERR(output->receiver.thread))) {
		status = PTR_ERR(output->receiver.thread);
		MARS_ERR("cannot start receiver thread, status = %d\n", status);
		output->receiver.thread = NULL;
		output->receiver.terminated = true;
		goto done;
	}
	get_task_struct(output->receiver.thread);
	wake_up_process(output->receiver.thread);


	{
		struct mars_cmd cmd = {
			.cmd_code = CMD_CONNECT,
			.cmd_str1 = output->path,
		};

		status = mars_send_struct(output->socket, &cmd, mars_cmd_meta);
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
#if 1
	/* Limit transfers to page boundaries.
	 * Currently, this is more restrictive than necessary.
	 * TODO: improve performance by doing better when possible.
	 * This needs help from the server in some efficient way.
	 */
	int maxlen = PAGE_SIZE - (mref->ref_pos & (PAGE_SIZE-1));
	if (mref->ref_len > maxlen)
		mref->ref_len = maxlen;
#endif

	_CHECK_ATOMIC(&mref->ref_count, !=,  0);
	if (!mref->ref_data) { // buffered IO
		struct client_mref_aspect *mref_a = client_mref_get_aspect(output->brick, mref);
		if (!mref_a)
			return -EILSEQ;

		mref->ref_data = brick_block_alloc(mref->ref_pos, mref->ref_len);
		if (!mref->ref_data)
			return -ENOMEM;

		mref_a->do_dealloc = true;
		mref->ref_flags = 0;
	}

	atomic_inc(&mref->ref_count);
	return 0;
}

static void client_ref_put(struct client_output *output, struct mref_object *mref)
{
	struct client_mref_aspect *mref_a;
	CHECK_ATOMIC(&mref->ref_count, 1);
	if (!atomic_dec_and_test(&mref->ref_count))
		return;
	mref_a = client_mref_get_aspect(output->brick, mref);
	if (mref_a && mref_a->do_dealloc) {
		brick_block_free(mref->ref_data, mref->ref_len);
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
		msleep(3000);
#else
		msleep(1000 * 2 / HZ);
#endif
	}

	atomic_inc(&output->fly_count);
	atomic_inc(&mref->ref_count);

	traced_lock(&output->lock, flags);
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

        while (status >= 0 && mars_socket_is_alive(output->socket) && !kthread_should_stop()) {
		struct mars_cmd cmd = {};
		struct list_head *tmp;
		struct client_mref_aspect *mref_a = NULL;
		struct mref_object *mref = NULL;
		unsigned long flags;

		status = mars_recv_struct(output->socket, &cmd, mars_cmd_meta);
		MARS_IO("got cmd = %d status = %d\n", cmd.cmd_code, status);
		if (status < 0)
			goto done;

		switch (cmd.cmd_code) {
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
					list_del_init(&mref_a->hash_head);
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

			status = mars_recv_cb(output->socket, mref);
			MARS_IO("new status = %d, pos = %lld len = %d rw = %d\n", status, mref->ref_pos, mref->ref_len, mref->ref_rw);
			if (status < 0) {
				MARS_WRN("interrupted data transfer during callback, status = %d\n", status);
				traced_lock(&output->hash_lock[hash_index], flags);
				list_add_tail(&mref_a->hash_head, &output->hash_table[hash_index]);
				traced_unlock(&output->hash_lock[hash_index], flags);
				goto done;
			}

			traced_lock(&output->lock, flags);
			list_del_init(&mref_a->io_head);
			traced_unlock(&output->lock, flags);

			atomic_dec(&output->fly_count);
			SIMPLE_CALLBACK(mref, 0);
			client_ref_put(output, mref);
			break;
		}
		case CMD_GETINFO:
			status = mars_recv_struct(output->socket, &output->info, mars_info_meta);
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

	mars_shutdown_socket(output->socket);
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

static int sender_thread(void *data)
{
	struct client_output *output = data;
	struct client_brick *brick = output->brick;
	unsigned long flags;
	int status = 0;

	output->receiver.restart_count = 0;

        while (!kthread_should_stop()) {
		struct list_head *tmp;
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;
		bool do_resubmit = false;

		if (unlikely(!output->socket)) {
			status = _connect(output, brick->brick_name);
			MARS_IO("connect status = %d\n", status);
			if (unlikely(status < 0)) {
				msleep(5000);
				continue;
			}
			do_resubmit = true;
		}

		if (do_resubmit) {
			/* Re-Submit any waiting requests
			 */
			MARS_IO("re-submit\n");
			traced_lock(&output->lock, flags);
			_do_resubmit(output);
			traced_unlock(&output->lock, flags);
		}

		wait_event_interruptible_timeout(output->event, !list_empty(&output->mref_list) || output->get_info || kthread_should_stop(), 1 * HZ);
		
		if (output->get_info) {
			status = _request_info(output);
			if (status >= 0) {
				output->get_info = false;
			}
		}

		if (list_empty(&output->mref_list))
			continue;

		traced_lock(&output->lock, flags);
		tmp = output->mref_list.next;
		list_del(tmp);
		list_add(tmp, &output->wait_list);
		traced_unlock(&output->lock, flags);
		
		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		mref = mref_a->object;

		MARS_IO("sending mref, id = %d pos = %lld len = %d rw = %d\n", mref->ref_id, mref->ref_pos, mref->ref_len, mref->ref_rw);

		status = mars_send_mref(output->socket, mref);
		MARS_IO("status = %d\n", status);
		if (unlikely(status < 0)) {
			// retry submission on next occasion..
			traced_lock(&output->lock, flags);
			list_del(&mref_a->io_head);
			list_add(&mref_a->io_head, &output->mref_list);
			traced_unlock(&output->lock, flags);

			MARS_WRN("sending failed, status = %d\n", status);

			_kill_socket(output);

			continue;
		}
	}
//done:
	if (status < 0) {
		MARS_WRN("sender thread terminated with status = %d\n", status);
	}

	_kill_socket(output);

	/* Signal error on all pending IO requests.
	 * We have no other chance (except probably delaying
	 * this until destruction which mostly is not what
	 * we want).
	 */
	traced_lock(&output->lock, flags);
	_do_resubmit(output);
	while (!list_empty(&output->mref_list)) {
		struct list_head *tmp = output->mref_list.next;
		struct client_mref_aspect *mref_a;
		struct mref_object *mref;

		list_del_init(tmp);
		traced_unlock(&output->lock, flags);
		mref_a = container_of(tmp, struct client_mref_aspect, io_head);
		mref = mref_a->object;
		MARS_DBG("signalling IO error at pos = %lld len = %d\n", mref->ref_pos, mref->ref_len);
		atomic_dec(&output->fly_count);
		SIMPLE_CALLBACK(mref, -ENOTCONN);
		client_ref_put(output, mref);
		traced_lock(&output->lock, flags);
	}
	traced_unlock(&output->lock, flags);

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
			output->sender.thread = kthread_create(sender_thread, output, "mars_sender%d", thread_count++);
			if (unlikely(IS_ERR(output->sender.thread))) {
				status = PTR_ERR(output->sender.thread);
				MARS_ERR("cannot start sender thread, status = %d\n", status);
				output->sender.thread = NULL;
				output->sender.terminated = true;
				goto done;
			}
		}
		get_task_struct(output->sender.thread);
		wake_up_process(output->sender.thread);
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
	char *res = brick_string_alloc(0);
        if (!res)
                return NULL;

	snprintf(res, 512, "socket = %p fly_count = %d\n",
		 output->socket,
		 atomic_read(&output->fly_count));

        return res;
}

static
void client_reset_statistics(struct client_brick *brick)
{
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
