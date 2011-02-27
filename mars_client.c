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

static void _kill_socket(struct client_output *output)
{
	if (output->socket) {
		MARS_DBG("shutdown socket\n");
		kernel_sock_shutdown(output->socket, SHUT_WR);
		//sock_release(output->socket);
		output->socket = NULL;
	}
}

static void _kill_thread(struct client_threadinfo *ti)
{
	if (ti->thread) {
		kthread_stop(ti->thread);
	}
}

static int _connect(struct client_output *output, const char *str)
{
	struct sockaddr_storage sockaddr = {};
	int status;

	if (!output->host) {
		output->host = kstrdup(str, GFP_MARS);
		status = -ENOMEM;
		if (!output->host)
			goto done;
		status = -EINVAL;
		output->path = strchr(output->host, '+');
		if (!output->path) {
			kfree(output->host);
			output->host = NULL;
			goto done;
		}
		*output->path++ = '\0';
	}

	status = mars_create_sockaddr(&sockaddr, output->host);
	if (unlikely(status < 0))
		goto done;
	
	status = mars_create_socket(&output->socket, &sockaddr, false);
	if (unlikely(status < 0)) {
		output->socket = NULL;
		goto done;
	}

	{
		struct mars_cmd cmd = {
			.cmd_code = CMD_CONNECT,
			.cmd_str1 = output->path,
		};

		status = mars_send_struct(&output->socket, &cmd, mars_cmd_meta);
		if (unlikely(status < 0))
			goto done;
	}
	if (status >= 0) {
		struct mars_cmd cmd = {
			.cmd_code = CMD_GETINFO,
		};

		status = mars_send_struct(&output->socket, &cmd, mars_cmd_meta);
	}

done:
	if (status < 0) {
		MARS_INF("cannot connect to remote host '%s' (status = %d) -- retrying\n", output->host ? output->host : "NULL", status);
		_kill_socket(output);
	}
	return status;
}

////////////////// own brick / input / output operations //////////////////

static int client_get_info(struct client_output *output, struct mars_info *info)
{
	int status;

#if 0
	status = _connect(output, output->brick->brick_name);
	if (status < 0)
		goto done;
#endif

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
	_CHECK_ATOMIC(&mref->ref_count, !=,  0);
	/* Limit transfers to page boundaries.
	 * Currently, this is more restrictive than necessary.
	 * TODO: improve performance by doing better when possible.
	 * This needs help from the server in some efficient way.
	 */
	maxlen = PAGE_SIZE - (mref->ref_pos & (PAGE_SIZE-1));
	if (mref->ref_len > maxlen)
		mref->ref_len = maxlen;

	if (!mref->ref_data) { // buffered IO
		struct client_mref_aspect *mref_a = client_mref_get_aspect(output, mref);
		if (!mref_a)
			return -EILSEQ;

		mref->ref_data = kmalloc(mref->ref_len, GFP_MARS);
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
	mref_a = client_mref_get_aspect(output, mref);
	if (mref_a && mref_a->do_dealloc) {
		kfree(mref->ref_data);
	}
	client_free_mref(mref);
}

static void client_ref_io(struct client_output *output, struct mref_object *mref)
{
	struct generic_callback *cb;
	struct client_mref_aspect *mref_a;
	unsigned long flags;
	int error = -EINVAL;

	mref_a = client_mref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		goto error;
	}

	atomic_inc(&mref->ref_count);

	traced_lock(&output->lock, flags);
	mref_a->object->ref_id = ++output->last_id;
	list_add_tail(&mref_a->io_head, &output->mref_list);
	traced_unlock(&output->lock, flags);

	wake_up_interruptible(&output->event);

	return;

error:
	MARS_ERR("IO error = %d\n", error);
	cb = mref->ref_cb;
	cb->cb_error = error;
	cb->cb_fn(cb);
	client_ref_put(output, mref);
}

static int receiver_thread(void *data)
{
	struct client_output *output = data;
	int status = 0;

        while (!kthread_should_stop() && output->socket) {
		struct mars_cmd cmd = {};
		struct list_head *tmp;
		struct client_mref_aspect *mref_a = NULL;
		struct mref_object *mref = NULL;
		struct generic_callback *cb;
		unsigned long flags;

		status = mars_recv_struct(&output->socket, &cmd, mars_cmd_meta);
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
			traced_lock(&output->lock, flags);
			for (tmp = output->wait_list.next; tmp != &output->wait_list; tmp = tmp->next) {
				mref_a = container_of(tmp, struct client_mref_aspect, io_head);
				if (mref_a->object->ref_id == cmd.cmd_int1) {
					mref = mref_a->object;
					break;
				}
			}
			traced_unlock(&output->lock, flags);

			if (!mref) {
				MARS_ERR("got unknown id = %d for callback\n", cmd.cmd_int1);
				status = -EBADR;
				goto done;
			}

			status = mars_recv_cb(&output->socket, mref);
			if (status < 0) {
				MARS_ERR("interrupted data transfer during callback, status = %d\n", status);
				goto done;
			}

			traced_lock(&output->lock, flags);
			list_del_init(&mref_a->io_head);
			traced_unlock(&output->lock, flags);

			cb = mref->ref_cb;
			cb->cb_fn(cb);
			client_ref_put(output, mref);
			break;
		case CMD_GETINFO:
			status = mars_recv_struct(&output->socket, &output->info, mars_info_meta);
			if (status < 0) {
				MARS_ERR("got bad info from remote side, status = %d\n", status);
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
	}

done:
	if (status < 0)
		MARS_ERR("receiver thread terminated with status = %d\n", status);
	output->receiver.thread = NULL;
	if (output->socket) {
		MARS_INF("shutting down socket\n");
		kernel_sock_shutdown(output->socket, SHUT_WR);
		//msleep(1000);
		output->socket = NULL;
	}
	return status;
}

static int sender_thread(void *data)
{
	struct client_output *output = data;
	struct client_brick *brick = output->brick;
	int status = 0;

        while (!kthread_should_stop()) {
		struct list_head *tmp;
		struct client_mref_aspect *mref_a;
		unsigned long flags;
		bool do_resubmit = false;

		if (unlikely(!output->socket)) {
			status = _connect(output, brick->brick_name);
			if (unlikely(status < 0)) {
				msleep(5000);
				continue;
			}
			do_resubmit = true;
		}

		if (unlikely(!output->receiver.thread)) {
			output->receiver.thread = kthread_create(receiver_thread, output, "mars_receiver%d", thread_count++);
			if (unlikely(IS_ERR(output->receiver.thread))) {
				MARS_ERR("cannot start receiver thread, status = %d\n", (int)PTR_ERR(output->receiver.thread));
				output->receiver.thread = NULL;
				msleep(5000);
				continue;
			}
			wake_up_process(output->receiver.thread);
		}

		if (do_resubmit) {
			/* Re-Submit any waiting requests
			 */
			traced_lock(&output->lock, flags);
			if (!list_empty(&output->wait_list)) {
				struct list_head *first = output->wait_list.next;
				struct list_head *last = output->wait_list.prev;
				struct list_head *old_start = output->mref_list.next;
#define list_connect __list_del // the original routine has a misleading name: in reality it is more general
				list_connect(&output->mref_list, first);
				list_connect(last, old_start);
				INIT_LIST_HEAD(&output->wait_list);
			}
			traced_unlock(&output->lock, flags);
		}

		wait_event_interruptible_timeout(output->event, !list_empty(&output->mref_list), 1 * HZ);
		
		if (list_empty(&output->mref_list))
			continue;

		traced_lock(&output->lock, flags);
		tmp = output->mref_list.next;
		list_del(tmp);
		list_add(tmp, &output->wait_list);
		traced_unlock(&output->lock, flags);
		
		mref_a = container_of(tmp, struct client_mref_aspect, io_head);

		status = mars_send_mref(&output->socket, mref_a->object);
		if (unlikely(status < 0)) {
			// retry submission on next occasion..
			traced_lock(&output->lock, flags);
			list_del(&mref_a->io_head);
			list_add(&mref_a->io_head, &output->mref_list);
			traced_unlock(&output->lock, flags);

			MARS_ERR("sending failed, status = %d\n", status);

			_kill_socket(output);
			_kill_thread(&output->receiver);

			/* Forcibly mark as dead, in any case.
			 * In consequence, a new connection will be tried thereafter.
			 */
			output->receiver.thread = NULL;
			continue;
		}
	}
//done:
	if (status < 0)
		MARS_ERR("sender thread terminated with status = %d\n", status);

	_kill_socket(output);
	_kill_thread(&output->receiver);

	output->sender.thread = NULL;
	return status;
}

static int client_switch(struct client_brick *brick)
{
	struct client_output *output = brick->outputs[0];
	int status = 0;

	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);
		output->sender.thread = kthread_create(sender_thread, output, "mars_sender%d", thread_count++);
		if (unlikely(IS_ERR(output->sender.thread))) {
			status = PTR_ERR(output->sender.thread);
			MARS_ERR("cannot start sender thread, status = %d\n", status);
			output->sender.thread = NULL;
			goto done;
		}
		wake_up_process(output->sender.thread);
		mars_power_led_on((void*)brick, true);
	} else {
		mars_power_led_on((void*)brick, false);
		_kill_thread(&output->sender);
		mars_power_led_off((void*)brick, !output->sender.thread);
	}
done:
	return status;
}


//////////////// object / aspect constructors / destructors ///////////////

static int client_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct client_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->io_head);
	return 0;
}

static void client_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct client_mref_aspect *ini = (void*)_ini;
	(void)ini;
}

MARS_MAKE_STATICS(client);

////////////////////// brick constructors / destructors ////////////////////

static int client_brick_construct(struct client_brick *brick)
{
	return 0;
}

static int client_output_construct(struct client_output *output)
{
	spin_lock_init(&output->lock);
	INIT_LIST_HEAD(&output->mref_list);
	INIT_LIST_HEAD(&output->wait_list);
	init_waitqueue_head(&output->event);
	init_waitqueue_head(&output->sender.event);
	init_waitqueue_head(&output->receiver.event);
	init_waitqueue_head(&output->info_event);
	return 0;
}

static int client_output_destruct(struct client_output *output)
{
	if (output->host)
		kfree(output->host);
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct client_brick_ops client_brick_ops = {
	.brick_switch = client_switch,
};

static struct client_output_ops client_output_ops = {
	.make_object_layout = client_make_object_layout,
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
	.aspect_types = client_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
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
	.default_input_types = client_input_types,
	.default_output_types = client_output_types,
	.brick_construct = &client_brick_construct,
};
EXPORT_SYMBOL_GPL(client_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_client(void)
{
	MARS_INF("init_client()\n");
	return client_register_brick_type();
}

static void __exit exit_client(void)
{
	MARS_INF("exit_client()\n");
	client_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS client brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_client);
module_exit(exit_client);
