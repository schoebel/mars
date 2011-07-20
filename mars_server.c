// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Server brick (just for demonstration)

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/kthread.h>

#define _STRATEGY
#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_server.h"

static struct socket *server_socket = NULL;
static struct task_struct *server_thread = NULL;

///////////////////////// own helper functions ////////////////////////


static
int cb_thread(void *data)
{
	struct server_brick *brick = data;
	int status = -EINVAL;

	brick->cb_running = true;
	wake_up_interruptible(&brick->startup_event);

	MARS_DBG("--------------- cb_thread starting on socket %p\n", brick->handler_socket);

        while (!kthread_should_stop()) {
		struct server_mref_aspect *mref_a;
		struct mref_object *mref;
		struct list_head *tmp;
		struct socket **sock;
		unsigned long flags;

		status = -EINVAL;
		if (!brick->handler_socket)
			break;

		wait_event_interruptible_timeout(
			brick->cb_event,
			!list_empty(&brick->cb_read_list) ||
			!list_empty(&brick->cb_write_list) ||
			kthread_should_stop(),
			3 * HZ);

		if (!brick->handler_socket)
			break;

		traced_lock(&brick->cb_lock, flags);
		tmp = brick->cb_write_list.next;
		if (tmp == &brick->cb_write_list) {
			tmp = brick->cb_read_list.next;
			if (tmp == &brick->cb_read_list) {
				traced_unlock(&brick->cb_lock, flags);
				continue;
			}
		}
		list_del_init(tmp);
		traced_unlock(&brick->cb_lock, flags);

		mref_a = container_of(tmp, struct server_mref_aspect, cb_head);
		mref = mref_a->object;
		CHECK_PTR(mref, err);
		status = -ENOTSOCK;
		sock = mref_a->sock;
		CHECK_PTR(sock, err);
		CHECK_PTR(*sock, err);

		down(&brick->socket_sem);
		status = mars_send_cb(sock, mref);
		up(&brick->socket_sem);

		atomic_dec(&brick->in_flight);
		GENERIC_INPUT_CALL(brick->inputs[0], mref_put, mref);

		if (unlikely(status < 0)) {
			MARS_ERR("cannot send response, status = %d\n", status);
			kernel_sock_shutdown(*sock, SHUT_WR);
			break;
		}
	}

err:
	brick->cb_running = false;
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
	brick = mref_a->brick;
	CHECK_PTR(brick, err);
	mref = mref_a->object;
	CHECK_PTR(mref, err);

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

int server_io(struct server_brick *brick, struct socket **sock)
{
	struct mref_object *mref;
	struct server_mref_aspect *mref_a;
	int status = -ENOTRECOVERABLE;

	if (!brick->cb_running)
		goto done;

	mref = server_alloc_mref(&brick->hidden_output, &brick->mref_object_layout);
	status = -ENOMEM;
	if (!mref)
		goto done;

	mref_a = server_mref_get_aspect(&brick->hidden_output, mref);
	if (unlikely(!mref_a)) {
		mars_free_mref(mref);
		goto done;
	}

	status = mars_recv_mref(sock, mref);
	if (status < 0) {
		mars_free_mref(mref);
		goto done;
	}
	
	mref_a->brick = brick;
	mref_a->sock = sock;
	mref->_ref_cb.cb_private = mref_a;
	mref->_ref_cb.cb_fn = server_endio;
	mref->ref_cb = &mref->_ref_cb;
	atomic_inc(&brick->in_flight);
	
	status = GENERIC_INPUT_CALL(brick->inputs[0], mref_get, mref);
	if (status < 0) {
		MARS_INF("mref_get execution error = %d\n", status);
		mref->_ref_cb.cb_error = status;
		server_endio(&mref->_ref_cb);
		status = 0; // continue serving requests
		goto done;
	}
	
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
		mref = mref_a->object;
		if (!mref)
			continue;

		GENERIC_INPUT_CALL(brick->inputs[0], mref_put, mref);
	}
}

static
int handler_thread(void *data)
{
	struct server_brick *brick = data;
	struct socket **sock = &brick->handler_socket;
	struct task_struct *cb_thread = brick->cb_thread;
	int max_round = 300;
	int status = 0;

	brick->cb_thread = NULL;
	brick->handler_thread = NULL;
	wake_up_interruptible(&brick->startup_event);
	MARS_DBG("--------------- handler_thread starting on socket %p\n", *sock);
	if (!*sock)
		goto done;

	//fake_mm();

        while (brick->cb_running && !kthread_should_stop()) {
		struct mars_cmd cmd = {};

		status = mars_recv_struct(sock, &cmd, mars_cmd_meta);
		if (status < 0) {
			MARS_ERR("bad command status = %d\n", status);
			break;
		}

		MARS_IO("cmd = %d\n", cmd.cmd_code);

		status = -EPROTO;
		switch (cmd.cmd_code) {
		case CMD_NOP:
			MARS_DBG("got NOP operation\n");
			status = 0;
			break;
		case CMD_STATUS:
			//...
			MARS_ERR("NYI\n");
			break;
		case CMD_GETINFO:
		{
			struct mars_info info = {};
			status = GENERIC_INPUT_CALL(brick->inputs[0], mars_get_info, &info);
			if (status < 0) {
				break;
			}
			down(&brick->socket_sem);
			status = mars_send_struct(sock, &cmd, mars_cmd_meta);
			if (status < 0) {
				break;
			}
			status = mars_send_struct(sock, &info, mars_info_meta);
			up(&brick->socket_sem);
			break;
		}
		case CMD_GETENTS:
		{
			status = -EINVAL;
			if (unlikely(!cmd.cmd_str1 || !mars_global))
				break;

			down(&brick->socket_sem);
			down_read(&mars_global->dent_mutex);
			status = mars_send_dent_list(sock, &mars_global->dent_anchor);
			up_read(&mars_global->dent_mutex);
			up(&brick->socket_sem);

			if (status < 0) {
				MARS_ERR("could not send dentry information, status = %d\n", status);
			}
			break;
		}
		case CMD_CONNECT:
		{
			struct mars_brick *prev;
			const char *path = cmd.cmd_str1;

			status = -EINVAL;
			CHECK_PTR(path, err);
			CHECK_PTR(mars_global, err);
			CHECK_PTR(_bio_brick_type, err);

			//prev = mars_find_brick(mars_global, NULL, cmd.cmd_str1);
			prev = make_brick_all(
				mars_global,
				NULL,
				NULL,
				NULL,
				10 * HZ,
				path,
				(const struct generic_brick_type*)_bio_brick_type,
				(const struct generic_brick_type*[]){},
				NULL,
				path,
				(const char *[]){},
				0);
			if (likely(prev)) {
				status = generic_connect((void*)brick->inputs[0], (void*)prev->outputs[0]);
			} else {
				MARS_ERR("cannot find brick '%s'\n", path);
			}
			
		err:
			cmd.cmd_int1 = status;
			down(&brick->socket_sem);
			status = mars_send_struct(sock, &cmd, mars_cmd_meta);
			up(&brick->socket_sem);
			break;
		}
		case CMD_MREF:
			status = server_io(brick, sock);
			break;
		case CMD_CB:
			MARS_ERR("oops, as a server I should never get CMD_CB; something is wrong here - attack attempt??\n");
			break;
		default:
			MARS_ERR("unknown command %d\n", cmd.cmd_code);
		}
		if (status < 0)
			break;
	}

	kernel_sock_shutdown(*sock, SHUT_WR);
	//sock_release(*sock);
	//cleanup_mm();

done:
	MARS_DBG("handler_thread terminating, status = %d\n", status);
	kthread_stop(cb_thread);
	wait_event_interruptible_timeout(
		brick->startup_event,
		!brick->cb_running,
		10 * HZ);

	_clean_list(brick, &brick->cb_read_list);
	_clean_list(brick, &brick->cb_write_list);

	do {
		int status = mars_kill_brick((void*)brick);
		if (status >= 0) {
			//if(*sock)
			//sock_release(*sock);
			break;
		}
		if (status >= 0 || max_round-- < 0) {
			MARS_INF("not dead, giving up....\n");
			break;
		}
		msleep(1000);
	} while (brick->cb_running && !brick->power.led_off);

	MARS_DBG("done\n");
	return 0;
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
	if (brick->power.button) {
		mars_power_led_off((void*)brick, false);

		MARS_INF("starting.....");
		
		mars_power_led_on((void*)brick, true);
	} else {
		mars_power_led_on((void*)brick, false);
		mars_power_led_off((void*)brick, true);
	}
	return 0;
}

//////////////// object / aspect constructors / destructors ///////////////

static int server_mref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct server_mref_aspect *ini = (void*)_ini;
	INIT_LIST_HEAD(&ini->cb_head);
	return 0;
}

static void server_mref_aspect_exit_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct server_mref_aspect *ini = (void*)_ini;
	CHECK_HEAD_EMPTY(&ini->cb_head);
}

MARS_MAKE_STATICS(server);

////////////////////// brick constructors / destructors ////////////////////

static int server_brick_construct(struct server_brick *brick)
{
	struct server_output *hidden = &brick->hidden_output;
	_server_output_init(brick, hidden, "internal");
	init_waitqueue_head(&brick->startup_event);
	init_waitqueue_head(&brick->cb_event);
	sema_init(&brick->socket_sem, 1);
	spin_lock_init(&brick->cb_lock);
	INIT_LIST_HEAD(&brick->cb_read_list);
	INIT_LIST_HEAD(&brick->cb_write_list);
	return 0;
}

static int server_output_construct(struct server_output *output)
{
	return 0;
}

///////////////////////// static structs ////////////////////////

static struct server_brick_ops server_brick_ops = {
	.brick_switch = server_switch,
};

static struct server_output_ops server_output_ops = {
	.make_object_layout = server_make_object_layout,
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
	.aspect_types = server_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MREF] = LAYOUT_ALL,
	}
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
	.default_input_types = server_input_types,
	.default_output_types = server_output_types,
	.brick_construct = &server_brick_construct,
};
EXPORT_SYMBOL_GPL(server_brick_type);

///////////////////////////////////////////////////////////////////////

// strategy layer

static int _server_thread(void *data)
{
	char *id = my_id();
	int version = 0;
	int status = 0;

	//fake_mm();

	MARS_INF("-------- server starting on host '%s' ----------\n", id);

        while (!kthread_should_stop()) {
		int size;
		struct server_brick *brick;
		struct task_struct *thread;
		struct socket *new_socket = NULL;
		int status;
		status = kernel_accept(server_socket, &new_socket, O_NONBLOCK);
		if (status < 0) {
			msleep(500);
			if (status == -EAGAIN)
				continue; // without error message
			MARS_ERR("accept status = %d\n", status);
			continue;
		}
		if (!new_socket) {
			MARS_ERR("got no socket\n");
			msleep(3000);
			continue;
		}
		MARS_DBG("got new connection %p\n", new_socket);

		/* TODO: check authorization.
		 */

		size = server_brick_type.brick_size +
			(server_brick_type.max_inputs + server_brick_type.max_outputs) * sizeof(void*) +
			sizeof(struct server_input),

		brick = kzalloc(size, GFP_MARS);
		if (!brick) {
			MARS_ERR("cannot allocate server instance\n");
			goto err;
		}
		
		status = generic_brick_init_full(brick, size, (void*)&server_brick_type, NULL, NULL, NULL);
		if (status) {
			MARS_ERR("cannot init server brick, status = %d\n", status);
			goto err;
		}

		brick->handler_socket = new_socket;

		thread = kthread_create(cb_thread, brick, "mars_cb%d", version);
		if (IS_ERR(thread)) {
			MARS_ERR("cannot create cb thread, status = %ld\n", PTR_ERR(thread));
			goto err;
		}
		brick->cb_thread = thread;
		wake_up_process(thread);

		thread = kthread_create(handler_thread, brick, "mars_handler%d", version++);
		if (IS_ERR(thread)) {
			MARS_ERR("cannot create handler thread, status = %ld\n", PTR_ERR(thread));
			goto err;
		}
		brick->handler_thread = thread;
		wake_up_process(thread);

		wait_event_interruptible(brick->startup_event, brick->handler_thread == NULL && brick->cb_thread == NULL);
		continue;

	err:
		if (new_socket) {
			kernel_sock_shutdown(new_socket, SHUT_WR);
			//sock_release(new_socket);
		}
		msleep(3000);
	}

	MARS_INF("-------- cleaning up ----------\n");

	//cleanup_mm();

	MARS_INF("-------- done status = %d ----------\n", status);
	server_thread = NULL;
	return status;
}

////////////////// module init stuff /////////////////////////

static int __init init_server(void)
{
	struct sockaddr_storage sockaddr = {};
	struct task_struct *thread;
	int status;

	MARS_INF("init_server()\n");
	
	status = mars_create_sockaddr(&sockaddr, "");
	if (status < 0)
		return status;

	status = mars_create_socket(&server_socket, &sockaddr, true);
	if (status < 0)
		return status;

	status = kernel_listen(server_socket, 100);
	if (status < 0)
		return status;

	thread = kthread_create(_server_thread, NULL, "mars_server");
	if (IS_ERR(thread)) {
		return PTR_ERR(thread);
	}

	server_thread = thread;
	wake_up_process(thread);

	return server_register_brick_type();
}

static void __exit exit_server(void)
{
	MARS_INF("exit_server()\n");
	server_unregister_brick_type();
	if (server_thread) {
		if (server_socket) {
			kernel_sock_shutdown(server_socket, SHUT_WR);
		}
		kthread_stop(server_thread);
		if (server_socket && !server_thread) {
			//sock_release(server_socket);
			server_socket = NULL;
		}
	}
}

MODULE_DESCRIPTION("MARS server brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_server);
module_exit(exit_server);
