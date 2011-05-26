// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_SERVER_H
#define MARS_SERVER_H

#include <linux/wait.h>

#include "mars_net.h"

//extern struct socket *server_socket;
//extern struct task_struct *server_thread;
//extern wait_queue_head_t server_event;

struct server_mref_aspect {
	GENERIC_ASPECT(mref);
	struct server_brick *brick;
	struct socket **sock;
	struct list_head cb_head;
};

struct server_output {
	MARS_OUTPUT(server);
};

struct server_brick {
	MARS_BRICK(server);
	atomic_t in_flight;
	struct socket *handler_socket;
	struct semaphore socket_sem;
	struct task_struct *handler_thread;
	struct task_struct *cb_thread;
	wait_queue_head_t startup_event;
	wait_queue_head_t cb_event;
	struct generic_object_layout mref_object_layout;
	struct server_output hidden_output;
	spinlock_t cb_lock;
	struct list_head cb_read_list;
	struct list_head cb_write_list;
	bool cb_running;
};

struct server_input {
	MARS_INPUT(server);
};

MARS_TYPES(server);

#endif
