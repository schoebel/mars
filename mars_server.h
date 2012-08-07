// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_SERVER_H
#define MARS_SERVER_H

#include <linux/wait.h>

#include "mars_net.h"
#include "lib_limiter.h"

extern struct mars_limiter server_limiter;

struct server_mref_aspect {
	GENERIC_ASPECT(mref);
	struct server_brick *brick;
	struct list_head cb_head;
};

struct server_output {
	MARS_OUTPUT(server);
};

struct server_brick {
	MARS_BRICK(server);
	struct list_head server_link;
	atomic_t in_flight;
	struct semaphore socket_sem;
	struct mars_socket handler_socket;
	struct task_struct *handler_thread;
	struct task_struct *cb_thread;
	wait_queue_head_t startup_event;
	wait_queue_head_t cb_event;
	spinlock_t cb_lock;
	struct list_head cb_read_list;
	struct list_head cb_write_list;
	bool cb_running;
	bool self_shutdown;
};

struct server_input {
	MARS_INPUT(server);
};

MARS_TYPES(server);

#endif
