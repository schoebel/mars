// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_CLIENT_H
#define MARS_CLIENT_H

#include "mars_net.h"

#define CLIENT_HASH_MAX 256

struct client_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	struct list_head hash_head;
	bool do_dealloc;
};

struct client_brick {
	MARS_BRICK(client);
	// tunables
	int max_flying; // limit on parallelism
};

struct client_input {
	MARS_INPUT(client);
};

struct client_threadinfo {
	struct task_struct *thread;
	wait_queue_head_t run_event;
	bool terminated;
};

struct client_output {
	MARS_OUTPUT(client);
	atomic_t fly_count;
	spinlock_t lock;
	struct list_head mref_list;
	struct list_head wait_list;
	wait_queue_head_t event;
	int  last_id;
	struct socket *socket;
	char *host;
	char *path;
	struct client_threadinfo sender;
	struct client_threadinfo receiver;
	struct mars_info info;
	wait_queue_head_t info_event;
	bool get_info;
	bool got_info;
	spinlock_t hash_lock[CLIENT_HASH_MAX];
	struct list_head hash_table[CLIENT_HASH_MAX];
};

MARS_TYPES(client);

#endif
