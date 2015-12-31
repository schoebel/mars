/*
 * MARS Long Distance Replication Software
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
 */

#ifndef XIO_CLIENT_H
#define XIO_CLIENT_H

#include "xio_net.h"
#include "../lib/lib_limiter.h"

extern struct rate_limiter client_limiter;
extern int global_net_io_timeout;
extern int xio_client_abort;
extern int max_client_channels;
extern int max_client_bulk;

#define MAX_CLIENT_CHANNELS		4

struct client_aio_aspect {
	GENERIC_ASPECT(aio);
	struct list_head io_head;
	struct list_head hash_head;
	struct list_head tmp_head;
	unsigned long submit_jiffies;
	int alloc_len;
	bool do_dealloc;
};

struct client_brick {
	XIO_BRICK(client);
	/*  tunables */
	int max_flying; /*  limit on parallelism */
	bool limit_mode;
	bool allow_permuting_writes;
	bool separate_reads;

	/*  readonly from outside */
	int connection_state; /*  0 = switched off, 1 = not connected, 2 = connected */
};

struct client_input {
	XIO_INPUT(client);
};

struct client_threadinfo {
	struct task_struct *thread;
};

struct client_channel {
	struct xio_socket socket;
	struct client_threadinfo receiver;
	struct list_head wait_list;
	struct client_output *output;
	long current_space;
	int thread_count;
	int recv_error;
	int ch_nr;
	bool is_used;
	bool is_open;
	bool is_connected;
};

struct client_bundle {
	char *host;
	char *path;
	int thread_count;
	int old_channel;

	wait_queue_head_t sender_event;
	struct client_threadinfo sender;
	struct client_channel channel[MAX_CLIENT_CHANNELS];
};

struct client_output {
	XIO_OUTPUT(client);
	atomic_t fly_count;
	atomic_t timeout_count;
	spinlock_t lock;
	struct list_head aio_list;
	int  last_id;
	struct client_bundle bundle;
	struct xio_info info;

	wait_queue_head_t info_event;
	bool get_info;
	bool got_info;
	struct list_head *hash_table;
};

XIO_TYPES(client);

#endif
