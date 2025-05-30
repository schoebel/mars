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

#ifndef MARS_CLIENT_H
#define MARS_CLIENT_H

#include "mars_net.h"
#include "lib_limiter.h"

extern struct mars_limiter client_limiter;
extern int global_net_io_timeout;
extern int mars_client_info_timeout;
extern int mars_client_abort;
extern int max_client_channels;
extern int max_client_bulk;

extern atomic_t client_sender_count;
extern atomic_t client_receiver_count;

#define MAX_CLIENT_CHANNELS 4

struct client_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	struct list_head hash_head;
	unsigned long submit_jiffies;
	int alloc_len;
	bool do_dealloc;
	bool has_completed;
	bool is_hashed;
};

struct client_brick {
	MARS_BRICK(client);
	// tunables
	int max_flying; // limit on parallelism
	bool limit_mode;
	bool allow_permuting_writes;
	bool separate_reads;
	// readonly from outside
	int connection_state; // 0 = switched off, 1 = not connected, 2 = connected
	/* internal */
	atomic_t sender_count;
	atomic_t receiver_count;
	int socket_count;
	atomic_t fly_count;
	atomic_t timeout_count;
};

struct client_input {
	MARS_INPUT(client);
};

struct client_threadinfo {
	struct task_struct *thread;
};

enum CL_CHANNEL_STATE {
	CL_CHANNEL_INITIALIZED,
	CL_CHANNEL_OPEN,	/* socket is estabished */
	CL_CHANNEL_USED,	/* receiver thread has been created */
	CL_CHANNEL_CONNECTED,	/* first communication had no error */
};

struct client_channel {
	struct mars_socket socket;
	struct client_threadinfo receiver;
	struct list_head wait_list;
	struct client_output *output;
	long current_space;
	int recv_error;
	int thread_restart_count;
	int ch_nr;
	enum CL_CHANNEL_STATE ch_state;
};

enum CL_BUNDLE_STATE {
	CL_BUNDLE_INITIALIZED,
	CL_BUNDLE_RESPONSE_GOT,
};

struct client_bundle {
	char *host;
	char *path;
	struct mars_tcp_params *params;
	int last_thread_nr;
	short old_channel;
	enum CL_BUNDLE_STATE bundle_state;
	wait_queue_head_t sender_event;
	struct client_threadinfo sender;
	struct client_channel channel[MAX_CLIENT_CHANNELS];
};

struct client_output {
	MARS_OUTPUT(client);
	struct mutex mutex;
	struct list_head mref_list;
	int  last_id;
	struct client_bundle bundle;
	struct mars_info info;
	wait_queue_head_t info_event;
	bool get_info;
	bool got_info;
	struct list_head *hash_table;
};

MARS_TYPES(client);

#endif
