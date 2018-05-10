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

#ifndef MARS_SERVER_H
#define MARS_SERVER_H

#include <linux/wait.h>

#include "mars_net.h"
#include "lib_limiter.h"

extern int server_show_statist;

extern struct mars_limiter server_limiter;
extern int dent_limit;
extern int dent_retry;
extern int handler_limit;

extern atomic_t server_handler_count;

struct server_mref_aspect {
	GENERIC_ASPECT(mref);
	struct server_brick *brick;
	struct list_head cb_head;
	void *data;
	int len;
	bool do_put;
};

struct server_output {
	MARS_OUTPUT(server);
};

struct server_brick {
	MARS_BRICK(server);
	struct semaphore socket_sem;
	struct mars_socket handler_socket;
	struct mars_tcp_params *handler_params;
	struct mars_brick *conn_brick;
	struct task_struct *handler_thread;
	struct task_struct *cb_thread;
	wait_queue_head_t startup_event;
	wait_queue_head_t cb_event;
	spinlock_t cb_lock;
	struct list_head cb_read_list;
	struct list_head cb_write_list;
	atomic_t in_flight;
	int version;
	bool cb_running;
	bool handler_running;
};

struct server_input {
	MARS_INPUT(server);
};

MARS_TYPES(server);

#endif
