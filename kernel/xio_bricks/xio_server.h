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

#ifndef XIO_SERVER_H
#define XIO_SERVER_H

#include <linux/wait.h>

#include "xio_net.h"
#include "../lib/lib_limiter.h"

#define NR_SERVER_SOCKETS		3

extern int server_show_statist;

extern struct rate_limiter server_limiter;

struct server_aio_aspect {
	GENERIC_ASPECT(aio);
	struct server_brick *brick;
	struct list_head cb_head;
	void *data;
	int len;
	bool do_put;
};

struct server_output {
	XIO_OUTPUT(server);
};

struct server_brick {
	XIO_BRICK(server);
	struct semaphore socket_sem;
	struct xio_socket handler_socket;
	struct xio_brick *conn_brick;
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
	XIO_INPUT(server);
};

XIO_TYPES(server);

/* Internal interface to specific implementations.
 * This is used for a rough separation of the strategy layer
 * from the ordinary XIO layer.
 * Currently, separation is at linker level.
 * TODO: implement a dynamic separation later.
 */

/* Implemented separately, used by generic part */

extern int server_thread(void *data);

extern int handler_thread(void *data);

extern int cb_thread(void *data);

extern int server_io(struct server_brick *brick, struct xio_socket *sock, struct xio_cmd *cmd);

/* Implemented by generic part, used by specific part */

extern int server_switch(struct server_brick *brick);

#endif
