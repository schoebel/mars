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

#ifndef MARS_SIO_H
#define MARS_SIO_H

#include "lib_mapfree.h"

#define WITH_THREAD 16

struct sio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	int alloc_len;
	bool do_dealloc;
};

struct sio_brick {
	MARS_BRICK(sio);
	// parameters
	bool o_direct;
	bool o_fdsync;
};

struct sio_input {
	MARS_INPUT(sio);
};

struct sio_threadinfo {
	struct sio_output *output;
	struct list_head mref_list;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
	atomic_t queue_count;
	atomic_t fly_count;
	atomic_t total_count;
	unsigned long last_jiffies;
};

struct sio_output {
	MARS_OUTPUT(sio);
        // private
	struct mapfree_info *mf;
	struct sio_threadinfo tinfo[WITH_THREAD+1];
	spinlock_t g_lock;
	atomic_t work_count;
	int index;
	int error;
};

MARS_TYPES(sio);

#endif
