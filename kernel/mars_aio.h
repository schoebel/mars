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

#ifndef MARS_AIO_H
#define MARS_AIO_H

#include <linux/aio.h>
#include <linux/syscalls.h>

#include "mars.h"
#include "lib_mapfree.h"

#define AIO_SUBMIT_MAX_LATENCY    1000 //   1 ms
#define AIO_IO_R_MAX_LATENCY     50000 //  50 ms
#define AIO_IO_W_MAX_LATENCY    150000 // 150 ms
#define AIO_SYNC_MAX_LATENCY    150000 // 150 ms

extern struct threshold aio_submit_threshold;
extern struct threshold aio_io_threshold[2];
extern struct threshold aio_sync_threshold;

/* aio_sync_mode:
 *  0 = filemap_write_and_wait_range()
 *  1 = fdatasync()
 *  2 = fsync()
 */
extern int aio_sync_mode;

struct aio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	unsigned long long enqueue_stamp;
	long long start_jiffies;
	int resubmit;
	int alloc_len;
	bool do_dealloc;
};

struct aio_brick {
	MARS_BRICK(aio);
	// parameters
	bool o_creat;
	bool o_direct;
	bool o_fdsync;
	bool is_static_device;
};

struct aio_input {
	MARS_INPUT(aio);
};

struct aio_threadinfo {
	struct list_head mref_list[MARS_PRIO_NR];
	struct aio_output *output;
	struct task_struct *thread;
	wait_queue_head_t event;
	wait_queue_head_t terminate_event;
	struct mutex mutex;
	int queued[MARS_PRIO_NR];
	atomic_t queued_sum;
	atomic_t total_enqueue_count;
	bool should_terminate;
	bool terminated;
};

struct aio_output {
	MARS_OUTPUT(aio);
        // private
	struct mapfree_info *mf;
	int fd; // FIXME: remove this!
	struct aio_threadinfo tinfo[3];
	aio_context_t ctxp;
	wait_queue_head_t fdsync_event;
	bool fdsync_active;
	// statistics
	int index;
	atomic_t work_count;
	atomic_t total_read_count;
	atomic_t total_write_count;
	atomic_t total_alloc_count;
	atomic_t total_submit_count;
	atomic_t total_again_count;
	atomic_t total_delay_count;
	atomic_t total_msleep_count;
	atomic_t total_fdsync_count;
	atomic_t total_fdsync_wait_count;
	atomic_t total_mapfree_count;
	atomic_t read_count;
	atomic_t write_count;
	atomic_t alloc_count;
	atomic_t submit_count;
};

MARS_TYPES(aio);

#endif
