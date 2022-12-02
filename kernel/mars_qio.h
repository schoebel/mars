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

#ifndef MARS_QIO_H
#define MARS_QIO_H

#include <linux/fs.h>

#include "lib_qio_rw.h"
#include "lib_mapfree.h"

#define QIO_IO_R_MAX_LATENCY     50000 //  50 ms
#define QIO_IO_W_MAX_LATENCY    150000 // 150 ms

extern int mars_qio_hang_timeout_s;

struct qio_anchors {
	struct mutex prio_mutex;
	struct list_head submitted_list;
	wait_queue_head_t event;
	struct task_struct *thread;
	struct qio_brick *brick;
	int anch_prio;
	bool should_wake_now;
	bool should_terminate;
	bool has_terminated;
	bool all_have_expired;
};

struct qio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	struct lamport_time started_stamp;
	struct lamport_time enqueue_stamp;
	struct lamport_time dequeue_stamp;
	struct lamport_time completion_stamp;
	struct qio_anchors *anch;
	struct qio_rw qio_rw;
	int alloc_len;
	int qio_error;
	int nr_requeue;
	bool do_dealloc;
	bool is_write;
	bool is_active;
	bool use_nowait;
	bool has_expired;
};

struct qio_brick {
	MARS_BRICK(qio);
	/* in parameters */
	bool o_creat;
	/* out parameters */
	int error;
	/* private */
	struct file *file;
	struct mapfree_info *mf;
	struct qio_anchors thread_anch[2];
	/* statistics */
	struct lamport_time last_started_stamp;
	struct lamport_time last_submitted_stamp;
#ifdef CONFIG_MARS_DEBUG
	struct lamport_time last_dequeue_stamp;
#endif
	struct lamport_time last_completion_stamp;
	struct lamport_time last_hanging_stamp;
	atomic_t flying_reads;
	atomic_t flying_writes;
#ifdef CONFIG_MARS_DEBUG
	loff_t submit_pos;
	loff_t complet_pos;
	int submit_len;
	int complet_len;
#endif
};

struct qio_input {
	MARS_INPUT(qio);
	/* parameters */
	/* private */
};

struct qio_output {
	MARS_OUTPUT(qio);
	/* parameters */
	/* private */
};

MARS_TYPES(qio);

#endif
