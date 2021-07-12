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

#ifndef MARS_COPY_H
#define MARS_COPY_H

#include <linux/wait.h>

#define INPUT_A       0
#define INPUT_B       1
#define COPY_INPUT_NR 2

extern int mars_copy_overlap;
extern int mars_copy_strict_write_order;
extern int mars_copy_timeout;
extern int mars_copy_read_prio;
extern int mars_copy_write_prio;
extern int mars_copy_read_max_fly;
extern int mars_copy_write_max_fly;

extern atomic_t global_copy_read_flight;
extern atomic_t global_copy_write_flight;

enum {
	COPY_STATE_RESET    = -1,
	COPY_STATE_START    = 0, // don't change this, it _must_ be zero
	COPY_STATE_START2,
	COPY_STATE_READ1,
	COPY_STATE_READ2,
	COPY_STATE_READ3,
	COPY_STATE_WRITE,
	COPY_STATE_WRITTEN,
	COPY_STATE_CLEANUP,
	COPY_STATE_FINISHED,
};

struct copy_state {
	struct mref_object *table[2];
	bool active[2];
	char state;
	bool writeout;
	short prev;
	unsigned short len;
	short error;
};

struct copy_mref_aspect {
	GENERIC_ASPECT(mref);
	struct copy_input *input;
	struct copy_brick *brick;
	unsigned queue;
};

struct copy_brick {
	MARS_BRICK(copy);
	// parameters
	struct mars_limiter *copy_limiter;
	loff_t copy_start;
	loff_t copy_end; // stop working if == 0
	int io_prio;
	int append_mode; // 1 = passively, 2 = actively
	bool verify_mode; // 0 = copy, 1 = checksum+compare
	bool repair_mode; // whether to repair in case of verify errors
	bool recheck_mode; // whether to re-check after repairs (costs performance)
	bool utilize_mode; // utilize already copied data
	bool abort_mode;  // abort on IO error (default is retry forever)
	// readonly from outside
	loff_t copy_last; // current working position
	loff_t copy_dirty; // end of current working area
	struct lamport_time copy_last_stamp;
	int copy_error;
	int copy_error_count;
	int verify_ok_count;
	int verify_error_count;
	bool low_dirty;
	bool is_aborting;
	// internal
	bool trigger;
	bool terminated;
	unsigned long clash;
	atomic_t total_clash_count;
	atomic_t io_flight;
	atomic_t copy_read_flight;
	atomic_t copy_write_flight;
	long long last_jiffies;
	wait_queue_head_t event;
	struct task_struct *thread;
	struct copy_state **st;
};

struct copy_input {
	MARS_INPUT(copy);
	loff_t check_hint;
};

struct copy_output {
	MARS_OUTPUT(copy);
};

MARS_TYPES(copy);

#endif
