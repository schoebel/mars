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

#ifndef XIO_COPY_H
#define XIO_COPY_H

#include <linux/wait.h>
#include <linux/semaphore.h>

#define INPUT_A_IO			0
#define INPUT_A_COPY			1
#define INPUT_B_IO			2
#define INPUT_B_COPY			3

extern int xio_copy_overlap;
extern int xio_copy_read_prio;
extern int xio_copy_write_prio;
extern int xio_copy_read_max_fly;
extern int xio_copy_write_max_fly;

enum {
	COPY_STATE_RESET = -1,
	COPY_STATE_START = 0, /*  don't change this, it _must_ be zero */
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
	struct aio_object *table[2];
	bool active[2];
	char state;
	bool writeout;

	short prev;
	short len;
	short error;
};

struct copy_aio_aspect {
	GENERIC_ASPECT(aio);
	struct copy_brick *brick;
	int queue;
};

struct copy_brick {
	XIO_BRICK(copy);
	/*  parameters */
	struct rate_limiter *copy_limiter;
	loff_t copy_start;

	loff_t copy_end; /*  stop working if == 0 */
	int io_prio;

	int append_mode; /*  1 = passively, 2 = actively */
	bool verify_mode; /*  0 = copy, 1 = checksum+compare */
	bool repair_mode; /*  whether to repair in case of verify errors */
	bool recheck_mode; /*  whether to re-check after repairs (costs performance) */
	bool utilize_mode; /*  utilize already copied data */
	bool abort_mode;  /*  abort on IO error (default is retry forever) */
	/*  readonly from outside */
	loff_t copy_last; /*  current working position */
	struct timespec copy_last_stamp;
	int copy_error;
	int copy_error_count;
	int verify_ok_count;
	int verify_error_count;
	bool low_dirty;
	bool is_aborting;

	/*  internal */
	bool trigger;
	unsigned long clash;
	atomic_t total_clash_count;
	atomic_t io_flight;
	atomic_t copy_read_flight;
	atomic_t copy_write_flight;
	unsigned long last_jiffies;

	wait_queue_head_t event;
	struct semaphore mutex;
	struct task_struct *thread;
	struct copy_state **st;
};

struct copy_input {
	XIO_INPUT(copy);
};

struct copy_output {
	XIO_OUTPUT(copy);
};

XIO_TYPES(copy);

#endif
