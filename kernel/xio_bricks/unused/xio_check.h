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

#ifndef XIO_CHECK_H
#define XIO_CHECK_H

#define CHECK_LOCK

struct check_aio_aspect {
	GENERIC_ASPECT(aio);
#ifdef CHECK_LOCK
	struct list_head aio_head;

#endif
	struct generic_callback cb;
	struct check_output *output;
	unsigned long last_jiffies;
	atomic_t call_count;
	atomic_t callback_count;
	bool installed;
};

struct check_brick {
	XIO_BRICK(check);
};

struct check_input {
	XIO_INPUT(check);
};

struct check_output {
	XIO_OUTPUT(check);
	int instance_nr;

#ifdef CHECK_LOCK
	struct task_struct *watchdog;
	spinlock_t check_lock;
	struct list_head aio_anchor;

#endif
};

XIO_TYPES(check);

#endif
