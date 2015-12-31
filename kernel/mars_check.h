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

#ifndef MARS_CHECK_H
#define MARS_CHECK_H

#define CHECK_LOCK

struct check_mref_aspect {
	GENERIC_ASPECT(mref);
#ifdef CHECK_LOCK
	struct list_head mref_head;

#endif
	struct generic_callback cb;
	struct check_output *output;
	unsigned long last_jiffies;
	atomic_t call_count;
	atomic_t callback_count;
	bool installed;
};

struct check_brick {
	MARS_BRICK(check);
};

struct check_input {
	MARS_INPUT(check);
};

struct check_output {
	MARS_OUTPUT(check);
	int instance_nr;

#ifdef CHECK_LOCK
	struct task_struct *watchdog;
	spinlock_t check_lock;
	struct list_head mref_anchor;

#endif
};

MARS_TYPES(check);

#endif
