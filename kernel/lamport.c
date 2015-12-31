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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>

#include "lamport.h"

// TODO: replace with spinlock if possible (first check)
struct semaphore lamport_sem = __SEMAPHORE_INITIALIZER(lamport_sem, 1);
struct timespec lamport_now = {};

void get_lamport(struct timespec *now)
{
	int diff;

	down(&lamport_sem);

	*now = CURRENT_TIME;
	diff = timespec_compare(now, &lamport_now);
	if (diff >= 0) {
		timespec_add_ns(now, 1);
		memcpy(&lamport_now, now, sizeof(lamport_now));
		timespec_add_ns(&lamport_now, 1);
	} else {
		timespec_add_ns(&lamport_now, 1);
		memcpy(now, &lamport_now, sizeof(*now));
	}

	up(&lamport_sem);
}

void set_lamport(struct timespec *old)
{
	int diff;

	down(&lamport_sem);

	diff = timespec_compare(old, &lamport_now);
	if (diff >= 0) {
		memcpy(&lamport_now, old, sizeof(lamport_now));
		timespec_add_ns(&lamport_now, 1);
	}

	up(&lamport_sem);
}
