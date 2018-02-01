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

#ifndef LAMPORT_H
#define LAMPORT_H

#include <linux/time.h>

/*
 * We always get both the local real time and the Lamport time in parallel,
 * consistently.
 *
 * The implementation ensures that the distributed Lamport timestamp can
 * never fall behind the local real time.
 *
 * When not interested in real time, you can simply leave real_now at NULL.
 */
extern void get_lamport(struct timespec *real_now, struct timespec *lamport_now);

/* This ensures _strict_ monotonicity of the Lamport clock */
extern void set_lamport(struct timespec *lamport_old);

/* Non-strict version.
 * Use this for better performance when strictness is not needed.
 */
extern void set_lamport_nonstrict(struct timespec *lamport_old);

/* After strictly advancing the Lamport time, re-get the new values.
 * This is almost equivalent to a sequence of set_lamport() ; get_lamport()
 * but (1) atomic and (2) more efficient
 * because the internal lock is taken only once.
 */
extern void set_get_lamport(struct timespec *lamport_old, struct timespec *real_now, struct timespec *lamport_now);

/* Protect against illegal values, e.g. from currupt filesystems etc.
 */
extern int max_lamport_future;

extern bool protect_timespec(struct timespec *check);

#endif
