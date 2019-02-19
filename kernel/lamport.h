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
#include <linux/ktime.h>
#include <linux/timekeeping.h>

/* Adapt to upstream commits
 * 8758a240e2d74c5932ab51a73377e6507b7fd441
 * bfe1c566453a0979c0b3cd3728d0de962272f034
 */
#ifndef CURRENT_TIME
# include <linux/time64.h>
# define lamport_time         timespec64
# define lamport_time_to_ns   timespec64_to_ns
# define ns_to_lamport_time   ns_to_timespec64
# define lamport_time_compare timespec64_compare
# define lamport_time_add     timespec64_add
# define lamport_time_add_ns  timespec64_add_ns
# define lamport_time_sub     timespec64_sub
# define get_real_lamport     current_kernel_time64
#else /* deprecated */
# define lamport_time         timespec
# define lamport_time_to_ns   timespec_to_ns
# define ns_to_lamport_time   ns_to_timespec
# define lamport_time_compare timespec_compare
# define lamport_time_add     timespec_add
# define lamport_time_add_ns  timespec_add_ns
# define lamport_time_sub     timespec_sub
# define get_real_lamport()   CURRENT_TIME
#endif

/*
 * We always get both the local real time and the Lamport time in parallel,
 * consistently.
 *
 * The implementation ensures that the distributed Lamport timestamp can
 * never fall behind the local real time.
 *
 * When not interested in real time, you can simply leave real_now at NULL.
 */
extern void get_lamport(struct lamport_time *real_now,
			struct lamport_time *lamport_now);

/* This ensures _strict_ monotonicity of the Lamport clock */
extern void set_lamport(struct lamport_time *lamport_old);

/* Non-strict version.
 * Use this for better performance when strictness is not needed.
 */
extern void set_lamport_nonstrict(struct lamport_time *lamport_old);

/* After strictly advancing the Lamport time, re-get the new values.
 * This is almost equivalent to a sequence of set_lamport() ; get_lamport()
 * but (1) atomic and (2) more efficient
 * because the internal lock is taken only once.
 */
extern void set_get_lamport(struct lamport_time *lamport_old,
			    struct lamport_time *real_now,
			    struct lamport_time *lamport_now);

/* Protect against illegal values, e.g. from currupt filesystems etc.
 */
extern int max_lamport_future;

extern bool protect_lamport_time(struct lamport_time *check);

#endif
