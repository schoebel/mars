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
#ifndef CURRENT_TIME
#include <linux/timekeeping.h>
#endif

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

#include <linux/rwsem.h>

struct lamport_clock {
	struct rw_semaphore lamport_sem;
	struct lamport_time lamport_stamp;
};

extern struct lamport_clock global_lamport;

/* Protect against illegal values, e.g. from currupt filesystems etc.
 */
extern int max_lamport_future;

/*
 * We always get both the local real time and the Lamport time in parallel,
 * consistently.
 *
 * The implementation ensures that the distributed Lamport timestamp can
 * never fall behind the local real time.
 *
 * When not interested in real time, you can simply leave real_now at NULL.
 */
extern void _get_lamport(struct lamport_clock *clock,
			 struct lamport_time *real_now,
			 struct lamport_time *lamport_now);

/* This ensures _strict_ monotonicity of the Lamport clock */
extern void _set_lamport(struct lamport_clock *clock,
			 struct lamport_time *lamport_advance);

/* Non-strict version.
 * Use this for better performance when strictness is not needed.
 */
extern void _set_lamport_nonstrict(struct lamport_clock *clock,
				   struct lamport_time *lamport_advance);

/* After strictly advancing the Lamport time, re-get the new values.
 * This is almost equivalent to a sequence of set_lamport() ; get_lamport()
 * but (1) atomic and (2) more efficient
 * because the internal lock is taken only once.
 */
extern void _set_get_lamport(struct lamport_clock *clock,
			     struct lamport_time *lamport_advance,
			     struct lamport_time *real_now,
			     struct lamport_time *lamport_now);

extern bool _protect_lamport_time(struct lamport_clock *clock,
				  struct lamport_time *check);


/* Usually the following versions are the preferred ones for working
 * on the single global lamport clock instance.
 */

#define get_lamport(real_now,lamport_now)			\
	_get_lamport(&global_lamport,real_now,lamport_now)

#define set_lamport(lamport_advance)			\
	_set_lamport(&global_lamport,lamport_advance)

#define set_lamport_nonstrict(lamport_advance)			\
	_set_lamport_nonstrict(&global_lamport,lamport_advance)

#define set_get_lamport(lamport_advance,real_now,lamport_now)		\
	_set_get_lamport(&global_lamport,lamport_advance,real_now,lamport_now)

#define protect_lamport_time(check)				\
	_protect_lamport_time(&global_lamport,check)

/*
 * Here is a very general lockless version for inlining.
 * Typical usage is when no true concurrency can happen, or when
 * some other embracing locks are already protecting the scene.
 * All pointers except clock may be NULL, then no code
 * will be generated.
 */
static inline
void __lamport_op(struct lamport_time *clock,
		  struct lamport_time *lamport_prev,
		  struct lamport_time *lamport_advance,
		  struct lamport_time *real_now,
		  struct lamport_time *lamport_now)
{
	/* Remember the old clock value. */
	if (lamport_prev)
		*lamport_prev = *clock;

	/* Advance the clock when necessary. */
	if (lamport_advance)
		if (lamport_time_compare(lamport_advance, clock) > 0)
			*clock = *lamport_advance;
		else
			*clock = lamport_time_add(*clock,
						  (struct lamport_time){0, 1});
	else
		*clock = lamport_time_add(*clock,
					  (struct lamport_time){0, 1});

	/* Get and handle realtime */
	if (real_now) {
		*real_now = get_real_lamport();
		if (lamport_time_compare(real_now, clock) > 0)
			*clock = *real_now;
	}

	/* Finally, retrieve new lamport stamp */
	if (lamport_now)
		*lamport_now = *clock;
}

#endif
