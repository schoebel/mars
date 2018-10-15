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

#ifndef BRICK_WAIT_H
#define BRICK_WAIT_H

/* compat to some elder kernels...
 */
#ifndef ___wait_cond_timeout
#define ___wait_cond_timeout(x) (x)
#define prepare_to_wait_event(a,b,c) (prepare_to_wait(a, b, c), 0)
#endif

/* Some code stolen from include/linux/wait.h
 */
#define brick_wait(wq, condition, timeout)				\
({									\
	__label__ __out;						\
	wait_queue_t __wait;						\
	long __ret = timeout;	/* explicit shadow */			\
									\
	might_sleep();							\
	/* check in advance to avoid spinlocks in fastpath */		\
	if (condition)							\
		goto __out;						\
									\
	INIT_LIST_HEAD(&__wait.task_list);				\
	__wait.flags = 0;						\
									\
	for (;;) {							\
		long __int = prepare_to_wait_event(&wq, &__wait, TASK_INTERRUPTIBLE); \
									\
		if (__int) {						\
			__ret = __int;					\
			break;						\
		}							\
									\
		__ret = schedule_timeout(__ret);			\
									\
		__set_current_state(TASK_RUNNING);			\
		if (___wait_cond_timeout(condition))			\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
__out:	__ret;								\
})


#endif
