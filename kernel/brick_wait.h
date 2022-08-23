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

/* Historic adaptor.
 * To disappear somewhen.
 */
#define brick_wait_flagged(wq, flag, condition, timeout)		\
({									\
	long __tmout = (timeout);					\
	int __old_flag;							\
									\
	might_sleep();							\
	smp_rmb();							\
	__old_flag = (flag);						\
									\
	while (!(condition)) {						\
		int __new_flag;						\
									\
		__tmout = wait_event_interruptible_timeout(		\
					wq,				\
					({ smp_rmb();			\
					  __new_flag = (flag);		\
					  __old_flag != __new_flag; }),	\
					__tmout);			\
		if (__tmout <= 1)					\
			break;						\
		__old_flag = __new_flag;				\
	}								\
	__tmout;							\
})

#define brick_wake_flagged(wq, flag)					\
({									\
	smp_rmb();							\
	(flag)++;							\
	smp_wmb();							\
	wake_up_interruptible_all(wq);					\
})


#endif
