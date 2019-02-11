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

/* Try to abstract from changes of the upstream kernel
 * by using a hopefully stable interface.
 */
#define brick_wait(wq, flag, condition, timeout)			\
({									\
	unsigned long __tmout = (timeout);				\
									\
	might_sleep();							\
	(flag) = false;							\
	smp_wmb();							\
	while (!(condition)) {						\
		__tmout = wait_event_interruptible_timeout(		\
					wq,				\
					({ smp_rmb(); (flag); }),	\
					__tmout);			\
		if (__tmout <= 1)					\
			break;						\
		(flag) = false;						\
		smp_wmb();						\
	}								\
	__tmout;							\
})

#define brick_wake(wq, flag)						\
({									\
	(flag) = true;							\
	smp_wmb();							\
	wake_up_interruptible_all(wq);					\
})


#endif
