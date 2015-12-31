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

#ifndef BRICK_CHECKING_H
#define BRICK_CHECKING_H

/////////////////////////////////////////////////////////////////////////

// checking

#if defined(CONFIG_MARS_DEBUG) || defined(CONFIG_MARS_CHECKS)
#define BRICK_CHECKING			true
#else
#define BRICK_CHECKING			false
#endif

#define _CHECK_ATOMIC(atom, OP, minval)					\
do {									\
	if (BRICK_CHECKING) {						\
		int __test = atomic_read(atom);				\
		if (unlikely(__test OP(minval))) {			\
			atomic_set(atom, minval);			\
			BRICK_ERR("%d: atomic " #atom " " #OP " " #minval " (%d)\n", __LINE__, __test);\
		}							\
	}								\
} while (0)

#define CHECK_ATOMIC(atom, minval)					\
	_CHECK_ATOMIC(atom, <, minval)

#define CHECK_HEAD_EMPTY(head)						\
do {									\
	if (BRICK_CHECKING && unlikely(!list_empty(head) && (head)->next)) {\
		list_del_init(head);					\
		BRICK_ERR("%d: list_head " #head " (%p) not empty\n", __LINE__, head);\
	}								\
} while (0)

#ifdef CONFIG_MARS_DEBUG_MEM
#define CHECK_PTR_DEAD(ptr, label)					\
do {									\
	if (BRICK_CHECKING && unlikely((ptr) == (void *)0x5a5a5a5a5a5a5a5a)) {\
		BRICK_FAT("%d: pointer '" #ptr "' is DEAD\n", __LINE__);\
		goto label;						\
	}								\
} while (0)
#else
#define CHECK_PTR_DEAD(ptr, label) /*empty*/
#endif

#define CHECK_PTR_NULL(ptr, label)					\
do {									\
	CHECK_PTR_DEAD(ptr, label);					\
	if (BRICK_CHECKING && unlikely(!(ptr))) {			\
		BRICK_FAT("%d: pointer '" #ptr "' is NULL\n", __LINE__);\
		goto label;						\
	}								\
} while (0)

#ifdef CONFIG_MARS_DEBUG
#define CHECK_PTR(ptr, label)						\
do {									\
	CHECK_PTR_NULL(ptr, label);					\
	if (BRICK_CHECKING && unlikely(!virt_addr_valid(ptr))) {	\
		BRICK_FAT("%d: pointer '" #ptr "' (%p) is no valid virtual KERNEL address\n", __LINE__, ptr);\
		goto label;						\
	}								\
} while (0)
#else
#define CHECK_PTR(ptr, label) CHECK_PTR_NULL(ptr, label)
#endif

#define CHECK_ASPECT(a_ptr, o_ptr, label)				\
do {									\
	if (BRICK_CHECKING && unlikely((a_ptr)->object != o_ptr)) {	\
		BRICK_FAT("%d: aspect pointer '" #a_ptr "' (%p) belongs to object %p, not to " #o_ptr " (%p)\n",\
			__LINE__, a_ptr, (a_ptr)->object, o_ptr);	\
		goto label;						\
	}								\
} while (0)

#define _CHECK(ptr, label)						\
do {									\
	if (BRICK_CHECKING && unlikely(!(ptr))) {			\
		BRICK_FAT("%d: condition '" #ptr "' is VIOLATED\n", __LINE__);\
		goto label;						\
	}								\
} while (0)

#endif
