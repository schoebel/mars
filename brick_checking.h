// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_CHECKING_H
#define BRICK_CHECKING_H

/////////////////////////////////////////////////////////////////////////

// checking

#ifdef CONFIG_MARS_DEBUG
#define BRICK_CHECKING true
#else
#define BRICK_CHECKING false
#endif

#define _CHECK_ATOMIC(atom,OP,minval)					\
do {									\
	if (BRICK_CHECKING) {						\
		int __test = atomic_read(atom);				\
		if (__test OP (minval)) {				\
			atomic_set(atom, minval);			\
			BRICK_ERR("%d: atomic " #atom " " #OP " " #minval " (%d)\n", __LINE__, __test); \
		}							\
	}								\
} while (0)

#define CHECK_ATOMIC(atom,minval)		\
	_CHECK_ATOMIC(atom, <, minval)

#define CHECK_HEAD_EMPTY(head)						\
do {									\
	if (BRICK_CHECKING && unlikely(!list_empty(head) && (head)->next)) { \
		list_del_init(head);					\
		BRICK_ERR("%d: list_head " #head " (%p) not empty\n", __LINE__, head); \
	}								\
} while (0)

#define CHECK_PTR_DEAD(ptr,label)					\
do {									\
	if (BRICK_CHECKING && unlikely((ptr) == (void*)0x5a5a5a5a5a5a5a5a)) { \
		BRICK_FAT("%d: pointer '" #ptr "' is DEAD\n", __LINE__); \
		goto label;						\
	}								\
} while (0)

#define CHECK_PTR_NULL(ptr,label)					\
do {									\
	CHECK_PTR_DEAD(ptr, label);					\
	if (BRICK_CHECKING && unlikely(!(ptr))) {		        \
		BRICK_FAT("%d: pointer '" #ptr "' is NULL\n", __LINE__); \
		goto label;						\
	}								\
} while (0)

#define CHECK_PTR(ptr,label)						\
do {									\
	CHECK_PTR_NULL(ptr, label);					\
	if (BRICK_CHECKING && unlikely(!virt_addr_valid(ptr))) {	\
		BRICK_FAT("%d: pointer '" #ptr "' (%p) is no valid virtual KERNEL address\n", __LINE__, ptr); \
		goto label;						\
	}								\
} while (0)

#define _CHECK(ptr,label)						\
do {									\
	if (BRICK_CHECKING && unlikely(!(ptr))) {			\
		BRICK_FAT("%d: condition '" #ptr "' is VIOLATED\n", __LINE__); \
		goto label;						\
	}								\
} while (0)

#endif
