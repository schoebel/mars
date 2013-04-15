// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_ATOMIC_H
#define BRICK_ATOMIC_H

#include <linux/spinlock.h>

#include <asm/atomic.h>

#include "brick_checking.h"

#define ATOMIC_DEBUGGING

#ifndef CONFIG_MARS_DEBUG
#undef  ATOMIC_DEBUGGING
#endif

#define ATOMIC_MAXTRACE 32

/* Trivial wrapper to force type checking.
 */
typedef struct tatomic {
	atomic_t ta_atomic;
} tatomic_t;

typedef struct atomic_trace {
#ifdef ATOMIC_DEBUGGING
	atomic_t    at_count;
	short       at_lines[ATOMIC_MAXTRACE];
	pid_t       at_pids[ATOMIC_MAXTRACE];
	const char *at_sources[ATOMIC_MAXTRACE];
#endif
} atomic_trace_t;

#ifdef ATOMIC_DEBUGGING

#define tatomic_trace(_at, _cmd)					\
	({								\
		int _index = atomic_add_return(1, &(_at)->at_count) - 1; \
		if (likely(_index >= 0 && _index < ATOMIC_MAXTRACE)) {	\
			(_at)->at_lines[_index] = __LINE__;		\
			(_at)->at_pids[_index] = current->pid;		\
			(_at)->at_sources[_index] = __BASE_FILE__;	\
		}							\
		_cmd;							\
	})

#define tatomic_out(_at,_MSG)						\
	({								\
		int __i;						\
		int __max = atomic_read(&(_at)->at_count);		\
		_MSG("at_count = %d\n", __max);				\
		if (unlikely(__max > ATOMIC_MAXTRACE))			\
			__max = ATOMIC_MAXTRACE;			\
		for (__i = 0; __i < __max; __i++) {			\
			_MSG("%2d pid=%d %s:%d\n", __i, (_at)->at_pids[__i], (_at)->at_sources[__i], (_at)->at_lines[__i]);	\
		}							\
	})

#define _CHECK_TATOMIC(_at,_atom,OP,_minval,_fixval)			\
do {									\
	if (BRICK_CHECKING) {						\
		int __test = atomic_read(&(_atom)->ta_atomic);		\
		if (unlikely(__test OP (_minval))) {			\
			atomic_set(&(_atom)->ta_atomic, _fixval);	\
			BRICK_ERR("%d: tatomic " #_atom " " #OP " " #_minval " (%d)\n", __LINE__, __test); \
			tatomic_out(_at, BRICK_DMP);			\
		}							\
	}								\
} while (0)

#else

#define tatomic_trace(_at,_cmd)  _cmd

#define _CHECK_TATOMIC(_at,_atom,OP,_minval,_fixval)			\
	_CHECK_ATOMIC(&(_atom)->ta_atomic, OP, _minval)

#endif

#define CHECK_TATOMIC(_at,_atom,_minval)		\
	_CHECK_TATOMIC(_at, _atom, <, _minval, _minval)

#define tatomic_inc(at,a)           tatomic_trace(at, atomic_inc(&(a)->ta_atomic))
#define tatomic_dec(at,a)           tatomic_trace(at, atomic_dec(&(a)->ta_atomic))
#define tatomic_dec_and_test(at,a)  tatomic_trace(at, atomic_dec_and_test(&(a)->ta_atomic))

#endif
