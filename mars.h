// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_H
#define MARS_H

#include <linux/list.h>
#include <asm/spinlock.h>
#include <asm/atomic.h>

#define MARS_DELAY /**/
//#define MARS_DELAY msleep(20000)

#define MARS_FATAL "MARS_FATAL  " __BASE_FILE__ ": "
#define MARS_ERROR "MARS_ERROR  " __BASE_FILE__ ": "
#define MARS_INFO  "MARS_INFO   " __BASE_FILE__ ": "
#define MARS_DEBUG "MARS_DEBUG  " __BASE_FILE__ ": "

#define MARS_FAT(fmt, args...) do { printk(MARS_FATAL "%s(): " fmt, __FUNCTION__, ##args); MARS_DELAY; } while (0)
#define MARS_ERR(fmt, args...) do { printk(MARS_ERROR "%s(): " fmt, __FUNCTION__, ##args); MARS_DELAY; } while (0)
#define MARS_INF(fmt, args...) do { printk(MARS_INFO  "%s(): " fmt, __FUNCTION__, ##args); } while (0)
#ifdef MARS_DEBUGGING
#define MARS_DBG(fmt, args...) do { printk(MARS_DEBUG "%s(): " fmt, __FUNCTION__, ##args); } while (0)
#else
#define MARS_DBG(args...) /**/
#endif

#define BRICK_OBJ_MARS_REF            0
#define BRICK_OBJ_NR                  1

#define GFP_MARS GFP_NOIO

#include "brick.h"

/////////////////////////////////////////////////////////////////////////

// MARS-specific definitions

// object stuff

/* mars_ref */

#define MARS_REF_UPTODATE        1
#define MARS_REF_READING         2
#define MARS_REF_WRITING         4

extern const struct generic_object_type mars_ref_type;

struct mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
};

struct mars_ref_aspect_layout {
	GENERIC_ASPECT_LAYOUT(mars_ref);
};

struct mars_ref_object_layout {
	GENERIC_OBJECT_LAYOUT(mars_ref);
};

#define MARS_REF_OBJECT(PREFIX)						\
	GENERIC_OBJECT(PREFIX);						\
	/* supplied by caller */					\
	loff_t ref_pos;							\
	int    ref_len;							\
	int    ref_may_write;						\
	void  *ref_data;         /* preset to NULL for buffered IO */	\
	/* maintained by the ref implementation, readable for callers */ \
	int    ref_flags;						\
	int    ref_rw;							\
	/* maintained by the ref implementation, incrementable for	\
	 * callers (but not decrementable! use ref_put()) */		\
	atomic_t ref_count;						\
        /* callback part */						\
	struct generic_callback *ref_cb;				\

struct mars_ref_object {
	MARS_REF_OBJECT(mars_ref);
};

// internal helper structs

struct mars_info {
	loff_t current_size;
	int transfer_order;
	int transfer_size;
	struct file *backing_file;
};

// brick stuff

#define MARS_BRICK(PREFIX)						\
	GENERIC_BRICK(PREFIX);						\

struct mars_brick {
	MARS_BRICK(mars);
};

#define MARS_INPUT(PREFIX)						\
	GENERIC_INPUT(PREFIX);						\

struct mars_input {
	MARS_INPUT(mars);
};

#define MARS_OUTPUT(PREFIX)						\
	GENERIC_OUTPUT(PREFIX);						\

struct mars_output {
	MARS_OUTPUT(mars);
};

#define MARS_BRICK_OPS(PREFIX)						\
	GENERIC_BRICK_OPS(PREFIX);					\
	int (*mars_dummy_op)(int);					\
	
#define MARS_OUTPUT_OPS(PREFIX)						\
	GENERIC_OUTPUT_OPS(PREFIX);					\
	int  (*mars_get_info)(struct PREFIX##_output *output, struct mars_info *info); \
	/* mars_ref */							\
	int  (*mars_ref_get)(struct PREFIX##_output *output, struct mars_ref_object *mref); \
	void (*mars_ref_io)(struct PREFIX##_output *output, struct mars_ref_object *mref); \
	void (*mars_ref_put)(struct PREFIX##_output *output, struct mars_ref_object *mref); \

// all non-extendable types

#define _MARS_TYPES(BRICK)						\
									\
struct BRICK##_brick_ops {                                              \
        MARS_BRICK_OPS(BRICK);                                          \
};                                                                      \
                                                                        \
struct BRICK##_output_ops {					        \
	MARS_OUTPUT_OPS(BRICK);						\
};                                                                      \
									\
struct BRICK##_brick_type {                                             \
	GENERIC_BRICK_TYPE(BRICK);                                      \
};									\
									\
struct BRICK##_input_type {					        \
	GENERIC_INPUT_TYPE(BRICK);                                      \
};									\
									\
struct BRICK##_output_type {					        \
	GENERIC_OUTPUT_TYPE(BRICK);                                     \
};									\
									\
struct BRICK##_callback {					        \
	GENERIC_CALLBACK(BRICK);					\
};									\
									\
GENERIC_MAKE_FUNCTIONS(BRICK);					        \
GENERIC_MAKE_CONNECT(BRICK,BRICK);				        \


#define MARS_TYPES(BRICK)						\
									\
_MARS_TYPES(BRICK)						        \
									\
struct BRICK##_object_layout;						\
									\
GENERIC_MAKE_CONNECT(generic,BRICK);				        \
GENERIC_OBJECT_LAYOUT_FUNCTIONS(BRICK);				        \
GENERIC_ASPECT_LAYOUT_FUNCTIONS(BRICK,mars_ref);		        \
GENERIC_ASPECT_FUNCTIONS(BRICK,mars_ref);			        \


// instantiate all mars-specific functions

GENERIC_OBJECT_FUNCTIONS(mars_ref);

/////////////////////////////////////////////////////////////////////////

// MARS-specific helper functions

#define MARS_MAKE_STATICS(BRICK)					\
									\
int BRICK##_brick_nr = -EEXIST;				                \
EXPORT_SYMBOL_GPL(BRICK##_brick_nr);			                \
									\
static const struct generic_aspect_type BRICK##_mars_ref_aspect_type = { \
	.aspect_type_name = #BRICK "_mars_ref_aspect_type",		\
	.object_type = &mars_ref_type,					\
	.aspect_size = sizeof(struct BRICK##_mars_ref_aspect),		\
	.init_fn = BRICK##_mars_ref_aspect_init_fn,			\
	.exit_fn = BRICK##_mars_ref_aspect_exit_fn,			\
};									\
									\
static const struct generic_aspect_type *BRICK##_aspect_types[BRICK_OBJ_NR] = {	\
	[BRICK_OBJ_MARS_REF] = &BRICK##_mars_ref_aspect_type,		\
};									\

#define _CHECK_ATOMIC(atom,OP,minval)					\
	do {								\
		int test = atomic_read(atom);				\
		if (test OP (minval)) {					\
			atomic_set(atom, minval);			\
			MARS_ERR("%d: atomic " #atom " " #OP " " #minval " (instead %d)\n", __LINE__, test); \
		}							\
	} while (0)

#define CHECK_ATOMIC(atom,minval)			\
	_CHECK_ATOMIC(atom, <, minval)

#define CHECK_HEAD_EMPTY(head)						\
	if (unlikely(!list_empty(head))) {				\
		INIT_LIST_HEAD(head);					\
		MARS_ERR("%d: list_head " #head " (%p) not empty\n", __LINE__, head); \
	}								\

#endif

#define CHECK_PTR(ptr,label)						\
	if (unlikely(!(ptr))) {						\
		MARS_FAT("%d: ptr " #ptr " is NULL\n", __LINE__);	\
		goto label;						\
	}

#define _CHECK(ptr,label)						\
	if (unlikely(!(ptr))) {						\
		MARS_FAT("%d: condition " #ptr " is VIOLATED\n", __LINE__); \
		goto label;						\
	}
