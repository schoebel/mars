// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_H
#define MARS_H

#include <linux/list.h>
#include <asm/spinlock.h>
#include <asm/atomic.h>

#define MARS_ERROR "MARS_ERROR  " __BASE_FILE__ ": "
#define MARS_INFO  "MARS_INFO   " __BASE_FILE__ ": "
#define MARS_DEBUG "MARS_DEBUG  " __BASE_FILE__ ": "

#define MARS_ERR(fmt, args...) printk(MARS_ERROR "%s(): " fmt, __FUNCTION__, ##args)
#define MARS_INF(fmt, args...) printk(MARS_INFO  "%s(): " fmt, __FUNCTION__, ##args)
#ifdef MARS_DEBUGGING
#define MARS_DBG(fmt, args...) printk(MARS_DEBUG "%s(): " fmt, __FUNCTION__, ##args)
#else
#define MARS_DBG(args...) /**/
#endif

#define BRICK_OBJ_MARS_IO             0
#define BRICK_OBJ_MARS_BUF            1
#define BRICK_OBJ_NR                  2

#include "brick.h"

/////////////////////////////////////////////////////////////////////////

// MARS-specific definitions

// object stuff

/* mars_io */

extern const struct generic_object_type mars_io_type;

struct mars_io_aspect {
	GENERIC_ASPECT(mars_io);
};

struct mars_io_aspect_layout {
	GENERIC_ASPECT_LAYOUT(mars_io);
};

struct mars_io_object_layout {
	GENERIC_OBJECT_LAYOUT(mars_io);
};

#define MARS_IO_OBJECT(PREFIX)						\
	GENERIC_OBJECT(PREFIX);						\
	struct bio *orig_bio;						\
	int (*mars_endio)(struct mars_io_object *mio, int error);	\

struct mars_io_object {
	MARS_IO_OBJECT(mars_io);
};

/* mars_buf */

#define MARS_BUF_UPTODATE        1
#define MARS_BUF_READING         2
#define MARS_BUF_WRITING         4

extern const struct generic_object_type mars_buf_type;

struct mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
};

struct mars_buf_aspect_layout {
	GENERIC_ASPECT_LAYOUT(mars_buf);
};

struct mars_buf_object_layout {
	GENERIC_OBJECT_LAYOUT(mars_buf);
};

#define MARS_BUF_OBJECT(PREFIX)						\
	GENERIC_OBJECT(PREFIX);						\
	void *buf_data;							\
	int buf_len;							\
	int buf_flags;							\
	loff_t buf_pos;							\
        /* callback part */						\
	void *cb_private;						\
	int cb_rw;							\
	int(*cb_buf_endio)(struct mars_buf_object *mbuf);		\
	int cb_error;							\

struct mars_buf_object {
	MARS_BUF_OBJECT(mars_buf);
};

// internal helper structs

struct mars_info {
	loff_t current_size;
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
	/* mars_io */							\
	int (*mars_io)(struct PREFIX##_output *output, struct mars_io_object *mio); \
	int (*mars_get_info)(struct PREFIX##_output *output, struct mars_info *info); \
	/* mars_buf */							\
	int (*mars_buf_get)(struct PREFIX##_output *output, struct mars_buf_object **mbuf, struct generic_object_layout *object_layout, loff_t pos, int len); \
	int (*mars_buf_put)(struct PREFIX##_output *output, struct mars_buf_object *mbuf); \
	int (*mars_buf_io)(struct PREFIX##_output *output, struct mars_buf_object *mbuf); \

// all non-extendable types

#define _MARS_TYPES(BRICK)						\
									\
struct BRICK##_brick_ops {					        \
	MARS_BRICK_OPS(BRICK);						\
};									\
									\
struct BRICK##_output_ops {					        \
	MARS_OUTPUT_OPS(BRICK);					\
};									\
									\
struct BRICK##_brick_type {					        \
	GENERIC_BRICK_TYPE(BRICK);					\
};									\
									\
struct BRICK##_input_type {					        \
	GENERIC_INPUT_TYPE(BRICK);					\
};									\
									\
struct BRICK##_output_type {					        \
	GENERIC_OUTPUT_TYPE(BRICK);					\
};									\
GENERIC_MAKE_FUNCTIONS(BRICK);					        \
GENERIC_MAKE_CONNECT(BRICK,BRICK);				        \


#define MARS_TYPES(BRICK)						\
									\
_MARS_TYPES(BRICK)						        \
									\
struct BRICK##_object_layout;						\
									\
GENERIC_MAKE_CONNECT(generic,BRICK);				        \
GENERIC_MAKE_CONNECT(mars,BRICK);					\
GENERIC_OBJECT_LAYOUT_FUNCTIONS(BRICK);				        \
GENERIC_ASPECT_LAYOUT_FUNCTIONS(BRICK,mars_io);		                \
GENERIC_ASPECT_LAYOUT_FUNCTIONS(BRICK,mars_buf);		        \
GENERIC_ASPECT_FUNCTIONS(BRICK,mars_io);			        \
GENERIC_ASPECT_FUNCTIONS(BRICK,mars_buf);			        \


// instantiate all mars-specific functions

//GENERIC_ASPECT_LAYOUT_FUNCTIONS(mars,mars_io);
//GENERIC_ASPECT_LAYOUT_FUNCTIONS(mars,mars_buf);

GENERIC_OBJECT_FUNCTIONS(mars_io);
GENERIC_OBJECT_FUNCTIONS(mars_buf);

//GENERIC_ASPECT_FUNCTIONS(mars,mars_io);
//GENERIC_ASPECT_FUNCTIONS(mars,mars_buf);

/////////////////////////////////////////////////////////////////////////

// MARS-specific helper functions

_MARS_TYPES(mars);
GENERIC_MAKE_CONNECT(generic,mars);

#define MARS_MAKE_STATICS(BRICK)					\
									\
int BRICK##_brick_nr = -EEXIST;				                \
EXPORT_SYMBOL_GPL(BRICK##_brick_nr);			                \
									\
static const struct generic_aspect_type BRICK##_mars_io_aspect_type = { \
	.aspect_type_name = #BRICK "_mars_io_aspect_type",		\
	.object_type = &mars_io_type,					\
	.aspect_size = sizeof(struct BRICK##_mars_io_aspect),		\
	.init_fn = BRICK##_mars_io_aspect_init_fn,			\
};									\
									\
static const struct generic_aspect_type BRICK##_mars_buf_aspect_type = { \
	.aspect_type_name = #BRICK "_mars_buf_aspect_type",		\
	.object_type = &mars_buf_type,					\
	.aspect_size = sizeof(struct BRICK##_mars_buf_aspect),		\
	.init_fn = BRICK##_mars_buf_aspect_init_fn,			\
};									\
									\
static const struct generic_aspect_type *BRICK##_aspect_types[BRICK_OBJ_NR] = {	\
	[BRICK_OBJ_MARS_IO] = &BRICK##_mars_io_aspect_type,		\
	[BRICK_OBJ_MARS_BUF] = &BRICK##_mars_buf_aspect_type,		\
};									\

#endif
