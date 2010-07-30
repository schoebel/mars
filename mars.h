// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_H
#define MARS_H

#include <linux/list.h>
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
#define BRICK_OBJ_MARS_BUF_CALLBACK   2
#define BRICK_OBJ_NR                  3

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

struct mars_buf_object {
	MARS_BUF_OBJECT(mars_buf);
};

/* mars_buf_callback_object */

extern const struct generic_object_type mars_buf_callback_type;

struct mars_buf_callback_aspect {
	GENERIC_ASPECT(mars_buf_callback);
};

struct mars_buf_callback_aspect_layout {
	GENERIC_ASPECT_LAYOUT(mars_buf_callback);
};

struct mars_buf_callback_object_layout {
	GENERIC_OBJECT_LAYOUT(mars_buf_callback);
};

#define MARS_BUF_CALLBACK_OBJECT(PREFIX)				\
	GENERIC_OBJECT(PREFIX);						\
	struct mars_buf_object *cb_mbuf;				\
	void *cb_private;						\
	int cb_rw;							\
	int(*cb_buf_endio)(struct mars_buf_callback_object *mbuf_cb);	\
	int cb_error;							\

struct mars_buf_callback_object {
	MARS_BUF_CALLBACK_OBJECT(mars_buf_callback);
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
	int (*mars_buf_get)(struct PREFIX##_output *output, struct mars_buf_object **mbuf, struct mars_buf_object_layout *buf_layout, loff_t pos, int len); \
	int (*mars_buf_put)(struct PREFIX##_output *output, struct mars_buf_object *mbuf); \
	int (*mars_buf_io)(struct PREFIX##_output *output, struct mars_buf_callback_object *mbuf_cb); \

// all non-extendable types
#define _MARS_TYPES(PREFIX)						\
struct PREFIX##_brick_ops {					        \
	MARS_BRICK_OPS(PREFIX);						\
};									\
									\
struct PREFIX##_output_ops {					        \
	MARS_OUTPUT_OPS(PREFIX);					\
};									\
									\
struct PREFIX##_brick_type {					        \
	GENERIC_BRICK_TYPE(PREFIX);					\
};									\
									\
struct PREFIX##_input_type {					        \
	GENERIC_INPUT_TYPE(PREFIX);					\
};									\
									\
struct PREFIX##_output_type {					        \
	GENERIC_OUTPUT_TYPE(PREFIX);					\
};									\
GENERIC_MAKE_FUNCTIONS(PREFIX);					        \
GENERIC_MAKE_CONNECT(PREFIX,PREFIX);				        \


#define MARS_TYPES(PREFIX)						\
_MARS_TYPES(PREFIX)						        \
GENERIC_MAKE_CONNECT(generic,PREFIX);				        \
GENERIC_MAKE_CONNECT(mars,PREFIX);					\
GENERIC_ASPECT_LAYOUT_FUNCTIONS(PREFIX,mars_io);		        \
GENERIC_ASPECT_LAYOUT_FUNCTIONS(PREFIX,mars_buf);		        \
GENERIC_ASPECT_LAYOUT_FUNCTIONS(PREFIX,mars_buf_callback);	        \
GENERIC_ASPECT_FUNCTIONS(PREFIX,mars_io);			        \
GENERIC_ASPECT_FUNCTIONS(PREFIX,mars_buf);			        \
GENERIC_ASPECT_FUNCTIONS(PREFIX,mars_buf_callback);		        \


// instantiate all mars-specific functions

GENERIC_OBJECT_LAYOUT_FUNCTIONS(mars_io);
GENERIC_OBJECT_LAYOUT_FUNCTIONS(mars_buf);
GENERIC_OBJECT_LAYOUT_FUNCTIONS(mars_buf_callback);

//GENERIC_ASPECT_LAYOUT_FUNCTIONS(mars,mars_io);
//GENERIC_ASPECT_LAYOUT_FUNCTIONS(mars,mars_buf);
//GENERIC_ASPECT_LAYOUT_FUNCTIONS(mars,mars_buf_callback);

GENERIC_OBJECT_FUNCTIONS(mars_io);
GENERIC_OBJECT_FUNCTIONS(mars_buf);
GENERIC_OBJECT_FUNCTIONS(mars_buf_callback);

GENERIC_ASPECT_FUNCTIONS(mars,mars_io);
GENERIC_ASPECT_FUNCTIONS(mars,mars_buf);
GENERIC_ASPECT_FUNCTIONS(mars,mars_buf_callback);

/////////////////////////////////////////////////////////////////////////

// MARS-specific helper functions

_MARS_TYPES(mars);
GENERIC_MAKE_CONNECT(generic,mars);

#define MARS_MAKE_STATICS(PREFIX)					\
									\
int PREFIX##_brick_nr = -EEXIST;				        \
EXPORT_SYMBOL_GPL(PREFIX##_brick_nr);			                \
									\
static const struct generic_aspect_type PREFIX##_mars_io_aspect_type = { \
	.aspect_type_name = #PREFIX "_mars_io_aspect_type",		\
	.object_type = &mars_io_type,					\
	.aspect_size = sizeof(struct PREFIX##_mars_io_aspect),		\
	.init_fn = PREFIX##_mars_io_aspect_init_fn,			\
};									\
									\
static const struct generic_aspect_type PREFIX##_mars_buf_aspect_type = { \
	.aspect_type_name = #PREFIX "_mars_buf_aspect_type",		\
	.object_type = &mars_buf_type,					\
	.aspect_size = sizeof(struct PREFIX##_mars_buf_aspect),		\
	.init_fn = PREFIX##_mars_buf_aspect_init_fn,			\
};									\
									\
static const struct generic_aspect_type PREFIX##_mars_buf_callback_aspect_type = { \
	.aspect_type_name = #PREFIX "_mars_buf_callback_aspect_type",	\
	.object_type = &mars_buf_callback_type,				\
	.aspect_size = sizeof(struct PREFIX##_mars_buf_callback_aspect), \
	.init_fn = PREFIX##_mars_buf_callback_aspect_init_fn,		\
};									\
									\
static const struct generic_aspect_type *PREFIX##_aspect_types[BRICK_OBJ_NR] = {	\
	[BRICK_OBJ_MARS_IO] = &PREFIX##_mars_io_aspect_type,		\
	[BRICK_OBJ_MARS_BUF] = &PREFIX##_mars_buf_aspect_type,		\
	[BRICK_OBJ_MARS_BUF_CALLBACK] = &PREFIX##_mars_buf_callback_aspect_type, \
};									\

#endif
