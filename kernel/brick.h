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

#ifndef BRICK_H
#define BRICK_H

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/kthread.h>

#include <asm/atomic.h>

/* Adapt to 3f07c0144132e4f59d88055ac8ff3e691a5fa2b8
 * and following commits.
 */
#ifndef SIGNAL_STOP_STOPPED
#include <linux/sched/signal.h>
#endif

#ifndef CONFIG_MARS_MODULE
// when unsure, include faked config file
#include "mars_config.h"
#endif

#include "brick_locks.h"
#include "meta.h"

#define MAX_BRICK_TYPES 64

#define brick_msleep(msecs) _brick_msleep(msecs, false)
extern int _brick_msleep(int msecs, bool shorten);
#define brick_yield() cond_resched()

/////////////////////////////////////////////////////////////////////////

// printk() replacements

#define SAFE_STR(str) ((str) ? (str) : "NULL")

#define _BRICK_MSG(_class, _dump, _fmt, _args...)		\
	brick_say(_class, _dump, "BRICK", __BASE_FILE__, __LINE__, __FUNCTION__, _fmt, ##_args)

#define BRICK_FAT(_fmt, _args...) _BRICK_MSG(SAY_FATAL, true,  _fmt, ##_args)
#define BRICK_ERR(_fmt, _args...) _BRICK_MSG(SAY_ERROR, false, _fmt, ##_args)
#define BRICK_WRN(_fmt, _args...) _BRICK_MSG(SAY_WARN,  false, _fmt, ##_args)
#define BRICK_INF(_fmt, _args...) _BRICK_MSG(SAY_INFO,  false, _fmt, ##_args)

#ifdef BRICK_DEBUGGING
#define BRICK_DBG(_fmt, _args...) _BRICK_MSG(SAY_DEBUG, false, _fmt, ##_args)
#else
#define BRICK_DBG(_args...) /**/
#endif

#ifdef IO_DEBUGGING
#define BRICK_IO(_fmt, _args...)  _BRICK_MSG(SAY_DEBUG, false, _fmt, ##_args)
#else
#define BRICK_IO(_args...) /*empty*/
#endif

#include "brick_checking.h"

/////////////////////////////////////////////////////////////////////////

// number management helpers

extern int get_nr(void);
extern void put_nr(int nr);

/////////////////////////////////////////////////////////////////////////

// definitions for generic objects with aspects

struct generic_object;
struct generic_aspect;

#define GENERIC_ASPECT_TYPE(OBJTYPE)					\
	const char *aspect_type_name;					\
	const struct generic_object_type *object_type;			\
	int  aspect_size;						\
        int  (*init_fn)(struct OBJTYPE##_aspect *ini);			\
        void (*exit_fn)(struct OBJTYPE##_aspect *ini);			\

struct generic_aspect_type {
	GENERIC_ASPECT_TYPE(generic);
};

#define GENERIC_OBJECT_TYPE(OBJTYPE)					\
	const char *object_type_name;					\
	int default_size;						\
	int object_type_nr;						\
        int  (*init_fn)(struct OBJTYPE##_object *ini);			\
        void (*exit_fn)(struct OBJTYPE##_object *ini);			\

struct generic_object_type {
	GENERIC_OBJECT_TYPE(generic);
};

#define GENERIC_OBJECT_LAYOUT(OBJTYPE)					\
	int size_hint;							\
	atomic_t alloc_count;						\
	atomic_t aspect_count;						\
	atomic_t total_alloc_count;					\
	atomic_t total_aspect_count;					\

struct generic_object_layout {
	GENERIC_OBJECT_LAYOUT(generic);
};

#define GENERIC_OBJECT(OBJTYPE)						\
	const struct generic_object_type *object_type;			\
	struct generic_object_layout *object_layout;			\
	struct OBJTYPE##_aspect **aspects;				\
	int aspect_nr_max;						\
	int free_offset;						\
	int max_offset;							\
	

struct generic_object {
	GENERIC_OBJECT(generic);
};

#define GENERIC_ASPECT(OBJTYPE)						\
	struct OBJTYPE##_object *object;				\
	const struct generic_aspect_type *aspect_type;			\
	bool shortcut;							\

struct generic_aspect {
	GENERIC_ASPECT(generic);
};

/////////////////////////////////////////////////////////////////////////

// definitions for asynchronous callback objects

#define GENERIC_CALLBACK(OBJTYPE)					\
	void (*cb_fn)(struct OBJTYPE##_callback *cb);			\
	void  *cb_private;						\
	int    cb_error;						\
	struct generic_callback *cb_next;				\

struct generic_callback {
	GENERIC_CALLBACK(generic);
};

#define CALLBACK_OBJECT(OBJTYPE)					\
	GENERIC_OBJECT(OBJTYPE);					\
	struct generic_callback *object_cb;				\
	struct generic_callback _object_cb;				\

struct callback_object {
	CALLBACK_OBJECT(generic);
};

/* Initial setup of the callback chain
 */
#define _SETUP_CALLBACK(obj,fn,priv)					\
	(obj)->_object_cb.cb_fn = (fn);					\
	(obj)->_object_cb.cb_private = (priv);				\
	(obj)->_object_cb.cb_error = 0;					\
	(obj)->_object_cb.cb_next = NULL;				\
	(obj)->object_cb = &(obj)->_object_cb;				\

#ifdef BRICK_DEBUGGING
#define SETUP_CALLBACK(obj,fn,priv)					\
	if (unlikely((obj)->_object_cb.cb_fn)) {			\
		BRICK_ERR("callback function %p is already installed (new=%p)\n", \
			  (obj)->_object_cb.cb_fn, (fn));		\
	}								\
	_SETUP_CALLBACK(obj,fn,priv)
#else
#define SETUP_CALLBACK(obj,fn,priv) _SETUP_CALLBACK(obj,fn,priv)
#endif

/* Insert a new member into the callback chain
 */
#define _INSERT_CALLBACK(obj,new,fn,priv)				\
	if (likely(!(new)->cb_fn)) {					\
		(new)->cb_fn = (fn);					\
		(new)->cb_private = (priv);				\
		(new)->cb_error = 0;					\
		(new)->cb_next = (obj)->object_cb;			\
		(obj)->object_cb = (new);				\
	}

#ifdef BRICK_DEBUGGING
#define INSERT_CALLBACK(obj,new,fn,priv)				\
	if (unlikely(!(obj)->_object_cb.cb_fn)) {			\
		BRICK_ERR("initical callback function is missing\n");	\
	}								\
	_INSERT_CALLBACK(obj,new,fn,priv)				\
	else { BRICK_ERR("new object %p is not pristine\n", (new)->cb_fn); }
#else
#define INSERT_CALLBACK(obj,new,fn,priv) _INSERT_CALLBACK(obj,new,fn,priv)
#endif

/* Call the first callback in the chain.
 */
#define SIMPLE_CALLBACK(obj,err)					\
	if (likely(obj)) {						\
		struct generic_callback *__cb = (obj)->object_cb;	\
		if (likely(__cb)) {					\
			__cb->cb_error = (err);				\
			__cb->cb_fn(__cb);				\
		} else {						\
			BRICK_ERR("callback object_cb pointer is NULL\n"); \
		}							\
	} else {							\
		BRICK_ERR("callback obj pointer is NULL\n");		\
	}

#define CHECKED_CALLBACK(obj,err,done)					\
	{								\
		struct generic_callback *__cb;				\
		CHECK_PTR(obj, done);					\
		__cb = (obj)->object_cb;				\
		CHECK_PTR_NULL(__cb, done);				\
		__cb->cb_error = (err);					\
		__cb->cb_fn(__cb);					\
	}

/* An intermediate callback handler must call this
 * to continue the callback chain.
 */
#define NEXT_CHECKED_CALLBACK(cb,done)					\
	{								\
		struct generic_callback *__next_cb = (cb)->cb_next;	\
		CHECK_PTR_NULL(__next_cb, done);			\
		__next_cb->cb_error = (cb)->cb_error;			\
		__next_cb->cb_fn(__next_cb);				\
	}

/* The last callback handler in the chain should call this
 * for checking whether the end of the chain has been reached
 */
#define LAST_CALLBACK(cb)						\
	{								\
		struct generic_callback *__next_cb = (cb)->cb_next;	\
		if (unlikely(__next_cb)) {				\
			BRICK_ERR("end of callback chain %p has not been reached, rest = %p\n", (cb), __next_cb); \
		}							\
	}

/* Query the callback status.
 * This uses always the first member of the chain!
 */
#define CALLBACK_ERROR(obj)						\
	((obj)->object_cb ? (obj)->object_cb->cb_error : -EINVAL)

/////////////////////////////////////////////////////////////////////////

// definitions for generic bricks

struct generic_input;
struct generic_output;
struct generic_brick_ops;
struct generic_output_ops;
struct generic_brick_type;

struct generic_switch {
	bool button;       /* in:  main switch (on/off)                     */
	bool led_on;       /* out: indicate regular operation               */
	bool led_off;      /* out: indicate no activity of any kind         */
	bool force_off;    /* in:  make ready for destruction               */
	int  io_timeout;   /* in:  report IO errors after timeout (seconds) */
	int  percent_done; /* out: generic progress indicator               */
	wait_queue_head_t event;
};

#define GENERIC_BRICK(BRITYPE)						\
	const struct BRITYPE##_brick_type *type;			\
	struct BRITYPE##_brick_ops *ops;				\
	int nr_inputs;							\
	int nr_outputs;							\
	int brick_index; /* globally unique */                          \
	struct BRITYPE##_input **inputs;				\
	struct BRITYPE##_output **outputs;				\
	struct generic_switch power;					\
	int (*free)(struct BRITYPE##_brick *del);			\
	struct list_head tmp_head;					\

struct generic_brick {
	GENERIC_BRICK(generic);
};

#define GENERIC_INPUT(BRITYPE)						\
	struct BRITYPE##_brick *brick;					\
	const struct BRITYPE##_input_type *type;			\
	struct BRITYPE##_output *connect;				\
	struct list_head input_head;					\
	
struct generic_input {
	GENERIC_INPUT(generic);
};

#define GENERIC_OUTPUT(BRITYPE)						\
	struct BRITYPE##_brick *brick;					\
	const struct BRITYPE##_output_type *type;			\
	struct BRITYPE##_output_ops *ops;				\
	struct list_head output_head;					\
	int nr_connected;						\
	
struct generic_output {
	GENERIC_OUTPUT(generic);
};

#define GENERIC_OUTPUT_CALL(OUTPUT,OP,ARGS...)				\
	(								\
		(void)LOCK_CHECK(OP),					\
		(OUTPUT) && (OUTPUT)->ops->OP ?				\
		(OUTPUT)->ops->OP(OUTPUT, ##ARGS) :			\
		-ENOTCONN						\
	)
		
#define GENERIC_INPUT_CALL(INPUT,OP,ARGS...)				\
	(							        \
		(void)LOCK_CHECK(OP),					\
		(INPUT) && (INPUT)->connect ?				\
		GENERIC_OUTPUT_CALL((INPUT)->connect, OP, ##ARGS) :	\
		-ENOTCONN						\
	)

#define GENERIC_BRICK_OPS(BRITYPE)					\
	int (*brick_switch)(struct BRITYPE##_brick *brick);		\
	
struct generic_brick_ops {
	GENERIC_BRICK_OPS(generic);
};

#define GENERIC_OUTPUT_OPS(BRITYPE)					\
	/*int (*output_start)(struct BRITYPE##_output *output);*/	\
	/*int (*output_stop)(struct BRITYPE##_output *output);*/		\
	
struct generic_output_ops {
	GENERIC_OUTPUT_OPS(generic)
};

// although possible, *_type should never be extended
#define GENERIC_BRICK_TYPE(BRITYPE)					\
	const char *type_name;						\
	int brick_size;							\
	int max_inputs;							\
	int max_outputs;						\
	const struct BRITYPE##_input_type **default_input_types;	\
	const struct BRITYPE##_output_type **default_output_types;	\
	struct BRITYPE##_brick_ops *master_ops;				\
	const struct generic_aspect_type **aspect_types;		\
	const struct BRITYPE##_input_types **default_type;		\
	int (*brick_construct)(struct BRITYPE##_brick *brick);		\
	int (*brick_destruct)(struct BRITYPE##_brick *brick);		\

struct generic_brick_type {
	GENERIC_BRICK_TYPE(generic);
};

#define GENERIC_INPUT_TYPE(BRITYPE)					\
	char *type_name;						\
	int input_size;							\
	int (*input_construct)(struct BRITYPE##_input *input);		\
	int (*input_destruct)(struct BRITYPE##_input *input);		\

struct generic_input_type {
	GENERIC_INPUT_TYPE(generic);
};

#define GENERIC_OUTPUT_TYPE(BRITYPE)					\
	char *type_name;						\
	int output_size;						\
	struct BRITYPE##_output_ops *master_ops;			\
	int (*output_construct)(struct BRITYPE##_output *output);	\
	int (*output_destruct)(struct BRITYPE##_output *output);	\

struct generic_output_type {
	GENERIC_OUTPUT_TYPE(generic);
};

int generic_register_brick_type(const struct generic_brick_type *new_type);
int generic_unregister_brick_type(const struct generic_brick_type *old_type);

INLINE void _generic_output_init(struct generic_brick *brick,
				 const struct generic_output_type *type,
				 struct generic_output *output)
{
	output->brick = brick;
	output->type = type;
	output->ops = type->master_ops;
	output->nr_connected = 0;
	INIT_LIST_HEAD(&output->output_head);
}

INLINE void _generic_output_exit(struct generic_output *output)
{
	list_del_init(&output->output_head);
	output->brick = NULL;
	output->type = NULL;
	output->ops = NULL;
	output->nr_connected = 0;
}

#ifdef _STRATEGY // call this only in strategy bricks, never in ordinary bricks

// you need this only if you circumvent generic_brick_init_full()
INLINE int generic_brick_init(const struct generic_brick_type *type, struct generic_brick *brick)
{
	brick->brick_index = get_nr();
	brick->type = type;
	brick->ops = type->master_ops;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	brick->power.led_off = true;
	init_waitqueue_head(&brick->power.event);
	INIT_LIST_HEAD(&brick->tmp_head);
	return 0;
}

INLINE void generic_brick_exit(struct generic_brick *brick)
{
	list_del_init(&brick->tmp_head);
	brick->type = NULL;
	brick->ops = NULL;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	put_nr(brick->brick_index);
}

INLINE int generic_input_init(struct generic_brick *brick,
			      int index,
			      const struct generic_input_type *type,
			      struct generic_input *input)
{
	if (index < 0 || index >= brick->type->max_inputs)
		return -EINVAL;
	if (brick->inputs[index])
		return -EEXIST;
	input->brick = brick;
	input->type = type;
	input->connect = NULL;
	INIT_LIST_HEAD(&input->input_head);
	brick->inputs[index] = input;
	brick->nr_inputs++;
	return 0;
}

INLINE void generic_input_exit(struct generic_input *input)
{
	list_del_init(&input->input_head);
	input->brick = NULL;
	input->type = NULL;
	input->connect = NULL;
}

INLINE int generic_output_init(struct generic_brick *brick,
			       int index,
			       const struct generic_output_type *type,
			       struct generic_output *output)
{
	if (index < 0 || index >= brick->type->max_outputs)
		return -ENOMEM;
	if (brick->outputs[index])
		return -EEXIST;
	_generic_output_init(brick, type, output);
	brick->outputs[index] = output;
	brick->nr_outputs++;
	return 0;
}

INLINE int generic_size(const struct generic_brick_type *brick_type)
{
	int size = brick_type->brick_size;
	int i;
	size += brick_type->max_inputs * sizeof(void*);
	for (i = 0; i < brick_type->max_inputs; i++) {
		size += brick_type->default_input_types[i]->input_size;
	}
	size += brick_type->max_outputs * sizeof(void*);
	for (i = 0; i < brick_type->max_outputs; i++) {
		size += brick_type->default_output_types[i]->output_size;
	}
	return size;
}

/* If possible, use this instead of generic_*_init().
 * input_types and output_types may be NULL => use default_*_types
 */
int generic_brick_init_full(
	void *data, 
	int size, 
	const struct generic_brick_type *brick_type,
	const struct generic_input_type **input_types,
	const struct generic_output_type **output_types);

int generic_brick_exit_full(
	struct generic_brick *brick);

INLINE int generic_connect(struct generic_input *input, struct generic_output *output)
{
	BRICK_DBG("generic_connect(input=%p, output=%p)\n", input, output);
	if (unlikely(!input || !output))
		return -EINVAL;
	if (unlikely(input->connect))
		return -EEXIST;
	if (unlikely(!list_empty(&input->input_head)))
		return -EINVAL;
	// helps only against the most common errors
	if (unlikely(input->brick == output->brick))
		return -EDEADLK;

	input->connect = output;
	output->nr_connected++;
	list_add(&input->input_head, &output->output_head);
	BRICK_DBG("now nr_connected=%d\n", output->nr_connected);
	return 0;
}

INLINE int generic_disconnect(struct generic_input *input)
{
	struct generic_output *connect;
	BRICK_DBG("generic_disconnect(input=%p)\n", input);
	if (!input)
		return -EINVAL;
	connect = input->connect;
	if (connect) {
		connect->nr_connected--;
		BRICK_DBG("now nr_connected=%d\n", connect->nr_connected);
		input->connect = NULL;
		list_del_init(&input->input_head);
	}
	return 0;
}

INLINE int generic_reconnect(struct generic_input *input,
			     struct generic_output *output)
{
	struct generic_output *old;

	BRICK_DBG("generic_reconnect(input=%p, output=%p)\n", input, output);
	if (unlikely(!input || !output))
		return -EINVAL;
	old = input->connect;
	// helps only against the most common errors
	if (unlikely(input->brick == output->brick))
		return -EDEADLK;

	input->connect = output;
	output->nr_connected++;
	if (old) {
		old->nr_connected--;
		BRICK_DBG("old nr_connected=%d\n", old->nr_connected);
		list_del_init(&input->input_head);
	}
	list_add(&input->input_head, &output->output_head);
	BRICK_DBG("new nr_connected=%d\n", output->nr_connected);
	return 0;
}

#endif // _STRATEGY

// simple wrappers for type safety
#define DECLARE_BRICK_FUNCTIONS(BRITYPE)				\
static inline int BRITYPE##_register_brick_type(void)		        \
{									\
	extern const struct BRITYPE##_brick_type BRITYPE##_brick_type;	\
	extern int BRITYPE##_brick_nr;					\
	if (BRITYPE##_brick_nr >= 0) {					\
		BRICK_ERR("brick type " #BRITYPE " is already registered.\n"); \
		return -EEXIST;						\
	}								\
	BRITYPE##_brick_nr = generic_register_brick_type((const struct generic_brick_type*)&BRITYPE##_brick_type); \
	return BRITYPE##_brick_nr < 0 ? BRITYPE##_brick_nr : 0;		\
}									\
									\
static inline int BRITYPE##_unregister_brick_type(void)		        \
{									\
	extern const struct BRITYPE##_brick_type BRITYPE##_brick_type;	\
	return generic_unregister_brick_type((const struct generic_brick_type*)&BRITYPE##_brick_type); \
}									\
									\
extern const struct BRITYPE##_brick_type BRITYPE##_brick_type;	        \
extern const struct BRITYPE##_input_type BRITYPE##_input_type;	        \
extern const struct BRITYPE##_output_type BRITYPE##_output_type;        \
									\
INLINE void _##BRITYPE##_output_init(struct BRITYPE##_brick *brick,	\
				    struct BRITYPE##_output *output)	\
{									\
	_generic_output_init(						\
		(struct generic_brick*)brick,				\
		(const struct generic_output_type*)&BRITYPE##_output_type, \
		(struct generic_output*)output);			\
}									\

///////////////////////////////////////////////////////////////////////

// default operations on objects / aspects

extern struct generic_object *generic_alloc(struct generic_brick *brick, struct generic_object_layout *object_layout, const struct generic_object_type *object_type);
extern void generic_free(struct generic_object *object);
extern struct generic_aspect *generic_get_aspect(struct generic_brick *brick, struct generic_object *obj);

#define DECLARE_ASPECT_FUNCTIONS(BRITYPE,OBJTYPE)			\
									\
INLINE struct OBJTYPE##_object *BRITYPE##_alloc_##OBJTYPE(struct BRITYPE##_brick *brick) \
{									\
        return (void*)generic_alloc((struct generic_brick*)brick, &brick->OBJTYPE##_object_layout, &OBJTYPE##_type); \
}									\
									\
INLINE void BRITYPE##_free_##OBJTYPE(struct OBJTYPE##_object *object)   \
{									\
	generic_free((struct generic_object*)object);			\
}									\
									\
INLINE struct BRITYPE##_##OBJTYPE##_aspect *BRITYPE##_##OBJTYPE##_get_aspect(struct BRITYPE##_brick *brick, struct OBJTYPE##_object *obj) \
{									\
        return (void*)generic_get_aspect((struct generic_brick*)brick, (struct generic_object*)obj); \
}									\
									\


///////////////////////////////////////////////////////////////////////

// some general helpers

/* Generic interface to simple brick status changes.
 */
extern void set_button(struct generic_switch *sw, bool val, bool force);
extern void set_led_on(struct generic_switch *sw, bool val);
extern void set_led_off(struct generic_switch *sw, bool val);
/*
 * "Forced switch off" means that it cannot be switched on again.
 */
extern void set_button_wait(struct generic_brick *brick, bool val, bool force, int timeout);

/* Operations on networks of bricks (wiring graphs).
 *
 * Switch on => first switch on all predecessors in the wiring graph
 * Switch off => first switch off all successors in the wiring graph
 *
 * Operations on brick networks by multiple threads in parallel are dangerous,
 * because the buttons may start flipping.
 * There is one exception: when @force is set, only the direction to
 * "off" remains possible. This is useful for emergency shutdowns.
 */
typedef enum {
	// only one brick instance
	BR_ON_ONE,   // switch on one brick instance
	BR_OFF_ONE,  // just switch off (may be switched on again)
	BR_KILL_ONE, // forced switch off => may be never switched on again
	BR_FREE_ONE, // forced switch off + deallocation (when possible)
	// dito, but operating on the whole graph
	BR_ON_ALL,
	BR_OFF_ALL, 
	BR_KILL_ALL,
	BR_FREE_ALL,
} brick_switch_t;

/////////////////////////////////////////////////////////////////////////

// threads

/* Please do not directly use kthreads any more in future.
 * Use these thin abstractions instead.
 */

#define brick_thread_t struct task_struct

#define brick_thread_create(_thread_fn, _data, _fmt, _args...)		\
	({								\
		brick_thread_t *_thr = NULL;				\
		int _max_retry = 3;					\
									\
		while (_max_retry-- > 0) {				\
			int _err;					\
									\
			flush_signals(current);				\
			_thr = kthread_create(_thread_fn, _data, _fmt, ##_args); \
			if (likely(!IS_ERR(_thr)))			\
				break;					\
			_err = PTR_ERR(_thr);				\
			if (_err == -EAGAIN || _err == -EINTR)		\
				continue;				\
			BRICK_ERR("cannot create thread '%s', status = %d\n", _fmt, _err); \
			_thr = NULL;					\
			break;						\
		}							\
		if (_thr) {						\
			struct say_channel *ch = get_binding(current);	\
			if (ch)						\
				bind_to_channel(ch, _thr);		\
			get_task_struct(_thr);				\
			wake_up_process(_thr);				\
		}							\
		_thr;							\
	})

#define brick_thread_stop(_thread)					\
	do {								\
		struct task_struct *__thread__ = (_thread);		\
									\
		if (likely(__thread__)) {				\
			BRICK_INF("stopping thread '%s'\n", __thread__->comm); \
			kthread_stop(__thread__);			\
			BRICK_INF("thread '%s' finished.\n", __thread__->comm); \
			remove_binding(__thread__);			\
			put_task_struct(__thread__);			\
			(_thread) = NULL;				\
		}							\
	} while (0)

#define brick_thread_should_stop()		\
	({					\
		flush_signals(current);		\
		brick_yield();			\
		kthread_should_stop();		\
	})

/////////////////////////////////////////////////////////////////////////

// init

extern int init_brick(void);
extern void exit_brick(void);

#endif
