// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_H
#define BRICK_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include <asm/atomic.h>

#include "meta.h"

#define MAX_BRICK_TYPES 64

#ifdef _STRATEGY
#define _STRATEGY_CODE(X) X
#define _NORMAL_CODE(X) /**/
#else
#define _STRATEGY_CODE(X) /**/
#define _NORMAL_CODE(X) X
#endif

#define msleep(msecs) brick_msleep(msecs, false)
extern int brick_msleep(int msecs, bool shorten);

/////////////////////////////////////////////////////////////////////////

// printk() replacements

#ifdef CONFIG_DEBUG_KERNEL
#define INLINE static inline
//#define INLINE __attribute__((__noinline__))
extern void say(const char *fmt, ...);
extern void say_mark(void);
extern void brick_dump_stack(void);

#else // CONFIG_DEBUG_KERNEL

#define INLINE static inline
#define say printk
#define say_mark() /*empty*/
#define brick_dump_stack() /*empty*/

#endif // CONFIG_DEBUG_KERNEL

#define SAFE_STR(str) ((str) ? (str) : "NULL")

#define BRICK_FATAL   "BRICK_FATAL "
#define BRICK_ERROR   "BRICK_ERROR "
#define BRICK_WARNING "BRICK_WARN  "
#define BRICK_INFO    "BRICK_INFO  "
#define BRICK_DEBUG   "BRICK_DEBUG "

#define _BRICK_FMT(_fmt) __BASE_FILE__ " %d %s(): " _fmt, __LINE__, __FUNCTION__

#define _BRICK_MSG(_dump, PREFIX, _fmt, _args...) do { say(PREFIX _BRICK_FMT(_fmt), ##_args); if (_dump) brick_dump_stack(); } while (0)

#define BRICK_FAT(_fmt, _args...) _BRICK_MSG(true,  BRICK_FATAL,   _fmt, ##_args)
#define BRICK_ERR(_fmt, _args...) _BRICK_MSG(true,  BRICK_ERROR,   _fmt, ##_args)
#define BRICK_WRN(_fmt, _args...) _BRICK_MSG(false, BRICK_WARNING, _fmt, ##_args)
#define BRICK_INF(_fmt, _args...) _BRICK_MSG(false, BRICK_INFO,    _fmt, ##_args)

#ifdef BRICK_DEBUGGING
#define BRICK_DBG(_fmt, _args...) _BRICK_MSG(false, BRICK_DEBUG,   _fmt, ##_args)
#else
#define BRICK_DBG(_args...) /**/
#endif

#ifdef IO_DEBUGGING
#define BRICK_IO(_fmt, _args...)  _BRICK_MSG(false, BRICK_DEBUG,   _fmt, ##_args)
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

#define GENERIC_ASPECT_TYPE(TYPE)					\
	const char *aspect_type_name;					\
	const struct generic_object_type *object_type;			\
	int  aspect_size;						\
        int  (*init_fn)(struct TYPE##_aspect *ini);			\
        void (*exit_fn)(struct TYPE##_aspect *ini);			\

struct generic_aspect_type {
	GENERIC_ASPECT_TYPE(generic);
};

#define GENERIC_OBJECT_TYPE(TYPE)					\
	const char *object_type_name;					\
	int default_size;						\
	int object_type_nr;						\
        int  (*init_fn)(struct TYPE##_object *ini);			\
        void (*exit_fn)(struct TYPE##_object *ini);			\

struct generic_object_type {
	GENERIC_OBJECT_TYPE(generic);
};

#define GENERIC_OBJECT_LAYOUT(TYPE)					\
	int size_hint;							\
	atomic_t alloc_count;						\
	atomic_t free_count;						\

struct generic_object_layout {
	GENERIC_OBJECT_LAYOUT(generic);
};

extern void init_generic_object_layout(struct generic_object_layout *lay, const struct generic_object_type *type);
extern void exit_generic_object_layout(struct generic_object_layout *lay);

#define GENERIC_OBJECT(TYPE)						\
	const struct generic_object_type *object_type;			\
	struct TYPE##_object_layout *object_layout;			\
	struct TYPE##_aspect **aspects;				\
	int aspect_nr_max;						\
	int free_offset;						\
	int max_offset;							\
	

struct generic_object {
	GENERIC_OBJECT(generic);
};

#define GENERIC_ASPECT(TYPE)						\
	struct TYPE##_object *object;					\
	const struct generic_aspect_type *aspect_type;			\
	bool shortcut;							\

struct generic_aspect {
	GENERIC_ASPECT(generic);
};

/////////////////////////////////////////////////////////////////////////

// definitions for asynchronous callback objects

#define GENERIC_CALLBACK(TYPE)						\
	void (*cb_fn)(struct TYPE##_callback *cb);			\
	void  *cb_private;						\
	int    cb_error;						\
	struct generic_callback *cb_next;				\

struct generic_callback {
	GENERIC_CALLBACK(generic);
};

#define CALLBACK_OBJECT(TYPE)						\
	GENERIC_OBJECT(TYPE);						\
	struct generic_callback *object_cb;				\
	struct generic_callback _object_cb;				\

struct callback_object {
	CALLBACK_OBJECT(generic);
};

/* Initial setup of the callback chain
 */
#define SETUP_CALLBACK(obj,fn,priv)					\
	(obj)->_object_cb.cb_fn = (fn);					\
	(obj)->_object_cb.cb_private = (priv);				\
	(obj)->_object_cb.cb_error = 0;					\
	(obj)->_object_cb.cb_next = NULL;				\
	(obj)->object_cb = &(obj)->_object_cb;				\

/* Insert a new member into the callback chain
 */
#define INSERT_CALLBACK(obj,new,fn,priv)				\
	if (!(new)->cb_fn) {						\
		(new)->cb_fn = (fn);					\
		(new)->cb_private = (priv);				\
		(new)->cb_error = 0;					\
		(new)->cb_next = (obj)->object_cb;			\
		(obj)->object_cb = (new);				\
	}

/* Call the first callback in the chain.
 */
#define SIMPLE_CALLBACK(obj,err)					\
	if (obj) {							\
		struct generic_callback *__cb = (obj)->object_cb;	\
		if (__cb) {						\
			__cb->cb_error = (err);				\
			__cb->cb_fn(__cb);				\
		}							\
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
	bool button;
	bool led_on;
	bool led_off;
	bool force_off;
	int  percent_done;
	wait_queue_head_t event;
};

#define GENERIC_BRICK(BRICK)						\
	const char *brick_name;						\
	const struct BRICK##_brick_type *type;				\
	struct BRICK##_brick_ops *ops;					\
	int nr_inputs;							\
	int nr_outputs;							\
	int brick_index; /* globally unique */                          \
	struct BRICK##_input **inputs;					\
	struct BRICK##_output **outputs;				\
	struct generic_switch power;					\
	int (*free)(struct BRICK##_brick *del);				\
	struct list_head tmp_head;					\

struct generic_brick {
	GENERIC_BRICK(generic);
};

#define GENERIC_INPUT(BRICK)						\
	const char *input_name;						\
	struct BRICK##_brick *brick;					\
	const struct BRICK##_input_type *type;				\
	struct BRICK##_output *connect;					\
	struct list_head input_head;					\
	
struct generic_input {
	GENERIC_INPUT(generic);
};

#define GENERIC_OUTPUT(BRICK)						\
	const char *output_name;					\
	struct BRICK##_brick *brick;					\
	const struct BRICK##_output_type *type;				\
	struct BRICK##_output_ops *ops;					\
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
		-ENOSYS							\
	)
		
#define GENERIC_INPUT_CALL(INPUT,OP,ARGS...)				\
	(							        \
		(void)LOCK_CHECK(OP),					\
		(INPUT) && (INPUT)->connect ?				\
		GENERIC_OUTPUT_CALL((INPUT)->connect, OP, ##ARGS) :	\
		-ECONNREFUSED						\
	)

#define GENERIC_BRICK_OPS(BRICK)					\
	int (*brick_switch)(struct BRICK##_brick *brick);		\
	
struct generic_brick_ops {
	GENERIC_BRICK_OPS(generic);
};

#define GENERIC_OUTPUT_OPS(BRICK)					\
	/*int (*output_start)(struct BRICK##_output *output);*/	\
	/*int (*output_stop)(struct BRICK##_output *output);*/		\
	
struct generic_output_ops {
	GENERIC_OUTPUT_OPS(generic)
};

// although possible, *_type should never be extended
#define GENERIC_BRICK_TYPE(BRICK)					\
	const char *type_name;						\
	int brick_size;							\
	int max_inputs;							\
	int max_outputs;						\
	const struct BRICK##_input_type **default_input_types;		\
	const char **default_input_names;				\
	const struct BRICK##_output_type **default_output_types;	\
	const char **default_output_names;				\
	struct BRICK##_brick_ops *master_ops;				\
	const struct generic_aspect_type **aspect_types;		\
	const struct BRICK##_input_types **default_type;		\
	int (*brick_construct)(struct BRICK##_brick *brick);		\
	int (*brick_destruct)(struct BRICK##_brick *brick);		\

struct generic_brick_type {
	GENERIC_BRICK_TYPE(generic);
};

#define GENERIC_INPUT_TYPE(BRICK)					\
	char *type_name;						\
	int input_size;							\
	int (*input_construct)(struct BRICK##_input *input);		\
	int (*input_destruct)(struct BRICK##_input *input);		\

struct generic_input_type {
	GENERIC_INPUT_TYPE(generic);
};

#define GENERIC_OUTPUT_TYPE(BRICK)					\
	char *type_name;						\
	int output_size;						\
	struct BRICK##_output_ops *master_ops;				\
	int (*output_construct)(struct BRICK##_output *output);		\
	int (*output_destruct)(struct BRICK##_output *output);		\

struct generic_output_type {
	GENERIC_OUTPUT_TYPE(generic);
};

int generic_register_brick_type(const struct generic_brick_type *new_type);
int generic_unregister_brick_type(const struct generic_brick_type *old_type);

INLINE void _generic_output_init(struct generic_brick *brick, const struct generic_output_type *type, struct generic_output *output, const char *output_name)
{
	output->output_name = output_name;
	output->brick = brick;
	output->type = type;
	output->ops = type->master_ops;
	output->nr_connected = 0;
	INIT_LIST_HEAD(&output->output_head);
}

INLINE void _generic_output_exit(struct generic_output *output)
{
	list_del_init(&output->output_head);
	output->output_name = NULL;
	output->brick = NULL;
	output->type = NULL;
	output->ops = NULL;
	output->nr_connected = 0;
}

#ifdef _STRATEGY // call this only in strategy bricks, never in ordinary bricks

// you need this only if you circumvent generic_brick_init_full()
INLINE int generic_brick_init(const struct generic_brick_type *type, struct generic_brick *brick, const char *brick_name)
{
	brick->brick_index = get_nr();
	brick->brick_name = brick_name;
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
	brick->brick_name = NULL;
	brick->type = NULL;
	brick->ops = NULL;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	put_nr(brick->brick_index);
}

INLINE int generic_input_init(struct generic_brick *brick, int index, const struct generic_input_type *type, struct generic_input *input, const char *input_name)
{
	if (index < 0 || index >= brick->type->max_inputs)
		return -EINVAL;
	if (brick->inputs[index])
		return -EEXIST;
	input->input_name = input_name;
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
	input->input_name = NULL;
	input->brick = NULL;
	input->type = NULL;
	input->connect = NULL;
}

INLINE int generic_output_init(struct generic_brick *brick, int index, const struct generic_output_type *type, struct generic_output *output, const char *output_name)
{
	if (index < 0 || index >= brick->type->max_outputs)
		return -ENOMEM;
	if (brick->outputs[index])
		return -EEXIST;
	_generic_output_init(brick, type, output, output_name);
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
	const struct generic_output_type **output_types,
	const char **names);

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

#endif // _STRATEGY

// simple wrappers for type safety
#define GENERIC_MAKE_FUNCTIONS(BRICK)					\
static inline int BRICK##_register_brick_type(void)		        \
{									\
	extern const struct BRICK##_brick_type BRICK##_brick_type;	\
	extern int BRICK##_brick_nr;					\
	if (BRICK##_brick_nr >= 0) {					\
		BRICK_ERR("brick type " #BRICK " is already registered.\n"); \
		return -EEXIST;						\
	}								\
	BRICK##_brick_nr = generic_register_brick_type((const struct generic_brick_type*)&BRICK##_brick_type); \
	return BRICK##_brick_nr < 0 ? BRICK##_brick_nr : 0;		\
}									\
									\
static inline int BRICK##_unregister_brick_type(void)		        \
{									\
	extern const struct BRICK##_brick_type BRICK##_brick_type;	\
	return generic_unregister_brick_type((const struct generic_brick_type*)&BRICK##_brick_type); \
}									\
									\
extern const struct BRICK##_brick_type BRICK##_brick_type;	        \
extern const struct BRICK##_input_type BRICK##_input_type;	        \
extern const struct BRICK##_output_type BRICK##_output_type;	        \
									\
INLINE void _##BRICK##_output_init(struct BRICK##_brick *brick, struct BRICK##_output *output, char *output_name) \
{									\
	_generic_output_init(						\
		(struct generic_brick*)brick,				\
		(const struct generic_output_type*)&BRICK##_output_type, \
		(struct generic_output*)output,				\
		output_name);						\
}									\
									\
_STRATEGY_CODE(							        \
INLINE int BRICK##_brick_init(struct BRICK##_brick *brick, char *brick_name) \
{									\
	return generic_brick_init((const struct generic_brick_type*)&BRICK##_brick_type, (struct generic_brick*)brick, brick_name); \
}									\
									\
INLINE int BRICK##_input_init(struct BRICK##_brick *brick, int index, struct BRICK##_input *input, char *input_name) \
{									\
	return generic_input_init(					\
		(struct generic_brick*)brick,				\
		index,							\
		(struct generic_input_type*)&BRICK##_input_type,	\
		(struct generic_input*)input,				\
		input_name);						\
}									\
									\
INLINE int BRICK##_output_init(struct BRICK##_brick *brick, int index, struct BRICK##_output *output, char *output_name) \
{									\
	return generic_output_init(					\
		(struct generic_brick*)brick,				\
		index,							\
		(const struct generic_output_type*)&BRICK##_output_type, \
		(struct generic_output*)output,				\
		output_name);						\
}									\
									\
)

/* Define a pair of connectable subtypes.
 * For type safety, use this for all possible combinations.
 * Yes, this may become quadratic in large type systems, but
 * (a) thou shalt not define much types,
 * (b) these macros generate only definitions, but no additional 
 * code at runtime.
 */
#define GENERIC_MAKE_CONNECT(INPUT_BRICK,OUTPUT_BRICK)			\
									\
_STRATEGY_CODE(							        \
									\
INLINE int INPUT_BRICK##_##OUTPUT_BRICK##_connect(	        \
	struct INPUT_BRICK##_input *input,				\
	struct OUTPUT_BRICK##_output *output)				\
{									\
	return generic_connect((struct generic_input*)input, (struct generic_output*)output); \
}									\
									\
INLINE int INPUT_BRICK##_##OUTPUT_BRICK####_disconnect(        \
	struct INPUT_BRICK##_input *input)				\
{									\
	return generic_disconnect((struct generic_input*)input);	\
}									\
)

///////////////////////////////////////////////////////////////////////

// default operations on objects / aspects

extern struct generic_object *generic_alloc(struct generic_brick *brick, struct generic_object_layout *object_layout, const struct generic_object_type *object_type);
extern void generic_free(struct generic_object *object);
extern struct generic_aspect *generic_get_aspect(struct generic_brick *brick, struct generic_object *obj);

#define GENERIC_ASPECT_FUNCTIONS(BRICK,TYPE)				\
									\
INLINE struct TYPE##_object *BRICK##_alloc_##TYPE(struct BRICK##_brick *brick, struct generic_object_layout *object_layout) \
{									\
        return (void*)generic_alloc((struct generic_brick*)brick, object_layout, &TYPE##_type); \
}									\
									\
INLINE void BRICK##_free_##TYPE(struct TYPE##_object *object)		\
{									\
	generic_free((struct generic_object*)object);			\
}									\
									\
INLINE struct BRICK##_##TYPE##_aspect *BRICK##_##TYPE##_get_aspect(struct BRICK##_brick *brick, struct TYPE##_object *obj) \
{									\
        return (void*)generic_get_aspect((struct generic_brick*)brick, (struct generic_object*)obj); \
}									\
									\


///////////////////////////////////////////////////////////////////////

// some general helpers

extern void get_lamport(struct timespec *now);
extern void set_lamport(struct timespec *old);

#ifdef CONFIG_DEBUG_SPINLOCK

# define LOCK_CHECK(OP)							\
	({								\
		if (atomic_read(&current->lock_count)) {			\
			BRICK_ERR("never call " #OP "() with a spinlock held.\n"); \
		}							\
	})

# define traced_lock(spinlock,flags)					\
	do {								\
		if (atomic_read(&current->lock_count)) {			\
			BRICK_ERR("please do not nest spinlocks at line %d, reorganize your code.\n", __LINE__); \
		}							\
		atomic_inc(&current->lock_count);			\
		(void)flags;						\
		spin_lock_irqsave(spinlock, flags);			\
	} while (0)

# define traced_unlock(spinlock,flags)					\
	do {								\
		spin_unlock_irqrestore(spinlock, flags);		\
		atomic_dec(&current->lock_count);			\
		say_mark();						\
	} while (0)

# define traced_readlock(spinlock,flags)				\
	do {								\
		if (atomic_read(&current->lock_count)) {			\
			BRICK_ERR("please do not nest spinlocks at line %d, reorganize your code.\n", __LINE__); \
		}							\
		atomic_inc(&current->lock_count);			\
		(void)flags;						\
		read_lock(spinlock);					\
	} while (0)

# define traced_readunlock(spinlock,flags)				\
	do {								\
		/*spin_unlock_irqrestore(spinlock,flags);*/		\
		read_unlock(spinlock);					\
		atomic_dec(&current->lock_count);			\
		say_mark();						\
	} while (0)

# define traced_writelock(spinlock,flags)				\
	do {								\
		if (atomic_read(&current->lock_count)) {			\
			BRICK_ERR("please do not nest spinlocks at line %d, reorganize your code.\n", __LINE__); \
		}							\
		atomic_inc(&current->lock_count);			\
		(void)flags;						\
		write_lock(spinlock);					\
	} while (0)

# define traced_writeunlock(spinlock,flags)				\
	do {								\
		/*spin_unlock_irqrestore(spinlock,flags);*/		\
		write_unlock(spinlock);					\
		atomic_dec(&current->lock_count);			\
		say_mark();						\
	} while (0)

#else
# define LOCK_CHECK(OP) 0
#if 0
# define traced_lock(spinlock,flags)   spin_lock_irqsave(spinlock,flags)
# define traced_unlock(spinlock,flags) spin_unlock_irqrestore(spinlock,flags)
# define traced_readlock(spinlock,flags)   read_lock_irqsave(spinlock,flags)
# define traced_readunlock(spinlock,flags) read_unlock_irqrestore(spinlock,flags)
# define traced_writelock(spinlock,flags)   write_lock_irqsave(spinlock,flags)
# define traced_writeunlock(spinlock,flags) write_unlock_irqrestore(spinlock,flags)
#else
# define traced_lock(spinlock,flags)   do { (void)flags; spin_lock(spinlock); } while (0)
# define traced_unlock(spinlock,flags) do { (void)flags; spin_unlock(spinlock); } while (0)
# define traced_readlock(spinlock,flags)   do { (void)flags; read_lock(spinlock); } while (0)
# define traced_readunlock(spinlock,flags) do { (void)flags; read_unlock(spinlock); } while (0)
# define traced_writelock(spinlock,flags)   do { (void)flags; write_lock(spinlock); } while (0)
# define traced_writeunlock(spinlock,flags) do { (void)flags; write_unlock(spinlock); } while (0)
#endif
#endif

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

extern int set_recursive_button(struct generic_brick *brick, brick_switch_t mode, int timeout);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_brick(void);
extern void exit_brick(void);

#endif
