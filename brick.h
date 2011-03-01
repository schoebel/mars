// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_H
#define BRICK_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/wait.h>

#ifdef _STRATEGY
#define _STRATEGY_CODE(X) X
#define _NORMAL_CODE(X) /**/
#else
#define _STRATEGY_CODE(X) /**/
#define _NORMAL_CODE(X) X
#endif

#define BRICK_ERROR "BRICK_ERROR "
#define BRICK_INFO  "BRICK_INFO  "
#define BRICK_DEBUG "BRICK_DEBUG "
//#define _BRICK_FMT(fmt) "[%s] " __BASE_FILE__ " %d %s(): " fmt, current->comm, __LINE__, __FUNCTION__
#define _BRICK_FMT(fmt) __BASE_FILE__ " %d %s(): " fmt, __LINE__, __FUNCTION__

#define BRICK_ERR(fmt, args...) printk(BRICK_ERROR _BRICK_FMT(fmt), ##args)
#define BRICK_INF(fmt, args...) printk(BRICK_INFO  _BRICK_FMT(fmt), ##args)
#ifdef BRICK_DEBUGGING
#define BRICK_DBG(fmt, args...) printk(BRICK_DEBUG _BRICK_FMT(fmt), ##args)
#else
#define BRICK_DBG(args...) /**/
#endif

#define MAX_BRICK_TYPES 64

/////////////////////////////////////////////////////////////////////////

// definitions for generic objects with aspects

#define MAX_DEFAULT_ASPECTS 8

struct generic_aspect;

#define GENERIC_ASPECT_TYPE(TYPE)					\
	char *aspect_type_name;						\
	const struct generic_object_type *object_type;			\
	int  aspect_size;						\
	int  (*init_fn)(struct generic_aspect *ini, void *data);	\
	void (*exit_fn)(struct generic_aspect *ini, void *data);	\

struct generic_aspect_type {
	GENERIC_ASPECT_TYPE(generic);
};

#define GENERIC_ASPECT_LAYOUT(TYPE)					\
	const struct generic_aspect_type *aspect_type;			\
	void *init_data;						\
	int aspect_offset;						\

struct generic_aspect_layout {
	GENERIC_ASPECT_LAYOUT(generic);
};

#define GENERIC_OBJECT_TYPE(TYPE)					\
	char *object_type_name;						\
	int default_size;						\
	int brick_obj_nr;						\
	int  (*init_fn)(struct generic_aspect *ini, void *data);	\
	void (*exit_fn)(struct generic_aspect *ini, void *data);	\

struct generic_object_type {
	GENERIC_OBJECT_TYPE(generic);
};

#define GENERIC_OBJECT_LAYOUT(TYPE)					\
	struct generic_aspect_layout **aspect_layouts;			\
	const struct generic_object_type *object_type;			\
	void *init_data;						\
	int aspect_count;						\
	int aspect_max;							\
	int object_size;						\
	int last_count;							\
	int last_jiffies;						\
	atomic_t alloc_count;						\
	atomic_t free_count;						\
	spinlock_t free_lock;						\
	struct generic_object *free_list;				\
	char *module_name;						\

struct generic_object_layout {
	GENERIC_OBJECT_LAYOUT(generic);
};

#define GENERIC_OBJECT(TYPE)						\
	struct TYPE##_object_layout *object_layout;			\
	int object_size;						\

struct generic_object {
	GENERIC_OBJECT(generic);
};

#define GENERIC_ASPECT(TYPE)						\
	struct TYPE##_object *object;					\

struct generic_aspect {
	GENERIC_ASPECT(generic);
};

#define GENERIC_CALLBACK(TYPE)						\
	void (*cb_fn)(struct TYPE##_callback *cb);			\
	void  *cb_private;						\
	int    cb_error;						\
	struct generic_callback *cb_prev;				\

struct generic_callback {
	GENERIC_CALLBACK(generic);
};

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
	/* _must_ be the last member */					\
	struct generic_aspect_layout aspect_layouts[BRICK_OBJ_NR];	\
	
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
	int (*make_object_layout)(struct BRICK##_output *output, struct generic_object_layout *object_layout); \
	
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
	const struct generic_aspect_type **aspect_types;		\
	const int layout_code[BRICK_OBJ_NR];				\

struct generic_output_type {
	GENERIC_OUTPUT_TYPE(generic);
};

#define LAYOUT_NONE         0
#define LAYOUT_ALL          -1
#define LAYOUT_1(X1)        ((X1) | 255 << 8)
#define LAYOUT_2(X1,X2)     ((X1) | (X2) << 8 | 255 << 16)
#define LAYOUT_3(X1,X2,X3)  ((X1) | (X2) << 8 | (X3) << 16 | 255 << 24)

int generic_register_brick_type(const struct generic_brick_type *new_type);
int generic_unregister_brick_type(const struct generic_brick_type *old_type);

inline void _generic_output_init(struct generic_brick *brick, const struct generic_output_type *type, struct generic_output *output, const char *output_name)
{
	output->output_name = output_name;
	output->brick = brick;
	output->type = type;
	output->ops = type->master_ops;
	output->nr_connected = 0;
	INIT_LIST_HEAD(&output->output_head);
}

#ifdef _STRATEGY // call this only in strategy bricks, never in ordinary bricks

// you need this only if you circumvent generic_brick_init_full()
inline int generic_brick_init(const struct generic_brick_type *type, struct generic_brick *brick, const char *brick_name)
{
	brick->brick_name = brick_name;
	brick->type = type;
	brick->ops = type->master_ops;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	brick->power.led_off = true;
	//brick->power.event = __WAIT_QUEUE_HEAD_INITIALIZER(brick->power.event);
	init_waitqueue_head(&brick->power.event);
	//INIT_LIST_HEAD(&brick->tmp_head);
	brick->tmp_head.next = brick->tmp_head.prev = &brick->tmp_head;
	return 0;
}

inline int generic_input_init(struct generic_brick *brick, int index, const struct generic_input_type *type, struct generic_input *input, const char *input_name)
{
	if (index < 0 || index >= brick->type->max_inputs)
		return -ENOMEM;
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

inline int generic_output_init(struct generic_brick *brick, int index, const struct generic_output_type *type, struct generic_output *output, const char *output_name)
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

inline int generic_size(const struct generic_brick_type *brick_type)
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

inline int generic_connect(struct generic_input *input, struct generic_output *output)
{
	BRICK_DBG("generic_connect(input=%p, output=%p)\n", input, output);
	if (!input || !output)
		return -EINVAL;
	if (input->connect)
		return -EEXIST;
	input->connect = output;
	output->nr_connected++; //TODO: protect against races, e.g. atomic_t
	list_add(&input->input_head, &output->output_head);
	BRICK_DBG("now nr_connected=%d\n", output->nr_connected);
	return 0;
}

inline int generic_disconnect(struct generic_input *input)
{
	BRICK_DBG("generic_disconnect(input=%p)\n", input);
	if (!input)
		return -EINVAL;
	if (input->connect) {
		input->connect->nr_connected--; //TODO: protect against races, e.g. atomic_t
		BRICK_DBG("now nr_connected=%d\n", input->connect->nr_connected);
		input->connect = NULL;
		list_del_init(&input->input_head);
	}
	return 0;
}

#endif // _STRATEGY

// simple wrappers for type safety
#define GENERIC_MAKE_FUNCTIONS(BRICK)					\
extern inline int BRICK##_register_brick_type(void)		        \
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
extern inline int BRICK##_unregister_brick_type(void)		        \
{									\
	extern const struct BRICK##_brick_type BRICK##_brick_type;	\
	return generic_unregister_brick_type((const struct generic_brick_type*)&BRICK##_brick_type); \
}									\
									\
extern int BRICK##_make_object_layout(struct BRICK##_output *output, struct generic_object_layout *object_layout) \
{									\
	return default_make_object_layout((struct generic_output*)output, object_layout); \
}									\
									\
extern const struct BRICK##_brick_type BRICK##_brick_type;	        \
extern const struct BRICK##_input_type BRICK##_input_type;	        \
extern const struct BRICK##_output_type BRICK##_output_type;	        \
									\
static inline void _##BRICK##_output_init(struct BRICK##_brick *brick, struct BRICK##_output *output, char *output_name) \
{									\
	_generic_output_init(						\
		(struct generic_brick*)brick,				\
		(const struct generic_output_type*)&BRICK##_output_type, \
		(struct generic_output*)output,				\
		output_name);						\
}									\
									\
_STRATEGY_CODE(							        \
static inline int BRICK##_brick_init(struct BRICK##_brick *brick, char *brick_name) \
{									\
	return generic_brick_init((const struct generic_brick_type*)&BRICK##_brick_type, (struct generic_brick*)brick, brick_name); \
}									\
									\
static inline int BRICK##_input_init(struct BRICK##_brick *brick, int index, struct BRICK##_input *input, char *input_name) \
{									\
	return generic_input_init(					\
		(struct generic_brick*)brick,				\
		index,							\
		(struct generic_input_type*)&BRICK##_input_type,	\
		(struct generic_input*)input,				\
		input_name);						\
}									\
									\
static inline int BRICK##_output_init(struct BRICK##_brick *brick, int index, struct BRICK##_output *output, char *output_name) \
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
 * (a) thou shalt not define many types,
 * (b) these macros generate only definitions, but no additional 
 * code at runtime.
 */
#define GENERIC_MAKE_CONNECT(INPUT_BRICK,OUTPUT_BRICK)			\
									\
_STRATEGY_CODE(							        \
									\
inline int INPUT_BRICK##_##OUTPUT_BRICK##_connect(	        \
	struct INPUT_BRICK##_input *input,				\
	struct OUTPUT_BRICK##_output *output)				\
{									\
	return generic_connect((struct generic_input*)input, (struct generic_output*)output); \
}									\
									\
inline int INPUT_BRICK##_##OUTPUT_BRICK####_disconnect(        \
	struct INPUT_BRICK##_input *input)				\
{									\
	return generic_disconnect((struct generic_input*)input);	\
}									\
)

///////////////////////////////////////////////////////////////////////

// default operations on objects / aspects

extern int default_make_object_layout(struct generic_output *output, struct generic_object_layout *object_layout);

extern int generic_add_aspect(struct generic_output *output, struct generic_object_layout *object_layout, const struct generic_aspect_type *aspect_type);

extern int default_init_object_layout(struct generic_output *output, struct generic_object_layout *object_layout, int aspect_max, const struct generic_object_type *object_type, char *module_name);

extern struct generic_object *alloc_generic(struct generic_object_layout *object_layout);

extern void free_generic(struct generic_object *object);

#define GENERIC_OBJECT_LAYOUT_FUNCTIONS(BRICK)				\
									\
inline int BRICK##_init_object_layout(struct BRICK##_output *output, struct generic_object_layout *object_layout, int aspect_max, const struct generic_object_type *object_type) \
{									\
	if (likely(object_layout->object_type))				\
		return 0;						\
	return default_init_object_layout((struct generic_output*)output, object_layout, aspect_max, object_type, #BRICK); \
}									\

#define GENERIC_ASPECT_LAYOUT_FUNCTIONS(BRICK,TYPE)			\
									\
inline int BRICK##_##TYPE##_add_aspect(struct BRICK##_output *output, struct TYPE##_object_layout *object_layout, const struct generic_aspect_type *aspect_type) \
{									\
	int res = generic_add_aspect((struct generic_output*)output, (struct generic_object_layout *)object_layout, aspect_type); \
	BRICK_DBG(#BRICK " " #TYPE "added aspect_type %p (%s) to object_layout %p (type %s) on output %p (type %s), status=%d\n", aspect_type, aspect_type->aspect_type_name, object_layout, object_layout->object_type->object_type_name, output, output->type->type_name, res); \
	return res;							\
}									\

#define GENERIC_OBJECT_FUNCTIONS(TYPE)					\
									\
inline struct TYPE##_object *TYPE##_construct(void *data, struct TYPE##_object_layout *object_layout) \
{									\
	struct TYPE##_object *obj = data;				\
	int i;								\
									\
	obj->object_layout = object_layout;				\
	if (object_layout->object_type->init_fn) {			\
		int status = object_layout->object_type->init_fn((void*)obj, object_layout->init_data); \
		if (status < 0) {					\
			return NULL;					\
		}							\
	}								\
	for (i = 0; i < object_layout->aspect_count; i++) {		\
		struct generic_aspect_layout *aspect_layout;		\
		struct generic_aspect *aspect;				\
		aspect_layout = object_layout->aspect_layouts[i];	\
		if (!aspect_layout->aspect_type)				\
			continue;					\
		aspect = data + aspect_layout->aspect_offset;		\
		aspect->object = (void*)obj;				\
		if (aspect_layout->aspect_type->init_fn) {		\
			int status = aspect_layout->aspect_type->init_fn((void*)aspect, aspect_layout->init_data); \
			if (status < 0) {				\
				return NULL;				\
			}						\
		}							\
	}								\
	return obj;							\
}									\
									\
inline void TYPE##_destruct(struct TYPE##_object *obj)	        \
{									\
	struct TYPE##_object_layout *object_layout = obj->object_layout; \
	int i;								\
									\
	if (unlikely(!object_layout || !object_layout->object_type)) {	\
		BRICK_ERR("object %p/%p is corrupted\n", obj, object_layout); \
		dump_stack();						\
		return;							\
	}								\
	if (object_layout->object_type->exit_fn) {			\
		object_layout->object_type->exit_fn((void*)obj, object_layout->init_data); \
	}								\
	for (i = 0; i < object_layout->aspect_count; i++) {		\
		struct generic_aspect_layout *aspect_layout;		\
		struct generic_aspect *aspect;				\
		aspect_layout = object_layout->aspect_layouts[i];	\
		if (!aspect_layout->aspect_type)				\
			continue;					\
		aspect = ((void*)obj) + aspect_layout->aspect_offset;	\
		if (aspect_layout->aspect_type->exit_fn) {		\
			aspect_layout->aspect_type->exit_fn((void*)aspect, aspect_layout->init_data); \
		}							\
	}								\
}									\

#define GENERIC_ASPECT_FUNCTIONS(BRICK,TYPE)				\
									\
inline struct BRICK##_##TYPE##_aspect *BRICK##_##TYPE##_get_aspect(struct BRICK##_output *output, struct TYPE##_object *obj) \
{									\
	struct generic_object_layout *object_layout;			\
	struct generic_aspect_layout *aspect_layout;			\
	int nr;								\
									\
	object_layout = (struct generic_object_layout*)obj->object_layout; \
	nr = object_layout->object_type->brick_obj_nr;			\
	aspect_layout = &output->aspect_layouts[nr];			\
	if (unlikely(!aspect_layout->aspect_type)) {			\
		BRICK_ERR("brick "#BRICK": bad aspect slot on " #TYPE " pointer %p\n", obj); \
		return NULL;						\
	}								\
	return (void*)obj + aspect_layout->aspect_offset;		\
}									\
									\
inline int BRICK##_##TYPE##_init_object_layout(struct BRICK##_output *output, struct generic_object_layout *object_layout) \
{									\
	return BRICK##_init_object_layout(output, object_layout, 32, &TYPE##_type); \
}									\
									\
inline struct TYPE##_object *BRICK##_alloc_##TYPE(struct BRICK##_output *output, struct generic_object_layout *object_layout) \
{									\
	int status = BRICK##_##TYPE##_init_object_layout(output, object_layout);	\
	if (status < 0)							\
		return NULL;						\
	return (struct TYPE##_object*)alloc_generic(object_layout);	\
}									\
									\
inline struct TYPE##_object *BRICK##_alloc_##TYPE##_pure(struct generic_object_layout *object_layout) \
{									\
	return (struct TYPE##_object*)alloc_generic(object_layout);	\
}									\
									\
inline void BRICK##_free_##TYPE(struct TYPE##_object *object)     \
{									\
	free_generic((struct generic_object*)object);			\
}									\


GENERIC_OBJECT_LAYOUT_FUNCTIONS(generic);
GENERIC_OBJECT_FUNCTIONS(generic);

///////////////////////////////////////////////////////////////////////

// some general helpers

extern void get_lamport(struct timespec *now);
extern void set_lamport(struct timespec *old);



#if 0
#undef spin_lock_irqsave
#define spin_lock_irqsave(l,f)       spin_lock(l)
#undef spin_unlock_irqrestore
#define spin_unlock_irqrestore(l,f)  spin_unlock(l)
#endif

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
	} while (0)

# define traced_writelock(spinlock,flags)				\
	do {								\
		if (atomic_read(&current->lock_count)) {			\
			BRICK_ERR("please do not nest spinlocks at line %d, reorganize your code.\n", __LINE__); \
		}							\
		atomic_inc(&current->lock_count);			\
		(void)flags;						\
		read_lock(spinlock);					\
	} while (0)

# define traced_writeunlock(spinlock,flags)				\
	do {								\
		/*spin_unlock_irqrestore(spinlock,flags);*/		\
		read_unlock(spinlock);					\
		atomic_dec(&current->lock_count);			\
	} while (0)

#else

# define LOCK_CHECK(OP) 0
# define traced_lock(spinlock,flags)   spin_lock_irqsave(spinlock,flags)
# define traced_unlock(spinlock,flags) spin_unlock_irqrestore(spinlock,flags)
# define traced_readlock(spinlock,flags)   read_lock_irqsave(spinlock,flags)
# define traced_readunlock(spinlock,flags) read_unlock_irqrestore(spinlock,flags)
# define traced_writelock(spinlock,flags)   write_lock_irqsave(spinlock,flags)
# define traced_writeunlock(spinlock,flags) write_unlock_irqrestore(spinlock,flags)

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

// metadata descriptions

/* The idea is to describe your C structures in such a way that
 * transfers to disk or over a network become self-describing.
 *
 * In essence, this is a kind of version-independent marshalling.
 *
 * Advantage:
 * When you extend your original C struct (and of course update the
 * corresponding meta structure), old data on disk (or network peers
 * running an old version of your program) will remain valid.
 * Upon read, newly added fields missing in the old version will be simply
 * not filled in and therefore remain zeroed (if you don't forget to
 * initially clear your structures via memset() / initializers / etc).
 * Note that this works only if you never rename or remove existing
 * fields; you should only add new ones.
 * [TODO: add macros for description of ignored / renamed fields to
 *  overcome this limitation]
 * You may increase the size of integers, for example from 32bit to 64bit
 * or even higher; sign extension will be automatically carried out
 * when necessary.
 * [TODO; NYI]
 * Also, you may change the order of fields, because the metadata interpreter
 * will check each field individually; field offsets are automatically
 * maintained.
 *
 * Disadvantage: this adds some (small) overhead.
 */

#define MAX_FIELD_LEN 24

enum field_type {
	FIELD_DONE,
	FIELD_REF,
	FIELD_SUB,
	FIELD_STRING,
	FIELD_RAW,
	FIELD_INT,
	FIELD_UINT,
};

struct meta {
	char  field_name[MAX_FIELD_LEN];
	int   field_type;
	int   field_size;
	int   field_offset;
	const struct meta *field_ref;
};

#define _META_INI(NAME,STRUCT,TYPE)					\
	.field_name = #NAME,						\
	.field_type = TYPE,					        \
	.field_size = sizeof(((STRUCT*)NULL)->NAME),		        \
	.field_offset = offsetof(STRUCT, NAME)			        \

#define META_INI(NAME,STRUCT,TYPE) { _META_INI(NAME,STRUCT,TYPE) }

#define _META_INI_REF(NAME,STRUCT,REF)					\
	.field_name = #NAME,						\
	.field_type = FIELD_REF,				        \
	.field_size = sizeof(*(((STRUCT*)NULL)->NAME)),		        \
	.field_offset = offsetof(STRUCT, NAME),			        \
	.field_ref = REF

#define META_INI_REF(NAME,STRUCT,REF) { _META_INI_REF(NAME,STRUCT,REF) }

#define _META_INI_SUB(NAME,STRUCT,SUB)					\
	.field_name = #NAME,						\
	.field_type = FIELD_SUB,				        \
	.field_size = sizeof(((STRUCT*)NULL)->NAME),		        \
	.field_offset = offsetof(STRUCT, NAME),			        \
	.field_ref = SUB

#define META_INI_SUB(NAME,STRUCT,SUB) { _META_INI_SUB(NAME,STRUCT,SUB) }

extern const struct meta *find_meta(const struct meta *meta, const char *field_name);
extern void free_meta(void *data, const struct meta *meta);

#endif
