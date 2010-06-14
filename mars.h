// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_H
#define MARS_H

#include <linux/list.h>

#ifdef _STRATEGY
#define _STRATEGY_CODE(X) X
#define _NORMAL_CODE(X) /**/
#else
#define _STRATEGY_CODE(X) /**/
#define _NORMAL_CODE(X) X
#endif

#define MARS_INFO "MARS_INFO: "
#define MARS_ERROR "MARS_ERROR: "

#define MARS_ERR(args...) printk(MARS_ERROR args)
#define MARS_DBG(args...) printk("MARS_DEBUG: " args)

/////////////////////////////////////////////////////////////////////////

// definitions for generic objects

#define MAX_DEFAULT_ASPECTS 8

#define GENERIC_OBJECT_LAYOUT(PREFIX)				\
	int max_size;						\
	int rest_size;						\
	int max_aspects;					\
	int nr_aspects;						\
	int *aspect_sizes;					\
	int *aspect_offsets;					\
	void *alloc_ptr;					\

struct generic_object_layout {
	GENERIC_OBJECT_LAYOUT(generic);
};

#ifdef _STRATEGY
#define GENERIC_OBJECT_LAYOUT_FUNCTIONS(PREFIX)				\
extern inline struct PREFIX##_object_layout *PREFIX##_init_object_layout(void *data, int size, int max_aspects) \
{									\
	struct PREFIX##_object_layout *object_layout = data;		\
	size -= sizeof(struct PREFIX##_object_layout);			\
	if (size < 0)							\
		return NULL;						\
	object_layout->max_aspects = max_aspects;			\
	object_layout->nr_aspects = 0;					\
	object_layout->max_size = sizeof(struct PREFIX##_object_layout); \
	data += sizeof(struct PREFIX##_object_layout);			\
	size -= max_aspects * sizeof(void*) * 2;			\
	if (size < 0)							\
		return NULL;						\
	object_layout->rest_size = size;				\
	object_layout->aspect_sizes = data;				\
	data += max_aspects * sizeof(void*);				\
	object_layout->aspect_offsets = data;				\
	data += max_aspects * sizeof(void*);				\
	object_layout->alloc_ptr = data;				\
	return object_layout;						\
}									\
									\
extern int PREFIX##_add_aspect(struct PREFIX##_object_layout *object_layout, int aspect_size) \
{									\
	int slot = object_layout->nr_aspects;				\
	int max_aspects = object_layout->max_aspects;			\
	if (unlikely(slot >= max_aspects)) {				\
		void *data = object_layout->alloc_ptr;			\
		void *old;						\
		int size = object_layout->rest_size;			\
		max_aspects <<= 1;					\
		size -= max_aspects * sizeof(void*) * 2;		\
		if (size < 0)						\
			return -ENOMEM;					\
		object_layout->rest_size = size;			\
		old = object_layout->aspect_sizes;			\
		object_layout->aspect_sizes = data;			\
		memcpy(data, old, max_aspects * sizeof(void*));		\
		data += max_aspects * sizeof(void*);			\
		old = object_layout->aspect_offsets;			\
		object_layout->aspect_offsets = data;			\
		memcpy(data, old, max_aspects * sizeof(void*));		\
		data += max_aspects * sizeof(void*);			\
		object_layout->alloc_ptr = data;			\
		object_layout->max_aspects = max_aspects;		\
	}								\
	object_layout->aspect_sizes[slot] = aspect_size;		\
	object_layout->aspect_offsets[slot] = object_layout->max_size;	\
	object_layout->max_size += aspect_size;				\
	object_layout->nr_aspects++;					\
	return slot;							\
}									\

#endif

#define GENERIC_OBJECT(PREFIX)					\
	struct PREFIX##_object_layout *object_layout;		\
	int object_size;					\

struct generic_object {
	GENERIC_OBJECT(generic);
};

#define GENERIC_ASPECT(PREFIX)					\
	struct PREFIX##_object *object;				\

struct generic_aspect {
	GENERIC_ASPECT(generic);
};

#define GENERIC_OBJECT_FUNCTIONS(PREFIX)				\
extern inline struct PREFIX##_object *PREFIX##_construct(void *data, struct PREFIX##_object_layout *object_layout) \
{									\
	int i;								\
	struct PREFIX##_object *obj = data;				\
	obj->object_layout = object_layout;				\
	for (i = 0; i < object_layout->nr_aspects; i++) {		\
		struct PREFIX##_aspect *aspect = data + object_layout->aspect_offsets[i]; \
		aspect->object = obj;					\
	}								\
	return obj;							\
}									\
									\
extern inline void *PREFIX##_get_aspect(struct PREFIX##_object *obj, int slot) \
{									\
	if (slot < 0 || slot >= obj->object_layout->nr_aspects)		\
		return NULL;						\
	return (void*)obj + obj->object_layout->aspect_offsets[slot];	\
}									\
									\


/////////////////////////////////////////////////////////////////////////

// definitions for generic bricks

struct generic_input;
struct generic_output;
struct generic_brick_ops;
struct generic_output_ops;
struct generic_brick_type;

#define GENERIC_BRICK(PREFIX)					\
	char *brick_name;					\
	struct PREFIX##_brick_type *type;			\
	struct PREFIX##_brick_ops *ops;				\
	int nr_inputs;						\
	int nr_outputs;						\
	struct PREFIX##_input **inputs;				\
	struct PREFIX##_output **outputs;			\
	struct list_head tmp_head;				\

struct generic_brick {
	GENERIC_BRICK(generic);
};

#define GENERIC_INPUT(PREFIX)					\
	char *input_name;					\
	struct PREFIX##_brick *brick;				\
	struct PREFIX##_input_type *type;			\
	struct PREFIX##_output *connect;			\
	
struct generic_input {
	GENERIC_INPUT(generic);
};

#define GENERIC_OUTPUT(PREFIX)					\
	char *output_name;					\
	struct PREFIX##_brick *brick;				\
	struct PREFIX##_output_type *type;			\
	struct PREFIX##_output_ops *ops;			\
	int nr_connected;					\
	
struct generic_output {
	GENERIC_OUTPUT(generic);
};

#define _GENERIC_CALL(ERROR,PTR,OP,...)				\
	((PTR)->ops->OP ? (PTR)->ops->OP(__VA_ARGS__) : ERROR)

#define GENERIC_CALL(PTR,OP,...)		\
	_GENERIC_CALL(0, PTR, OP, __VA_ARGS__)

#define GENERIC_CALL_FORCE(PTR,OP,...)		\
	_GENERIC_CALL(-ENOSYS, PTR, OP, __VA_ARGS__)

#define GENERIC_BRICK_OPS(PREFIX)				 \
	int (*brick_start)(struct PREFIX##_brick *brick);	 \
	int (*brick_stop)(struct PREFIX##_brick *brick);	 \
	
struct generic_brick_ops {
	GENERIC_BRICK_OPS(generic);
};

#define GENERIC_OUTPUT_OPS(PREFIX)				\
	int (*output_start)(struct PREFIX##_output *output);	\
	int (*output_stop)(struct PREFIX##_output *output);	\
	
struct generic_output_ops {
	GENERIC_OUTPUT_OPS(generic)
};

// although possible, *_type should never be extended
#define GENERIC_BRICK_TYPE(PREFIX)					\
	char type_name[32];						\
	int brick_size;							\
	int max_inputs;							\
	int max_outputs;						\
	struct PREFIX##_input_type **default_input_types;		\
	char **default_input_names;					\
	struct PREFIX##_output_type **default_output_types;		\
	char **default_output_names;					\
	struct PREFIX##_brick_ops *master_ops;				\
	struct PREFIX##input_types **default_type;			\
	int (*brick_construct)(struct PREFIX##_brick *brick);		\
	int (*brick_destruct)(struct PREFIX##_brick *brick);		\

struct generic_brick_type {
	GENERIC_BRICK_TYPE(generic);
};

#define GENERIC_INPUT_TYPE(PREFIX)					\
	char type_name[32];						\
	int input_size;							\
	int (*input_construct)(struct PREFIX##_input *input);		\
	int (*input_destruct)(struct PREFIX##_input *input);		\

struct generic_input_type {
	GENERIC_INPUT_TYPE(generic);
};

#define GENERIC_OUTPUT_TYPE(PREFIX)					\
	char type_name[32];						\
	int output_size;						\
	struct PREFIX##_output_ops *master_ops;				\
	int (*output_construct)(struct PREFIX##_output *output);	\
	int (*output_destruct)(struct PREFIX##_output *output);		\

struct generic_output_type {
	GENERIC_OUTPUT_TYPE(generic);
};

int generic_register_brick_type(struct generic_brick_type *new_type);
int generic_unregister_brick_type(struct generic_brick_type *old_type);

#ifdef _STRATEGY // call this only in strategy bricks, never in ordinary bricks

// you need this only if you circumvent generic_brick_init_full()
extern inline int generic_brick_init(struct generic_brick_type *type, struct generic_brick *brick, char *brick_name)
{
	brick->brick_name = brick_name;
	brick->type = type;
	brick->ops = type->master_ops;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	brick->tmp_head.next = brick->tmp_head.prev = &brick->tmp_head;
	return 0;
}

extern inline int generic_input_init(struct generic_brick *brick, int index, struct generic_input_type *type, struct generic_input *input, char *input_name)
{
	if (index < 0 || index >= brick->type->max_inputs)
		return -ENOMEM;
	if (brick->inputs[index])
		return -EEXIST;
	input->input_name = input_name;
	input->brick = brick;
	input->type = type;
	input->connect = NULL;
	brick->inputs[index] = input;
	brick->nr_inputs++;
	return 0;
}

extern inline int generic_output_init(struct generic_brick *brick, int index, struct generic_output_type *type, struct generic_output *output, char *output_name)
{
	if (index < 0 || index >= brick->type->max_outputs)
		return -ENOMEM;
	if (brick->outputs[index])
		return -EEXIST;
	output->output_name = output_name;
	output->brick = brick;
	output->type = type;
	output->ops = type->master_ops;
	output->nr_connected = 0;
	brick->outputs[index] = output;
	brick->nr_outputs++;
	return 0;
}

extern inline int generic_size(struct generic_brick_type *brick_type)
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
	struct generic_brick_type *brick_type,
	struct generic_input_type **input_types,
	struct generic_output_type **output_types,
	char **names);
int generic_brick_exit_full(
	struct generic_brick *brick);

extern inline int generic_connect(struct generic_input *input, struct generic_output *output)
{
	MARS_DBG("generic_connect(input=%p, output=%p)\n", input, output);
	if (!input || !output)
		return -EINVAL;
	if (input->connect)
		return -EEXIST;
	input->connect = output;
	output->nr_connected++; //TODO: protect against races, e.g. atomic_t
	MARS_DBG("now nr_connected=%d\n", output->nr_connected);
	return 0;
}

extern inline int generic_disconnect(struct generic_input *input)
{
	MARS_DBG("generic_disconnect(input=%p)\n", input);
	if (!input)
		return -EINVAL;
	if (input->connect) {
		input->connect->nr_connected--; //TODO: protect against races, e.g. atomic_t
		MARS_DBG("now nr_connected=%d\n", input->connect->nr_connected);
		input->connect = NULL;
	}
	return 0;
}

#endif // _STRATEGY

// simple wrappers for type safety
#define GENERIC_MAKE_FUNCTIONS(PREFIX)					\
extern inline int PREFIX##_register_brick_type(void)		        \
{									\
	extern struct PREFIX##_brick_type PREFIX##_brick_type;		\
	return generic_register_brick_type((struct generic_brick_type*)&PREFIX##_brick_type); \
}\
									\
extern inline int PREFIX##_unregister_brick_type(void)		        \
{									\
	extern struct PREFIX##_brick_type PREFIX##_brick_type;		\
	return generic_unregister_brick_type((struct generic_brick_type*)&PREFIX##_brick_type); \
}									\
									\
_STRATEGY_CODE(							        \
extern struct PREFIX##_brick_type PREFIX##_brick_type;		        \
extern struct PREFIX##_input_type PREFIX##_input_type;	                \
extern struct PREFIX##_output_type PREFIX##_output_type;	        \
									\
static inline int PREFIX##_brick_init(struct PREFIX##_brick *brick, char *brick_name) \
{									\
	return generic_brick_init((struct generic_brick_type*)&PREFIX##_brick_type, (struct generic_brick*)brick, brick_name); \
}									\
									\
static inline int PREFIX##_input_init(struct PREFIX##_brick *brick, int index, struct PREFIX##_input *input, char *input_name) \
{									\
	return generic_input_init(					\
		(struct generic_brick*)brick,				\
		index,							\
		(struct generic_input_type*)&PREFIX##_input_type,	\
		(struct generic_input*)input,				\
		input_name);						\
}									\
									\
static inline int PREFIX##_output_init(struct PREFIX##_brick *brick, int index, struct PREFIX##_input *output, char *output_name) \
{									\
	return generic_output_init(					\
		(struct generic_brick*)brick,				\
		index,							\
		(struct generic_output_type*)&PREFIX##_output_type,	\
		(struct generic_output*)output,				\
		output_name);						\
}									\
									\
extern inline int PREFIX##_size(struct PREFIX##_brick_type *brick_type) \
{									\
	return generic_size((struct generic_brick_type*)brick_type);	\
}									\
									\
extern inline int PREFIX##_brick_init_full(			        \
	void *data,							\
	int size,							\
	struct PREFIX##_brick_type *brick_type,				\
	struct PREFIX##_input_type **input_types,			\
	struct PREFIX##_output_type **output_types,			\
	char **names)							\
{									\
	return generic_brick_init_full(					\
		data,							\
		size,							\
		(struct generic_brick_type*)brick_type,			\
		(struct generic_input_type**)input_types,		\
		(struct generic_output_type**)output_types,		\
		(char**)names);						\
}									\
									\
extern inline int PREFIX##_brick_exit_full(			        \
	struct PREFIX##_brick *brick)					\
{									\
	return generic_brick_exit_full(					\
		(struct generic_brick*)brick);				\
}									\
)

/* Define a pair of connectable subtypes.
 * For type safety, use this for all possible combinations.
 * Yes, this may become quadratic in large type systems, but
 * (a) thou shalt not define many types,
 * (b) these macros generate only definitions, no code by itself
 */
#define GENERIC_MAKE_CONNECT(INPUT_PREFIX,OUTPUT_PREFIX)		\
									\
_STRATEGY_CODE(							        \
									\
extern inline int INPUT_PREFIX##_##OUTPUT_PREFIX##_connect(	        \
	struct INPUT_PREFIX##_input *input,				\
	struct OUTPUT_PREFIX##_output *output)				\
{									\
	return generic_connect((struct generic_input*)input, (struct generic_output*)output); \
}									\
									\
extern inline int INPUT_PREFIX##_##OUTPUT_PREFIX####_disconnect(        \
	struct INPUT_PREFIX##_input *input)				\
{									\
	return generic_disconnect((struct generic_input*)input);	\
}									\
)

/////////////////////////////////////////////////////////////////////////

// MARS-specific definitions

#define HT_SHIFT 6 //????
#define MARS_MAX_SEGMENT_SIZE (1U << (9+HT_SHIFT))

#define MARS_IO(PREFIX)					\
	GENERIC_OBJECT(PREFIX);				\
	struct bio *orig_bio;				\
	struct bio *mars_bio;				\
	int (*mars_endio)(struct mars_io *mio);		\

struct mars_io {
	MARS_IO(mars);
};

#define MARS_BRICK(PREFIX)				\
	GENERIC_BRICK(PREFIX);				\

struct mars_brick {
	MARS_BRICK(mars);
};

#define MARS_INPUT(PREFIX)				\
	GENERIC_INPUT(PREFIX);				\

struct mars_input {
	MARS_INPUT(mars);
};

#define MARS_OUTPUT(PREFIX)				\
	GENERIC_OUTPUT(PREFIX);				\

struct mars_output {
	MARS_OUTPUT(mars);
};

#define MARS_BRICK_OPS(PREFIX)					\
	GENERIC_BRICK_OPS(PREFIX);				\
	int (*mars_dummy_op)(int);				\

#define MARS_OUTPUT_OPS(PREFIX)					\
	GENERIC_OUTPUT_OPS(PREFIX);				\
	int (*mars_io)(struct PREFIX##_output *output, struct mars_io *mio); \

// all non-extendable types
#define _MARS_TYPES(PREFIX)		\
struct PREFIX##_brick_ops {	        \
	MARS_BRICK_OPS(PREFIX);		\
};					\
					\
struct PREFIX##_output_ops {	        \
	MARS_OUTPUT_OPS(PREFIX);	\
};					\
					\
struct PREFIX##_brick_type {		\
	GENERIC_BRICK_TYPE(PREFIX);	\
};					\
					\
struct PREFIX##_input_type {		\
	GENERIC_INPUT_TYPE(PREFIX);	\
};					\
					\
struct PREFIX##_output_type {		\
	GENERIC_OUTPUT_TYPE(PREFIX);	\
};					\
					\
GENERIC_MAKE_FUNCTIONS(PREFIX);	        \
GENERIC_MAKE_CONNECT(PREFIX,PREFIX);	\

#define MARS_TYPES(PREFIX)		\
_MARS_TYPES(PREFIX)		        \
GENERIC_MAKE_CONNECT(generic,PREFIX);	\
GENERIC_MAKE_CONNECT(mars,PREFIX);	\


/////////////////////////////////////////////////////////////////////////

// MARS-specific helper functions

_MARS_TYPES(mars);
GENERIC_MAKE_CONNECT(generic,mars);

#endif
