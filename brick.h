// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_H
#define BRICK_H

#ifdef _STRATEGY
#define _STRATEGY_CODE(X) X
#define _NORMAL_CODE(X) /**/
#else
#define _STRATEGY_CODE(X) /**/
#define _NORMAL_CODE(X) X
#endif

#define BRICK_ERROR "BRICK_ERROR: "
#define BRICK_INFO  "BRICK_INFO: "
#define BRICK_DEBUG "BRICK_DEBUG: "

#define BRICK_ERR(args...) printk(BRICK_ERROR args)
#define BRICK_INF(args...) printk(BRICK_INFO args)
#ifdef BRICK_DEBUGGING
#define BRICK_DBG(args...) printk(BRICK_DEBUG args)
#else
#define BRICK_DBG(args...) /**/
#endif

#define MAX_BRICK_TYPES 64

/////////////////////////////////////////////////////////////////////////

// definitions for generic objects with aspects

#define MAX_DEFAULT_ASPECTS 8

struct generic_aspect;

#define GENERIC_ASPECT_TYPE(PREFIX)					\
	char *aspect_type_name;						\
	int aspect_size;						\
	int (*init_fn)(struct generic_aspect *ini, void *data);	\

struct generic_aspect_type {
	GENERIC_ASPECT_TYPE(generic);
};

#define GENERIC_ASPECT_LAYOUT(PREFIX)					\
	struct generic_object_layout     *object_layout;		\
	const struct generic_aspect_type *aspect_type;			\
	int aspect_offset;						\
	void *init_data;						\
	struct PREFIX##_aspect_layout *next; /* TODO: replace with list_head */	\

struct generic_aspect_layout {
	GENERIC_ASPECT_LAYOUT(generic);
};

#define GENERIC_OBJECT_TYPE(PREFIX)					\
	char *object_type_name;						\
	int default_size;						\
	int brick_obj_nr;						\

struct generic_object_type {
	GENERIC_OBJECT_TYPE(generic);
};

#define GENERIC_OBJECT_LAYOUT(PREFIX)					\
	const struct generic_object_type *object_type;			\
	struct generic_aspect_layout *aspect_list; /* TODO: replace with list_head */ \
	int object_size;						\
	int rest_size;							\
	void *alloc_ptr;						\

struct generic_object_layout {
	GENERIC_OBJECT_LAYOUT(generic);
};

#define GENERIC_OBJECT_LAYOUT_FUNCTIONS(PREFIX)				\
									\
extern inline struct PREFIX##_object_layout *PREFIX##_init_object_layout(void *data, int size, int max_aspects, const struct generic_object_type *object_type) \
{									\
	struct PREFIX##_object_layout *object_layout = data;		\
	data += sizeof(struct PREFIX##_object_layout);			\
	size -= sizeof(struct PREFIX##_object_layout);			\
	if (size < 0)							\
		return NULL;						\
	object_layout->object_type = object_type;			\
	object_layout->object_size = object_type->default_size;		\
	object_layout->alloc_ptr = data;				\
	object_layout->rest_size = size;				\
	return object_layout;						\
}									\

#define GENERIC_ASPECT_LAYOUT_FUNCTIONS(BRICK,PREFIX)			\
									\
extern int BRICK##_##PREFIX##_add_aspect(struct BRICK##_output *output, struct generic_object_layout *object_layout, const struct generic_aspect_type *aspect_type) \
{									\
	int nr = object_layout->object_type->brick_obj_nr;		\
	struct generic_aspect_layout *aspect_layout;			\
	aspect_layout = (void*)&output->aspect_layouts[nr];		\
	if (aspect_layout->object_layout)				\
		return -EEXIST;						\
	aspect_layout->next = object_layout->aspect_list;		\
	object_layout->aspect_list = aspect_layout;			\
	aspect_layout->object_layout = object_layout;			\
	aspect_layout->aspect_type = aspect_type;			\
	aspect_layout->aspect_offset = object_layout->object_size;	\
	aspect_layout->init_data = output;				\
	object_layout->object_size += aspect_type->aspect_size;		\
	return 0;							\
}									\

#define GENERIC_OBJECT(PREFIX)						\
	struct PREFIX##_object_layout *object_layout;			\
	int object_size;						\

struct generic_object {
	GENERIC_OBJECT(generic);
};

#define GENERIC_ASPECT(PREFIX)						\
	struct PREFIX##_object *object;					\

struct generic_aspect {
	GENERIC_ASPECT(generic);
};

#define GENERIC_OBJECT_FUNCTIONS(PREFIX)				\
									\
extern inline struct PREFIX##_object *PREFIX##_construct(void *data, struct PREFIX##_object_layout *object_layout) \
{									\
	struct PREFIX##_object *obj = data;				\
	struct generic_aspect_layout *aspect_layout;			\
									\
	obj->object_layout = object_layout;				\
	for (aspect_layout = object_layout->aspect_list; aspect_layout; aspect_layout = aspect_layout->next) { \
		struct generic_aspect *aspect;				\
		if (!aspect_layout->aspect_type)				\
			continue;					\
		aspect = data + aspect_layout->aspect_offset;		\
		aspect->object = (void*)obj;				\
		if (aspect_layout->aspect_type->init_fn) {		\
			int status = aspect_layout->aspect_type->init_fn((void*)aspect, aspect_layout->init_data); \
			if (status) {					\
				return NULL;				\
			}						\
		}							\
	}								\
	return obj;							\
}									\

#define GENERIC_ASPECT_FUNCTIONS(BRICK,PREFIX)				\
									\
extern inline struct BRICK##_##PREFIX##_aspect *BRICK##_##PREFIX##_get_aspect(struct BRICK##_output *output, struct PREFIX##_object *obj) \
{									\
	struct PREFIX##_object_layout *object_layout;			\
	struct generic_aspect_layout *aspect_layout;			\
	int nr;								\
									\
	object_layout = obj->object_layout;				\
	nr = object_layout->object_type->brick_obj_nr;			\
	aspect_layout = &output->aspect_layouts[nr];			\
	if (unlikely(!aspect_layout->aspect_type)) {			\
		BRICK_ERR("brick "#BRICK": bad aspect slot on "#PREFIX" pointer %p\n", obj); \
		return NULL;						\
	}								\
	return (void*)obj + aspect_layout->aspect_offset;		\
}									\
									\


/////////////////////////////////////////////////////////////////////////

// definitions for generic bricks

struct generic_input;
struct generic_output;
struct generic_brick_ops;
struct generic_output_ops;
struct generic_brick_type;

#define GENERIC_BRICK(PREFIX)						\
	char *brick_name;						\
	const struct PREFIX##_brick_type *type;				\
	struct PREFIX##_brick_ops *ops;					\
	int nr_inputs;							\
	int nr_outputs;							\
	struct PREFIX##_input **inputs;					\
	struct PREFIX##_output **outputs;				\
	struct list_head tmp_head;					\

struct generic_brick {
	GENERIC_BRICK(generic);
};

#define GENERIC_INPUT(PREFIX)						\
	char *input_name;						\
	struct PREFIX##_brick *brick;					\
	const struct PREFIX##_input_type *type;				\
	struct PREFIX##_output *connect;				\
	
struct generic_input {
	GENERIC_INPUT(generic);
};

#define GENERIC_OUTPUT(PREFIX)						\
	char *output_name;						\
	struct PREFIX##_brick *brick;					\
	const struct PREFIX##_output_type *type;			\
	struct PREFIX##_output_ops *ops;				\
	int nr_connected;						\
	/* _must_ be the last member */					\
	struct generic_aspect_layout aspect_layouts[BRICK_OBJ_NR];	\
	
struct generic_output {
	GENERIC_OUTPUT(generic);
};

#define GENERIC_OUTPUT_CALL(OUTPUT,OP,...)				\
	((OUTPUT) && (OUTPUT)->ops->OP ?				\
	 (OUTPUT)->ops->OP(OUTPUT, ##__VA_ARGS__) : -ENOSYS)		\

#define GENERIC_INPUT_CALL(INPUT,OP,...)				\
	((INPUT) && (INPUT)->connect ?					\
	 GENERIC_OUTPUT_CALL((INPUT)->connect, OP, ##__VA_ARGS__) :	\
	 -ENOSYS)							\

#define GENERIC_BRICK_OPS(PREFIX)					\
	/*int (*brick_start)(struct PREFIX##_brick *brick);*/		\
	/*int (*brick_stop)(struct PREFIX##_brick *brick);*/		\
	
struct generic_brick_ops {
	GENERIC_BRICK_OPS(generic);
};

#define GENERIC_OUTPUT_OPS(PREFIX)					\
	/*int (*output_start)(struct PREFIX##_output *output);*/	\
	/*int (*output_stop)(struct PREFIX##_output *output);*/		\
	int (*make_object_layout)(struct PREFIX##_output *output, struct generic_object_layout *object_layout); \
	
struct generic_output_ops {
	GENERIC_OUTPUT_OPS(generic)
};

// although possible, *_type should never be extended
#define GENERIC_BRICK_TYPE(PREFIX)					\
	char *type_name;						\
	int brick_size;							\
	int max_inputs;							\
	int max_outputs;						\
	const struct PREFIX##_input_type **default_input_types;		\
	char **default_input_names;					\
	const struct PREFIX##_output_type **default_output_types;	\
	char **default_output_names;					\
	struct PREFIX##_brick_ops *master_ops;				\
	const struct PREFIX##input_types **default_type;		\
	int (*brick_construct)(struct PREFIX##_brick *brick);		\
	int (*brick_destruct)(struct PREFIX##_brick *brick);		\

struct generic_brick_type {
	GENERIC_BRICK_TYPE(generic);
};

#define GENERIC_INPUT_TYPE(PREFIX)					\
	char *type_name;						\
	int input_size;							\
	int (*input_construct)(struct PREFIX##_input *input);		\
	int (*input_destruct)(struct PREFIX##_input *input);		\

struct generic_input_type {
	GENERIC_INPUT_TYPE(generic);
};

#define GENERIC_OUTPUT_TYPE(PREFIX)					\
	char *type_name;						\
	int output_size;						\
	struct PREFIX##_output_ops *master_ops;				\
	int (*output_construct)(struct PREFIX##_output *output);	\
	int (*output_destruct)(struct PREFIX##_output *output);		\
	const int *test[BRICK_OBJ_NR];					\

struct generic_output_type {
	GENERIC_OUTPUT_TYPE(generic);
};

int generic_register_brick_type(const struct generic_brick_type *new_type);
int generic_unregister_brick_type(const struct generic_brick_type *old_type);

#ifdef _STRATEGY // call this only in strategy bricks, never in ordinary bricks

// you need this only if you circumvent generic_brick_init_full()
extern inline int generic_brick_init(const struct generic_brick_type *type, struct generic_brick *brick, char *brick_name)
{
	brick->brick_name = brick_name;
	brick->type = type;
	brick->ops = type->master_ops;
	brick->nr_inputs = 0;
	brick->nr_outputs = 0;
	brick->tmp_head.next = brick->tmp_head.prev = &brick->tmp_head;
	return 0;
}

extern inline int generic_input_init(struct generic_brick *brick, int index, const struct generic_input_type *type, struct generic_input *input, char *input_name)
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

extern inline int generic_output_init(struct generic_brick *brick, int index, const struct generic_output_type *type, struct generic_output *output, char *output_name)
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

extern inline int generic_size(const struct generic_brick_type *brick_type)
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
	char **names);

int generic_brick_exit_full(
	struct generic_brick *brick);

extern inline int generic_connect(struct generic_input *input, struct generic_output *output)
{
	BRICK_DBG("generic_connect(input=%p, output=%p)\n", input, output);
	if (!input || !output)
		return -EINVAL;
	if (input->connect)
		return -EEXIST;
	input->connect = output;
	output->nr_connected++; //TODO: protect against races, e.g. atomic_t
	BRICK_DBG("now nr_connected=%d\n", output->nr_connected);
	return 0;
}

extern inline int generic_disconnect(struct generic_input *input)
{
	BRICK_DBG("generic_disconnect(input=%p)\n", input);
	if (!input)
		return -EINVAL;
	if (input->connect) {
		input->connect->nr_connected--; //TODO: protect against races, e.g. atomic_t
		BRICK_DBG("now nr_connected=%d\n", input->connect->nr_connected);
		input->connect = NULL;
	}
	return 0;
}

#endif // _STRATEGY

// simple wrappers for type safety
#define GENERIC_MAKE_FUNCTIONS(PREFIX)					\
extern inline int PREFIX##_register_brick_type(void)		        \
{									\
	extern const struct PREFIX##_brick_type PREFIX##_brick_type;	\
	extern int PREFIX##_brick_nr;					\
	if (PREFIX##_brick_nr >= 0) {					\
		BRICK_ERR("brick type " #PREFIX " is already registered.\n"); \
		return -EEXIST;						\
	}								\
	PREFIX##_brick_nr = generic_register_brick_type((const struct generic_brick_type*)&PREFIX##_brick_type); \
	return PREFIX##_brick_nr < 0 ? PREFIX##_brick_nr : 0;		\
}									\
									\
extern inline int PREFIX##_unregister_brick_type(void)		        \
{									\
	extern const struct PREFIX##_brick_type PREFIX##_brick_type;	\
	return generic_unregister_brick_type((const struct generic_brick_type*)&PREFIX##_brick_type); \
}									\
									\
_STRATEGY_CODE(							        \
extern const struct PREFIX##_brick_type PREFIX##_brick_type;	        \
extern const struct PREFIX##_input_type PREFIX##_input_type;		\
extern const struct PREFIX##_output_type PREFIX##_output_type;	        \
									\
static inline int PREFIX##_brick_init(struct PREFIX##_brick *brick, char *brick_name) \
{									\
	return generic_brick_init((const struct generic_brick_type*)&PREFIX##_brick_type, (struct generic_brick*)brick, brick_name); \
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
		(const struct generic_output_type*)&PREFIX##_output_type, \
		(struct generic_output*)output,				\
		output_name);						\
}									\
									\
extern inline int PREFIX##_size(const struct PREFIX##_brick_type *brick_type) \
{									\
	return generic_size((const struct generic_brick_type*)brick_type); \
}									\
									\
extern inline int PREFIX##_brick_init_full(			        \
	void *data,							\
	int size,							\
	const struct PREFIX##_brick_type *brick_type,			\
	const struct PREFIX##_input_type **input_types,			\
	const struct PREFIX##_output_type **output_types,		\
	char **names)							\
{									\
	return generic_brick_init_full(					\
		data,							\
		size,							\
		(const struct generic_brick_type*)brick_type,		\
		(const struct generic_input_type**)input_types,		\
		(const struct generic_output_type**)output_types,	\
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
 * (b) these macros generate only definitions, but no additional 
 * code at runtime.
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


#endif
