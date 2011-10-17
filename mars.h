// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_H
#define MARS_H

#include <linux/semaphore.h>
#include <linux/rwsem.h>

//#define MARS_TRACING // write runtime trace data to /mars/trace.csv

#define msleep msleep_interruptible

/////////////////////////////////////////////////////////////////////////

// include the generic brick infrastructure

#define OBJ_TYPE_MREF               0
#define OBJ_TYPE_MAX                1

#include "brick.h"
#include "brick_mem.h"

#define GFP_MARS GFP_BRICK

/////////////////////////////////////////////////////////////////////////

// MARS-specific debugging helpers

#define MARS_DELAY /**/
//#define MARS_DELAY msleep(20000)

#define MARS_FATAL   "MARS_FATAL  "
#define MARS_ERROR   "MARS_ERROR  "
#define MARS_WARNING "MARS_WARN   "
#define MARS_INFO    "MARS_INFO   "
#define MARS_DEBUG   "MARS_DEBUG  "

#define _MARS_FMT(_fmt) "[%s] " __BASE_FILE__ " %d %s(): " _fmt, current->comm, __LINE__, __FUNCTION__

#define _MARS_MSG(_stacktrace, PREFIX, _fmt, _args...) do { say(PREFIX _MARS_FMT(_fmt), ##_args); MARS_DELAY; if (_stacktrace) dump_stack(); } while (0)

#define MARS_FAT(_fmt, _args...) _MARS_MSG(true,  MARS_FATAL,   _fmt, ##_args)
#define MARS_ERR(_fmt, _args...) _MARS_MSG(true,  MARS_ERROR,   _fmt, ##_args)
#define MARS_WRN(_fmt, _args...) _MARS_MSG(false, MARS_WARNING, _fmt, ##_args)
#define MARS_INF(_fmt, _args...) _MARS_MSG(false, MARS_INFO,    _fmt, ##_args)

#ifdef MARS_DEBUGGING
#define MARS_DBG(_fmt, _args...) _MARS_MSG(false, MARS_DEBUG,   _fmt, ##_args)
#else
#define MARS_DBG(_args...) /**/
#endif

#ifdef IO_DEBUGGING
#define MARS_IO(_fmt, _args...)  _MARS_MSG(false, MARS_DEBUG,   _fmt, ##_args)
#else
#define MARS_IO(_args...) /*empty*/
#endif

#ifdef STAT_DEBUGGING
#define MARS_STAT MARS_INF
#else
#define MARS_STAT(_args...) /*empty*/
#endif

/////////////////////////////////////////////////////////////////////////

// MARS-specific definitions

#define MARS_PRIO_HIGH   -1
#define MARS_PRIO_NORMAL  0 // this is automatically used by memset()
#define MARS_PRIO_LOW     1
#define MARS_PRIO_NR      3

// object stuff

/* mref */

#define MREF_UPTODATE        1
#define MREF_READING         2
#define MREF_WRITING         4

extern const struct generic_object_type mref_type;

struct mref_aspect {
	GENERIC_ASPECT(mref);
};

struct mref_object_layout {
	GENERIC_OBJECT_LAYOUT(mref);
};

#ifdef MARS_TRACING

extern unsigned long long start_trace_clock;

#define MAX_TRACES 16

#define TRACING_INFO							\
	int ref_traces;							\
	unsigned long long   ref_trace_stamp[MAX_TRACES];		\
	const char          *ref_trace_info[MAX_TRACES];

extern void _mars_log(char *buf, int len);
extern void mars_log(const char *fmt, ...);
extern void mars_trace(struct mref_object *mref, const char *info);
extern void mars_log_trace(struct mref_object *mref);

#else
#define TRACING_INFO /*empty*/
#define _mars_log(buf,len) /*empty*/
#define mars_log(fmt...) /*empty*/
#define mars_trace(mref,info) /*empty*/
#define mars_log_trace(mref) /*empty*/
#endif

#define MREF_OBJECT(PREFIX)						\
	CALLBACK_OBJECT(PREFIX);					\
	/* supplied by caller */					\
	void  *ref_data;         /* preset to NULL for buffered IO */	\
	loff_t ref_pos;							\
	int    ref_len;							\
	int    ref_may_write;						\
	int    ref_prio;						\
	int    ref_timeout;						\
	/* maintained by the ref implementation, readable for callers */ \
	loff_t ref_total_size; /* just for info, need not be implemented */ \
	int    ref_flags;						\
	int    ref_rw;							\
	int    ref_id; /* not mandatory; may be used for identification */ \
	bool   ref_skip_sync; /* skip sync for this particular mref */	\
	/* maintained by the ref implementation, incrementable for	\
	 * callers (but not decrementable! use ref_put()) */		\
	atomic_t ref_count;						\
	/* internal */							\
	TRACING_INFO;

struct mref_object {
	MREF_OBJECT(mref);
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
	struct list_head global_brick_link;				\
	struct list_head dent_brick_link;				\
	const char *brick_path;						\
	struct mars_global *global;					\
	int brick_version;						\
	void (*show_status)(struct mars_brick *brick, bool shutdown);	\

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
	char *(*brick_statistics)(struct PREFIX##_brick *brick, int verbose); \
	void (*reset_statistics)(struct PREFIX##_brick *brick);		\
	
#define MARS_OUTPUT_OPS(PREFIX)						\
	GENERIC_OUTPUT_OPS(PREFIX);					\
	int  (*mars_get_info)(struct PREFIX##_output *output, struct mars_info *info); \
	/* mref */							\
	int  (*mref_get)(struct PREFIX##_output *output, struct mref_object *mref); \
	void (*mref_io)(struct PREFIX##_output *output, struct mref_object *mref); \
	void (*mref_put)(struct PREFIX##_output *output, struct mref_object *mref); \

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
GENERIC_ASPECT_FUNCTIONS(BRICK,mref);					\
extern int init_mars_##BRICK(void);					\
extern void exit_mars_##BRICK(void);


// instantiate a pseudo base-class "mars"

_MARS_TYPES(mars);
GENERIC_ASPECT_FUNCTIONS(mars,mref);

/////////////////////////////////////////////////////////////////////////

// MARS-specific helpers

#define MARS_MAKE_STATICS(BRICK)					\
									\
int BRICK##_brick_nr = -EEXIST;				                \
EXPORT_SYMBOL_GPL(BRICK##_brick_nr);			                \
									\
static const struct generic_aspect_type BRICK##_mref_aspect_type = {    \
	.aspect_type_name = #BRICK "_mref_aspect_type",			\
	.object_type = &mref_type,					\
	.aspect_size = sizeof(struct BRICK##_mref_aspect),		\
	.init_fn = BRICK##_mref_aspect_init_fn,				\
	.exit_fn = BRICK##_mref_aspect_exit_fn,				\
};									\
									\
static const struct generic_aspect_type *BRICK##_aspect_types[OBJ_TYPE_MAX] = {	\
	[OBJ_TYPE_MREF] = &BRICK##_mref_aspect_type,			\
};									\

extern const struct meta mars_info_meta[];
extern const struct meta mars_mref_meta[];
extern const struct meta mars_timespec_meta[];

/////////////////////////////////////////////////////////////////////////

#ifdef _STRATEGY
#include "sy_old/strategy.h"
#endif

extern void mars_power_led_on(struct generic_brick *brick, bool val);
extern void mars_power_led_off(struct generic_brick *brick, bool val);
/* this should disappear!
 */
extern void (*_mars_trigger)(void);
#define mars_trigger() do { MARS_INF("trigger...\n"); if (_mars_trigger) _mars_trigger(); } while (0)

/////////////////////////////////////////////////////////////////////////

/* Some special brick types for avoidance of cyclic references.
 *
 * The client/server network bricks use this for independent instantiation
 * from the main instantiation logic (separate modprobe for mars_server
 * is possible).
 */
extern const struct generic_brick_type *_client_brick_type;
extern const struct generic_brick_type *_bio_brick_type;
extern const struct generic_brick_type *_aio_brick_type;

/* Kludge: our kernel threads will have no mm context, but need one
 * for stuff like ioctx_alloc() / aio_setup_ring() etc
 * which expect userspace resources.
 * We fake one.
 * TODO: factor out the userspace stuff from AIO such that
 * this fake is no longer necessary.
 * Even better: replace do_mmap() in AIO stuff by something
 * more friendly to kernelspace apps.
 */
#include <linux/mmu_context.h>

extern struct mm_struct *mm_fake;

static inline void set_fake(void)
{
        mm_fake = current->mm;
        if (mm_fake) {
		MARS_INF("\n");
                atomic_inc(&current->usage);
                atomic_inc(&mm_fake->mm_count);
                atomic_inc(&mm_fake->mm_users);
        }
}

static inline void put_fake(void)
{
#if 0
        if (mm_fake) {
		MARS_INF("\n");
                atomic_dec(&mm_fake->mm_users);
                mmput(mm_fake);
                mm_fake = NULL;
        }
#endif
}

static inline void use_fake_mm(void)
{
	if (!current->mm && mm_fake) {
		MARS_INF("\n");
		use_mm(mm_fake);
	}
}

/* Cleanup faked mm, otherwise do_exit() will crash
 */
static inline void unuse_fake_mm(void)
{
	if (current->mm == mm_fake && mm_fake) {
		MARS_INF("\n");
		unuse_mm(mm_fake);
		//current->mm = NULL;
	}
}

/////////////////////////////////////////////////////////////////////////

// init

extern int init_mars(void);
extern void exit_mars(void);

#endif
