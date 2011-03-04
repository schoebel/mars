// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_H
#define MARS_H

#include <linux/list.h>
#include <linux/semaphore.h>

#include <asm/spinlock.h>
#include <asm/atomic.h>

#define MARS_DELAY /**/
//#define MARS_DELAY msleep(20000)

#define MARS_FATAL "MARS_FATAL  "
#define MARS_ERROR "MARS_ERROR  "
#define MARS_INFO  "MARS_INFO   "
#define MARS_DEBUG "MARS_DEBUG  "
#define _MARS_FMT(fmt) "[%s] " __BASE_FILE__ " %d %s(): " fmt, current->comm, __LINE__, __FUNCTION__
//#define _MARS_FMT(fmt) _BRICK_FMT(fmt)

#define MARS_FAT(fmt, args...) do { printk(MARS_FATAL _MARS_FMT(fmt), ##args); MARS_DELAY; } while (0)
#define MARS_ERR(fmt, args...) do { printk(MARS_ERROR _MARS_FMT(fmt), ##args); MARS_DELAY; } while (0)
#define MARS_INF(fmt, args...) do { printk(MARS_INFO  _MARS_FMT(fmt), ##args); } while (0)
#ifdef MARS_DEBUGGING
#define MARS_DBG(fmt, args...) do { printk(MARS_DEBUG _MARS_FMT(fmt), ##args); } while (0)
#else
#define MARS_DBG(args...) /**/
#endif
#ifdef IO_DEBUGGING
#define MARS_IO MARS_DBG
#else
#define MARS_IO(args...) /*empty*/
#endif
#ifdef STAT_DEBUGGING
#define MARS_STAT MARS_INF
#else
#define MARS_IO(args...) /*empty*/
#endif

#define BRICK_OBJ_MREF            0
#define BRICK_OBJ_NR                  1

#define GFP_MARS GFP_NOIO

#include "brick.h"

/////////////////////////////////////////////////////////////////////////

// MARS-specific definitions

// object stuff

/* mref */

#define MREF_UPTODATE        1
#define MREF_READING         2
#define MREF_WRITING         4

extern const struct generic_object_type mref_type;

struct mref_aspect {
	GENERIC_ASPECT(mref);
};

struct mref_aspect_layout {
	GENERIC_ASPECT_LAYOUT(mref);
};

struct mref_object_layout {
	GENERIC_OBJECT_LAYOUT(mref);
};

#define MREF_OBJECT(PREFIX)						\
	GENERIC_OBJECT(PREFIX);						\
	/* supplied by caller */					\
	loff_t ref_pos;							\
	int    ref_len;							\
	int    ref_may_write;						\
	void  *ref_data;         /* preset to NULL for buffered IO */	\
	/* maintained by the ref implementation, readable for callers */ \
	int    ref_flags;						\
	int    ref_rw;							\
	int    ref_id; /* not mandatory; may be used for identification */ \
	/* maintained by the ref implementation, incrementable for	\
	 * callers (but not decrementable! use ref_put()) */		\
	atomic_t ref_count;						\
        /* callback part */						\
	struct generic_callback *ref_cb;				\
	struct generic_callback _ref_cb;				\

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
	int status_level;						\

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
GENERIC_OBJECT_LAYOUT_FUNCTIONS(BRICK);				        \
GENERIC_ASPECT_LAYOUT_FUNCTIONS(BRICK,mref);				\
GENERIC_ASPECT_FUNCTIONS(BRICK,mref);					\


// instantiate all mars-specific functions

GENERIC_OBJECT_FUNCTIONS(mref);

// instantiate a pseudo base-class "mars"

_MARS_TYPES(mars);
GENERIC_OBJECT_LAYOUT_FUNCTIONS(mars);
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
static const struct generic_aspect_type *BRICK##_aspect_types[BRICK_OBJ_NR] = {	\
	[BRICK_OBJ_MREF] = &BRICK##_mref_aspect_type,			\
};									\

#define _CHECK_ATOMIC(atom,OP,minval)					\
	do {								\
		int test = atomic_read(atom);				\
		if (test OP (minval)) {					\
			atomic_set(atom, minval);			\
			MARS_ERR("%d: atomic " #atom " " #OP " " #minval " (%d)\n", __LINE__, test); \
		}							\
	} while (0)

#define CHECK_ATOMIC(atom,minval)			\
	_CHECK_ATOMIC(atom, <, minval)

#define CHECK_HEAD_EMPTY(head)						\
	if (unlikely(!list_empty(head))) {				\
		INIT_LIST_HEAD(head);					\
		MARS_ERR("%d: list_head " #head " (%p) not empty\n", __LINE__, head); \
	}								\

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

extern const struct meta mars_info_meta[];
extern const struct meta mars_mref_meta[];

/////////////////////////////////////////////////////////////////////////

extern struct mars_global *mars_global;

extern void mars_trigger(void);
extern int  mars_power_button(struct mars_brick *brick, bool val);
extern void mars_power_led_on(struct mars_brick *brick, bool val);
extern void mars_power_led_off(struct mars_brick *brick, bool val);

extern int  mars_power_button_recursive(struct mars_brick *brick, bool val, int timeout);

/////////////////////////////////////////////////////////////////////////

#ifdef _STRATEGY // call this only in strategy bricks, never in ordinary bricks

#define MARS_ARGV_MAX 4
#define MARS_PATH_MAX 128

extern char *my_id(void);

#define MARS_DENT(TYPE)							\
	struct list_head dent_link;					\
	struct list_head brick_list;					\
	struct TYPE *d_parent;						\
	char *d_argv[MARS_ARGV_MAX];  /* for internal use, will be automatically deallocated*/ \
	char *d_args; /* ditto uninterpreted */				\
	char *d_name; /* current path component */			\
	char *d_rest; /* some "meaningful" rest of d_name*/		\
	char *d_path; /* full absolute path */				\
	int   d_namelen;						\
	int   d_pathlen;						\
	int   d_depth;							\
	unsigned int d_type; /* from readdir() => often DT_UNKNOWN => don't rely on it, use new_stat.mode instead */ \
	int   d_class;    /* for pre-grouping order */			\
	int   d_serial;   /* for pre-grouping order */			\
	int   d_version;  /* dynamic programming per call of mars_ent_work() */ \
	bool d_activate;  /* tells whether activation should start */	\
	bool d_kill_inactive; /* whether !d_activate should kill operation  */	\
	char d_once_error;						\
	struct kstat new_stat;						\
	struct kstat old_stat;						\
	char *new_link;							\
	char *old_link;							\
	struct mars_global *d_global;					\
	void *d_private;

struct mars_dent {
	MARS_DENT(mars_dent);
};

extern const struct meta mars_timespec_meta[];
extern const struct meta mars_kstat_meta[];
extern const struct meta mars_dent_meta[];

struct mars_global {
	struct semaphore mutex;
	struct generic_switch global_power;
	struct list_head dent_anchor;
	struct list_head brick_anchor;
	volatile bool main_trigger;
	wait_queue_head_t main_event;
	//void *private;
};

typedef int (*mars_dent_checker)(const char *path, const char *name, int namlen, unsigned int d_type, int *prefix, int *serial);
typedef int (*mars_dent_worker)(struct mars_global *global, struct mars_dent *dent, bool direction);

extern int mars_dent_work(struct mars_global *global, char *dirname, int allocsize, mars_dent_checker checker, mars_dent_worker worker, void *buf, int maxdepth);
extern struct mars_dent *_mars_find_dent(struct mars_global *global, const char *path);
extern struct mars_dent *mars_find_dent(struct mars_global *global, const char *path);
extern void mars_kill_dent(struct mars_dent *dent);
extern void mars_free_dent(struct mars_dent *dent);
extern void mars_free_dent_all(struct list_head *anchor);

// low-level brick instantiation

extern struct mars_brick *mars_find_brick(struct mars_global *global, const void *brick_type, const char *path);
extern struct mars_brick *mars_make_brick(struct mars_global *global, struct mars_dent *belongs, const void *_brick_type, const char *path, const char *name);
extern int mars_free_brick(struct mars_brick *brick);
extern int mars_kill_brick(struct mars_brick *brick);

// mid-level brick instantiation (identity is based on path strings)

extern char *vpath_make(const char *fmt, va_list *args);
extern char *path_make(const char *fmt, ...);

extern struct mars_brick *path_find_brick(struct mars_global *global, const void *brick_type, const char *fmt, ...);

/* Create a new brick and connect its inputs to a set of predecessors.
 * When @timeout > 0, switch on the brick as well as its predecessors.
 */
extern struct mars_brick *make_brick_all(
	struct mars_global *global,
	struct mars_dent *belongs,
	int timeout,
	const char *new_name,
	const struct generic_brick_type *new_brick_type,
	const struct generic_brick_type *prev_brick_type[],
	const char *new_fmt,
	const char *prev_fmt[],
	int prev_count,
	...
	);

// general MARS infrastructure

#define MARS_ERR_ONCE(dent, args...) if (!dent->d_once_error++) MARS_ERR(args)

/* General fs wrappers (for abstraction)
 */
extern int mars_lstat(const char *path, struct kstat *stat);
extern int mars_mkdir(const char *path);
extern int mars_symlink(const char *oldpath, const char *newpath, const struct timespec *stamp, uid_t uid);
extern int mars_rename(const char *oldpath, const char *newpath);
extern int mars_chmod(const char *path, mode_t mode);
extern int mars_lchown(const char *path, uid_t uid);

#endif // _STRATEGY

/* Some special brick types for avoidance of cyclic references.
 *
 * The client/server network bricks use this for independent instantiation
 * from the main instantiation logic (separate modprobe for mars_server
 * is possible).
 */
extern const struct generic_brick_type *_client_brick_type;
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

inline void set_fake(void)
{
	mm_fake = current->mm;
	if (mm_fake) {
		atomic_inc(&mm_fake->mm_count);
		atomic_inc(&mm_fake->mm_users);
	}
}

inline void put_fake(void)
{
	if (mm_fake) {
		atomic_dec(&mm_fake->mm_users);
		mmput(mm_fake);
		mm_fake = NULL;
	}
}

inline struct mm_struct *fake_mm(void)
{
#if 0
	if (!current->mm) {
		// will be never released.... ;)
		atomic_inc(&(current->mm = &init_mm)->mm_count);
	}
	return NULL;
#else
	struct mm_struct *old = current->mm;
	use_mm(mm_fake);
	return old;
#endif
}
/* Cleanup faked mm, otherwise do_exit() will crash
 */
inline void cleanup_mm(struct mm_struct *old)
{
#if 0
	if (current->mm == &init_mm) {
		current->mm = NULL;
	}
#else
	unuse_mm(old);
#endif
#if 1
	for (;;) msleep(1000);
#endif
}

#endif
