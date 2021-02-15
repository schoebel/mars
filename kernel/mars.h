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

#ifndef MARS_H
#define MARS_H

/* TRANSITIONAL compatibility to BOTH the old prepatch
 * and the new wrapper around vfs_*(). Both will be replaced
 * for kernel upstream.
 */
#include "compat.h"

#include <linux/semaphore.h>
#include <linux/rwsem.h>
#include <linux/major.h>

//#define MARS_TRACING // write runtime trace data to /mars/trace.csv

// check the Kconfig environment

#ifndef CONFIG_MARS_MODULE
// when unsure, include faked config file
#include "mars_config.h"
#ifndef CONFIG_SMP
#warning CONFIG_SMP is not set -- are you SURE???
#endif
#endif

#ifndef CONFIG_64BIT
#error MARS is only tested under 64bit
#endif
#ifndef CONFIG_BLOCK
#error CONFIG_BLOCK must be set
#endif
#ifndef CONFIG_PROC_SYSCTL
#error CONFIG_PROC_SYSCTL must be set
#endif
#ifndef CONFIG_HIGH_RES_TIMERS
#error CONFIG_HIGH_RES_TIMERS must be set
#endif

/////////////////////////////////////////////////////////////////////////

// include the generic brick infrastructure

#define OBJ_TYPE_MREF               0
#define OBJ_TYPE_MAX                1

#include "brick.h"
#include "brick_mem.h"
#include "brick_atomic.h"
#include "lamport.h"
#include "lib_timing.h"

#define GFP_MARS GFP_BRICK

/////////////////////////////////////////////////////////////////////////

// MARS-specific debugging helpers

#define _MARS_MSG(_class, _dump, _fmt, _args...)		\
	brick_say(_class, _dump, "MARS", __BASE_FILE__, __LINE__, __FUNCTION__, _fmt, ##_args)

#define MARS_FAT(_fmt, _args...) _MARS_MSG(SAY_FATAL, true,  _fmt, ##_args)
#define MARS_ERR(_fmt, _args...) _MARS_MSG(SAY_ERROR, false, _fmt, ##_args)
#define MARS_WRN(_fmt, _args...) _MARS_MSG(SAY_WARN,  false, _fmt, ##_args)
#define MARS_INF(_fmt, _args...) _MARS_MSG(SAY_INFO,  false, _fmt, ##_args)

#ifdef MARS_DEBUGGING
#define MARS_DBG(_fmt, _args...) _MARS_MSG(SAY_DEBUG, false, _fmt, ##_args)
#else
#define MARS_DBG(_args...) /**/
#endif

#ifdef IO_DEBUGGING
#define MARS_IO(_fmt, _args...)  _MARS_MSG(SAY_DEBUG, false, _fmt, ##_args)
#else
#define MARS_IO(_args...) /*empty*/
#endif

#ifdef STAT_DEBUGGING
#ifdef MARS_DEBUGGING
# define MARS_STAT MARS_DBG
#else
# define MARS_STAT MARS_INF
#endif
#else
#define MARS_STAT(_args...) /*empty*/
#endif

/////////////////////////////////////////////////////////////////////////

// MARS-specific definitions

/* This _should_ be updated when _compatible_ features
 * are added. When somebody may _rely_ on the new feature,
 * then this _must_ be updated.
 */
#define OPTIONAL_FEATURES_VERSION 4

/* for stringification */
#define _stringify(s) #s
#define stringify(s) _stringify(s)

extern int usable_features_version;

#define OLD_MARS_DIGEST_SIZE 16
#define MARS_DIGEST_SIZE     32

#define MARS_PRIO_HIGH   -1
#define MARS_PRIO_NORMAL  0 // this is automatically used by memset()
#define MARS_PRIO_LOW     1
#define MARS_PRIO_NR      3

// object stuff

/* mref */

extern const struct generic_object_type mref_type;

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

enum _MREF_FLAGS {
	/* New flags must always be appended */
	/* Never change the position of an existing flag */
	_MREF_UPTODATE,
	_MREF_READING,
	_MREF_WRITING,
	_MREF_WRITE,
	_MREF_MAY_WRITE,
	_MREF_SKIP_SYNC,
	_MREF_NODATA, /* only useful for chksum reading */
	/* Checksum bits, starting at the upper half */
	_MREF_CHKSUM_MD5_OLD = 16,
	_MREF_CHKSUM_MD5,
	_MREF_CHKSUM_CRC32C,
	_MREF_CHKSUM_CRC32,
	_MREF_CHKSUM_SHA1,
	_MREF_CHKSUM_LAST,
	_MREF_COMPRESS_LZO = 24,
	_MREF_COMPRESS_LZ4,
	_MREF_COMPRESS_ZLIB,
	_MREF_COMPRESS_LAST,
};

#define MREF_UPTODATE        (1UL << _MREF_UPTODATE)
#define MREF_READING         (1UL << _MREF_READING)
#define MREF_WRITING         (1UL << _MREF_WRITING)
#define MREF_WRITE           (1UL << _MREF_WRITE)
#define MREF_MAY_WRITE       (1UL << _MREF_MAY_WRITE)
#define MREF_SKIP_SYNC       (1UL << _MREF_SKIP_SYNC)
#define MREF_NODATA          (1UL << _MREF_NODATA)
#define MREF_CHKSUM_MD5_OLD  (1UL << _MREF_CHKSUM_MD5_OLD)
#define MREF_CHKSUM_MD5      (1UL << _MREF_CHKSUM_MD5)
#define MREF_CHKSUM_CRC32C   (1UL << _MREF_CHKSUM_CRC32C)
#define MREF_CHKSUM_CRC32    (1UL << _MREF_CHKSUM_CRC32)
#define MREF_CHKSUM_SHA1     (1UL << _MREF_CHKSUM_SHA1)
#define MREF_CHKSUM_LAST     (1UL << _MREF_CHKSUM_LAST)
#define MREF_COMPRESS_LZO    (1UL << _MREF_COMPRESS_LZO)
#define MREF_COMPRESS_LZ4    (1UL << _MREF_COMPRESS_LZ4)
#define MREF_COMPRESS_ZLIB   (1UL << _MREF_COMPRESS_ZLIB)
#define MREF_CHKSUM_ANY      (MREF_CHKSUM_MD5_OLD |	\
			      MREF_CHKSUM_MD5 |		\
			      MREF_CHKSUM_CRC32C |	\
			      MREF_CHKSUM_CRC32 |	\
			      MREF_CHKSUM_SHA1 |	\
			      MREF_CHKSUM_LAST)
#define MREF_COMPRESS_ANY     (MREF_COMPRESS_LZO |	\
			       MREF_COMPRESS_LZ4 |	\
			       MREF_COMPRESS_ZLIB)

#define MREF_OBJECT(OBJTYPE)						\
	CALLBACK_OBJECT(OBJTYPE);					\
	/* supplied by caller */					\
	void  *ref_data;         /* preset to NULL for buffered IO */	\
	loff_t ref_pos;							\
	int    ref_len;							\
	int    ref_prio;						\
	int    ref_timeout;						\
	/* shared */							\
	__u32  ref_flags;						\
	/* maintained by the ref implementation, readable for callers */ \
	loff_t ref_total_size; /* just for info, need not be implemented */ \
	unsigned char ref_checksum[MARS_DIGEST_SIZE];			\
	int    ref_id; /* not mandatory; may be used for identification */ \
	/* maintained by the ref implementation, incrementable for	\
	 * callers (but not decrementable! use ref_put()) */		\
	tatomic_t ref_count;						\
	/* deprecated, to be removed in future */			\
	int    ref_rw;							\
	int    ref_may_write;						\
	bool   ref_skip_sync; /* skip sync for this particular mref */	\
	int    ref_cs_mode; /* 0 = off, 1 = checksum + data, 2 = checksum only */ \
	/* internal */							\
	atomic_trace_t ref_at;						\
	bool   ref_initialized; /* internally used for checking */	\
	TRACING_INFO;

struct mref_object {
	MREF_OBJECT(mref);
};

#define _mref_check(mref)						\
	({								\
		if (unlikely(BRICK_CHECKING && !(mref)->ref_initialized)) { \
			MARS_ERR("mref %p is not initialized\n", (mref)); \
		}							\
		CHECK_TATOMIC(&(mref)->ref_at, &(mref)->ref_count, 1);	\
	})

#define _mref_get_first(mref)						\
	({								\
		if (unlikely(BRICK_CHECKING && (mref)->ref_initialized)) { \
			MARS_ERR("mref %p is already initialized\n", (mref)); \
		}							\
		_CHECK_TATOMIC(&(mref)->ref_at, &(mref)->ref_count, !=, 0, 0); \
		(mref)->ref_initialized = true;				\
		tatomic_inc(&(mref)->ref_at, &(mref)->ref_count);	\
	})

#define _mref_get(mref)							\
	({								\
		_mref_check(mref);					\
		tatomic_inc(&(mref)->ref_at, &(mref)->ref_count);	\
	})

#define _mref_put(mref)							\
	({								\
		_mref_check(mref);					\
		tatomic_dec_and_test(&(mref)->ref_at, &(mref)->ref_count); \
	})

// internal helper structs

/* Abstract state of a location-transparent store / LV.
 * Only test for equality is possible.
 * stor_id must not depend on the location.
 * stor_hash must change at any write completion (modulo 64bit hashing)
 * using a location-independent hash function.
 * stor_dirty indicates that the hash cannot be trusted (such as
 * currently flying IO requests etc).
 */
struct stor_state {
	struct lamport_time stor_stamp;
	__u64               stor_id;
	__u64               stor_hash;
	bool                stor_dirty;
};

extern void default_stor_init(struct stor_state *ini, const char *name);

struct mars_info {
	loff_t current_size;
	int tf_align;    // transfer alignment constraint
	int tf_min_size; // transfer is only possible in multiples of this
	struct stor_state stor_state;
};

// brick stuff

#define MARS_BRICK(BRITYPE)						\
	GENERIC_BRICK(BRITYPE);						\
	struct generic_object_layout mref_object_layout;		\
	struct list_head global_brick_link;				\
	struct list_head dent_brick_link;				\
	const char *resource_name;					\
	const char *brick_path;						\
	struct mars_global *global;					\
	struct lamport_time create_stamp;				\
	struct lamport_time kill_stamp;					\
	void **kill_ptr;						\
	int *mode_ptr;							\
	int kill_round;							\
	bool killme;							\
	bool rewire;							\

struct mars_brick {
	MARS_BRICK(mars);
};

#define MARS_INPUT(BRITYPE)						\
	GENERIC_INPUT(BRITYPE);						\

struct mars_input {
	MARS_INPUT(mars);
};

#define MARS_OUTPUT(BRITYPE)						\
	GENERIC_OUTPUT(BRITYPE);					\

struct mars_output {
	MARS_OUTPUT(mars);
};

#define MARS_BRICK_OPS(BRITYPE)						\
	GENERIC_BRICK_OPS(BRITYPE);					\
	char *(*brick_statistics)(struct BRITYPE##_brick *brick, int verbose); \
	void (*reset_statistics)(struct BRITYPE##_brick *brick);	\
	
#define MARS_OUTPUT_OPS(BRITYPE)					\
	GENERIC_OUTPUT_OPS(BRITYPE);					\
	int  (*mars_get_info)(struct BRITYPE##_output *output, struct mars_info *info); \
	/* mref */							\
	int  (*mref_get)(struct BRITYPE##_output *output, struct mref_object *mref); \
	void (*mref_io)(struct BRITYPE##_output *output, struct mref_object *mref); \
	void (*mref_put)(struct BRITYPE##_output *output, struct mref_object *mref); \

// all non-extendable types

#define _MARS_TYPES(BRITYPE)						\
									\
struct BRITYPE##_brick_ops {					        \
        MARS_BRICK_OPS(BRITYPE);					\
};                                                                      \
                                                                        \
struct BRITYPE##_output_ops {					        \
	MARS_OUTPUT_OPS(BRITYPE);					\
};                                                                      \
									\
struct BRITYPE##_brick_type {                                           \
	GENERIC_BRICK_TYPE(BRITYPE);					\
};									\
									\
struct BRITYPE##_input_type {					        \
	GENERIC_INPUT_TYPE(BRITYPE);					\
};									\
									\
struct BRITYPE##_output_type {					        \
	GENERIC_OUTPUT_TYPE(BRITYPE);					\
};									\
									\
struct BRITYPE##_callback {					        \
	GENERIC_CALLBACK(BRITYPE);					\
};									\
									\
DECLARE_BRICK_FUNCTIONS(BRITYPE);				        \


#define MARS_TYPES(BRITYPE)						\
									\
_MARS_TYPES(BRITYPE)						        \
									\
DECLARE_ASPECT_FUNCTIONS(BRITYPE,mref);					\
extern int init_mars_##BRITYPE(void);					\
extern void exit_mars_##BRITYPE(void);


// instantiate a pseudo base-class "mars"

_MARS_TYPES(mars);
DECLARE_ASPECT_FUNCTIONS(mars,mref);

/////////////////////////////////////////////////////////////////////////

// MARS-specific helpers

#define MARS_MAKE_STATICS(BRITYPE)					\
									\
int BRITYPE##_brick_nr = -EEXIST;				        \
EXPORT_SYMBOL_GPL(BRITYPE##_brick_nr);			                \
									\
static const struct generic_aspect_type BRITYPE##_mref_aspect_type = {  \
	.aspect_type_name = #BRITYPE "_mref_aspect_type",		\
	.object_type = &mref_type,					\
	.aspect_size = sizeof(struct BRITYPE##_mref_aspect),		\
	.init_fn = BRITYPE##_mref_aspect_init_fn,			\
	.exit_fn = BRITYPE##_mref_aspect_exit_fn,			\
};									\
									\
static const struct generic_aspect_type *BRITYPE##_aspect_types[OBJ_TYPE_MAX] = {	\
	[OBJ_TYPE_MREF] = &BRITYPE##_mref_aspect_type,			\
};									\

extern const struct meta stor_state_meta[];
extern const struct meta mars_info_meta[];
extern const struct meta mars_mref_meta[];
extern const struct meta mars_lamport_time_meta[];

/////////////////////////////////////////////////////////////////////////

#ifdef _STRATEGY
#include "sy_old/strategy.h"
#endif

extern void mars_power_led_on(struct mars_brick *brick, bool val);
extern void mars_power_led_off(struct mars_brick *brick, bool val);

/* this should disappear!
 */
enum mars_trigger_mode {
	_MARS_TRIGGER_LOCAL,
	_MARS_TRIGGER_FROM_REMOTE,
	_MARS_TRIGGER_TO_REMOTE,
	_MARS_TRIGGER_TO_REMOTE_ALL,
	_MARS_TRIGGER_FULL,
};

#define MARS_TRIGGER_LOCAL         (1 << _MARS_TRIGGER_LOCAL)
#define MARS_TRIGGER_FROM_REMOTE   (1 << _MARS_TRIGGER_FROM_REMOTE)
#define MARS_TRIGGER_TO_REMOTE     (1 << _MARS_TRIGGER_TO_REMOTE)
#define MARS_TRIGGER_TO_REMOTE_ALL (1 << _MARS_TRIGGER_TO_REMOTE_ALL)
#define MARS_TRIGGER_FULL          (1 << _MARS_TRIGGER_FULL)

void mars_remote_trigger(int code);

void __mars_trigger(int code);
#define mars_trigger()							\
	__mars_trigger(MARS_TRIGGER_LOCAL)

/////////////////////////////////////////////////////////////////////////

/* Some global stuff.
 */

extern struct banning mars_global_ban;

extern atomic_t mars_global_io_flying;

extern int mars_throttle_start;
extern int mars_throttle_end;

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
extern const struct generic_brick_type *_sio_brick_type;

#if !defined(CONFIG_MARS_PREFER_SIO) && (defined(MARS_HAS_PREPATCH) || defined(MARS_HAS_PREPATCH_V2))
#define ENABLE_MARS_AIO
#endif

#ifdef ENABLE_MARS_AIO
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
extern struct task_struct *mm_fake_task;
extern atomic_t mm_fake_count;

static inline void set_fake(void)
{
        mm_fake = current->mm;
        if (mm_fake) {
		MARS_DBG("initialized fake\n");
		mm_fake_task = current;
		get_task_struct(current); // paired with put_task_struct()
                atomic_inc(&mm_fake->mm_count); // paired with mmdrop()
                atomic_inc(&mm_fake->mm_users); // paired with mmput()
        }
}

static inline void put_fake(void)
{
        if (mm_fake && mm_fake_task) {
		int remain = atomic_read(&mm_fake_count);
		if (unlikely(remain != 0)) {
			MARS_ERR("cannot cleanup fake, remain = %d\n", remain);
		} else {
			MARS_DBG("cleaning up fake\n");
			mmput(mm_fake);
			mmdrop(mm_fake);
			mm_fake = NULL;
			put_task_struct(mm_fake_task);
			mm_fake_task = NULL;
		}
        }
}

static inline void use_fake_mm(void)
{
	if (!current->mm && mm_fake) {
		atomic_inc(&mm_fake_count);
		MARS_DBG("using fake, count=%d\n", atomic_read(&mm_fake_count));
		use_mm(mm_fake);
	}
}

/* Cleanup faked mm, otherwise do_exit() will crash
 */
static inline void unuse_fake_mm(void)
{
	if (current->mm == mm_fake && mm_fake) {
		MARS_DBG("unusing fake, count=%d\n", atomic_read(&mm_fake_count));
		atomic_dec(&mm_fake_count);
		unuse_mm(mm_fake);
		current->mm = NULL;
	}
}

#else
static inline void set_fake(void) {}
static inline void put_fake(void) {}
static inline void use_fake_mm(void) {}
static inline void unuse_fake_mm(void) {}
#endif

/////////////////////////////////////////////////////////////////////////

/* Crypto / digest stuff
 */

#define MARS_MAX_COMPR_SIZE (PAGE_SIZE * 8)

extern __u32 available_digest_mask;
extern __u32 usable_digest_mask;
extern __u32 used_log_digest;
extern __u32 used_net_digest;

extern __u32 disabled_log_digests;
extern __u32 disabled_net_digests;

extern __u32 mars_digest(__u32 digest_flags,
			 __u32 *used_flags,
			 void *digest,
			 const void *data, int len);

extern void mref_checksum(struct mref_object *mref);

/*******************************************************************/

/* compression stuff */

#define MARS_MAX_COMPR_SIZE (PAGE_SIZE * 8)

extern int compress_overhead;

extern __u32 available_compression_mask;
extern __u32 usable_compression_mask;

extern int mars_zlib_compression_level;

extern int mars_compress(void *src_data,
			 int src_len,
			 void *dst_data,
			 int dst_len,
			 __u32 check_flags,
			 __u32 *result_flags);

void *mars_decompress(void *src_data,
		      int src_len,
		      void *dst_data,
		      int dst_len,
		      __u32 check_flags);

/////////////////////////////////////////////////////////////////////////

/* Crash-testing instrumentation.
 * Only for debugging. Never use this for production.
 * Simulate a crash at the "wrong moment".
 */

#ifdef CONFIG_MARS_DEBUG
extern int mars_crash_mode;
extern int mars_hang_mode;
extern void _crashme(int mode, bool do_sync);
#else
extern inline void _crashme(int mode, bool do_sync) {}
#endif

/////////////////////////////////////////////////////////////////////////

// init

extern int init_mars(void);
extern void exit_mars(void);

#endif
