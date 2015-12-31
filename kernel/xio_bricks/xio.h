/*
 * MARS Long Distance Replication Software
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
 */

#ifndef XIO_H
#define XIO_H

#include <linux/semaphore.h>
#include <linux/rwsem.h>
#include <linux/major.h>

/*	remove_this */

/*  check the Kconfig environment */

#ifndef CONFIG_MARS_MODULE
/*  when unsure, include faked config file */
#include "mars_config.h"
#ifndef CONFIG_SMP
#warning CONFIG_SMP is not set -- are you SURE???
#endif
#endif

#ifndef CONFIG_64BIT
#error XIO is only tested under 64bit
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
#ifdef CONFIG_DEBUG_SLAB
#error Fixme: CONFIG_DEBUG_SLAB does not work (fix the bio offset calculation)
#endif
#ifdef CONFIG_DEBUG_SG
#error Fixme: CONFIG_DEBUG_SG does not work (fix the bio offset calculation)
#endif
/*	end_remove_this */
#if defined(CONFIG_CRYPTO_LZO) || defined(CONFIG_CRYPTO_LZO_MODULE)
#define __HAVE_LZO
#endif

#ifdef __enabled_CONFIG_CRYPTO_LZO
#if __enabled_CONFIG_CRYPTO_LZO
#define __HAVE_LZO
#endif
#endif

#ifdef __enabled_CONFIG_CRYPTO_LZO_MODULE
#if __enabled_CONFIG_CRYPTO_LZO_MODULE
#define __HAVE_LZO
#endif
#endif

/* TRANSITIONAL compatibility to BOTH the old prepatch
 * and the new wrapper around vfs_*(). Both will be replaced
 * for kernel upstream.
 */
#include "../vfs_compat.h"
#ifndef MARS_MAJOR
#define __USE_COMPAT
#endif

/***********************************************************************/

/*  include the generic brick infrastructure */

#define OBJ_TYPE_AIO			0
#define OBJ_TYPE_MAX			1

#include "brick.h"
#include "brick_mem.h"
#include "lamport.h"
#include "../lib/lib_timing.h"

/***********************************************************************/

/*  XIO-specific debugging helpers */

#define _XIO_MSG(_class, _dump, _fmt, _args...)				\
	brick_say(_class, _dump, "XIO", __BASE_FILE__, __LINE__, __func__, _fmt, ##_args)

#define XIO_FAT(_fmt, _args...) _XIO_MSG(SAY_FATAL, true,  _fmt, ##_args)
#define XIO_ERR(_fmt, _args...) _XIO_MSG(SAY_ERROR, false, _fmt, ##_args)
#define XIO_WRN(_fmt, _args...) _XIO_MSG(SAY_WARN,  false, _fmt, ##_args)
#define XIO_INF(_fmt, _args...) _XIO_MSG(SAY_INFO,  false, _fmt, ##_args)

#ifdef XIO_DEBUGGING
#define XIO_DBG(_fmt, _args...) _XIO_MSG(SAY_DEBUG, false, _fmt, ##_args)
#else
#define XIO_DBG(_args...) /**/
#endif

/***********************************************************************/

/*  XIO-specific definitions */

#define XIO_PRIO_HIGH			-1
#define XIO_PRIO_NORMAL			0 /*  this is automatically used by memset() */
#define XIO_PRIO_LOW			1
#define XIO_PRIO_NR			3

/*  object stuff */

/* aio */

#define AIO_UPTODATE			1
#define AIO_READING			2
#define AIO_WRITING			4

extern const struct generic_object_type aio_type;

#define XIO_CHECKSUM_SIZE		16

#define AIO_OBJECT(OBJTYPE)						\
	CALLBACK_OBJECT(OBJTYPE);					\
	/* supplied by caller */					\
	void  *io_data;  /* preset to NULL for buffered IO */		\
	loff_t io_pos;							\
	int    io_len;							\
	int    io_may_write;						\
	int    io_prio;							\
	int    io_timeout;						\
	int    io_cs_mode; /* 0 = off, 1 = checksum + data, 2 = checksum only */\
	/* maintained by the aio implementation, readable for callers */\
	loff_t io_total_size; /* just for info, need not be implemented */\
	unsigned char io_checksum[XIO_CHECKSUM_SIZE];			\
	int    io_flags;						\
	int    io_rw;							\
	int    io_id; /* not mandatory; may be used for identification */\
	bool   io_skip_sync; /* skip sync for this particular aio */	\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

struct aio_object {
	AIO_OBJECT(aio);
};

/*  internal helper structs */

struct xio_info {
	loff_t current_size;

	int tf_align;	 /*  transfer alignment constraint */
	int tf_min_size; /*  transfer is only possible in multiples of this */
};

/*  brick stuff */

#define XIO_BRICK(BRITYPE)						\
	GENERIC_BRICK(BRITYPE);						\
	struct generic_object_layout aio_object_layout;			\
	struct list_head global_brick_link;				\
	struct list_head dent_brick_link;				\
	const char *brick_name;						\
	const char *brick_path;						\
	void *private_ptr;						\
	void **kill_ptr;						\
	int *mode_ptr;							\
	int kill_round;							\
	bool killme;							\
	void (*show_status)(struct xio_brick *brick, bool shutdown);	\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

struct xio_brick {
	XIO_BRICK(xio);
};

#define XIO_INPUT(BRITYPE)						\
	GENERIC_INPUT(BRITYPE);						\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

struct xio_input {
	XIO_INPUT(xio);
};

#define XIO_OUTPUT(BRITYPE)						\
	GENERIC_OUTPUT(BRITYPE);					\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

struct xio_output {
	XIO_OUTPUT(xio);
};

#define XIO_BRICK_OPS(BRITYPE)						\
	GENERIC_BRICK_OPS(BRITYPE);					\
	char *(*brick_statistics)(struct BRITYPE##_brick *brick, int verbose);\
	void (*reset_statistics)(struct BRITYPE##_brick *brick);	\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

#define XIO_OUTPUT_OPS(BRITYPE)						\
	GENERIC_OUTPUT_OPS(BRITYPE);					\
	int  (*xio_get_info)(struct BRITYPE##_output *output, struct xio_info *info);\
	/* aio */							\
	int  (*aio_get)(struct BRITYPE##_output *output, struct aio_object *aio);\
	void (*aio_io)(struct BRITYPE##_output *output, struct aio_object *aio);\
	void (*aio_put)(struct BRITYPE##_output *output, struct aio_object *aio);\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

/*  all non-extendable types */

#define _XIO_TYPES(BRITYPE)						\
									\
struct BRITYPE##_brick_ops {						\
	XIO_BRICK_OPS(BRITYPE);						\
};									\
									\
struct BRITYPE##_output_ops {						\
	XIO_OUTPUT_OPS(BRITYPE);					\
};									\
									\
struct BRITYPE##_brick_type {						\
	GENERIC_BRICK_TYPE(BRITYPE);					\
};									\
									\
struct BRITYPE##_input_type {						\
	GENERIC_INPUT_TYPE(BRITYPE);					\
};									\
									\
struct BRITYPE##_output_type {						\
	GENERIC_OUTPUT_TYPE(BRITYPE);					\
};									\
									\
struct BRITYPE##_callback {						\
	GENERIC_CALLBACK(BRITYPE);					\
};									\
									\
DECLARE_BRICK_FUNCTIONS(BRITYPE);					\
/* this comment is for keeping TRAILING_SEMICOLON happy */

#define XIO_TYPES(BRITYPE)						\
									\
_XIO_TYPES(BRITYPE)							\
									\
DECLARE_ASPECT_FUNCTIONS(BRITYPE, aio);					\
extern int init_xio_##BRITYPE(void);					\
extern void exit_xio_##BRITYPE(void);					\
/* this comment is for keeping TRAILING_SEMICOLON happy */

/*  instantiate pseudo base-classes */

DECLARE_OBJECT_FUNCTIONS(aio);
_XIO_TYPES(xio);
DECLARE_ASPECT_FUNCTIONS(xio, aio);

/***********************************************************************/

/*  XIO-specific helpers */

#define XIO_MAKE_STATICS(BRITYPE)					\
									\
int BRITYPE##_brick_nr = -EEXIST;					\
									\
static const struct generic_aspect_type BRITYPE##_aio_aspect_type = {	\
	.aspect_type_name = #BRITYPE "_aio_aspect_type",		\
	.object_type = &aio_type,					\
	.aspect_size = sizeof(struct BRITYPE##_aio_aspect),		\
	.init_fn = BRITYPE##_aio_aspect_init_fn,			\
	.exit_fn = BRITYPE##_aio_aspect_exit_fn,			\
};									\
									\
static const struct generic_aspect_type *BRITYPE##_aspect_types[OBJ_TYPE_MAX] = {\
	[OBJ_TYPE_AIO] = &BRITYPE##_aio_aspect_type,			\
};									\
/* this comment is for keeping TRAILING_SEMICOLON happy */

extern const struct meta xio_info_meta[];
extern const struct meta xio_aio_user_meta[];
extern const struct meta xio_timespec_meta[];

/***********************************************************************/

/* Some minimal upcalls from generic IO layer to the strategy layer.
 * TODO: abstract away.
 */

extern void xio_set_power_on_led(struct xio_brick *brick, bool val);
extern void xio_set_power_off_led(struct xio_brick *brick, bool val);

/* this should disappear!
 */
extern void (*_local_trigger)(void);
extern void (*_remote_trigger)(void);
#define local_trigger() do { if (_local_trigger) { XIO_DBG("trigger...\n"); _local_trigger(); } } while (0)
#define remote_trigger()						\
do { if (_remote_trigger) { XIO_DBG("remote_trigger...\n"); _remote_trigger(); } } while (0)

/***********************************************************************/

/* Some global stuff.
 */

extern struct banning xio_global_ban;

extern atomic_t xio_global_io_flying;

extern int xio_throttle_start;
extern int xio_throttle_end;

/***********************************************************************/

/* Some special brick types for avoidance of cyclic references.
 *
 * The client/server network bricks use this for independent instantiation
 * from the main instantiation logic (separate modprobe for xio_server
 * is possible).
 */
extern const struct generic_brick_type *_client_brick_type;
extern const struct generic_brick_type *_bio_brick_type;
/*	remove_this */
#ifndef __USE_COMPAT
extern const struct generic_brick_type *_aio_brick_type;
#endif
/*	end_remove_this */
extern const struct generic_brick_type *_sio_brick_type;

/***********************************************************************/

/* Crypto stuff
 */

extern int xio_digest_size;
extern void xio_digest(unsigned char *digest, void *data, int len);
extern void aio_checksum(struct aio_object *aio);

/***********************************************************************/

/*  init */

extern int init_xio(void);
extern void exit_xio(void);

#endif
