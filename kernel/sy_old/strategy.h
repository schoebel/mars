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

// OLD CODE => will disappear!
#ifndef _OLD_STRATEGY
#define _OLD_STRATEGY

#define _STRATEGY // call this only in strategy bricks, never in ordinary bricks

#include "../mars.h"

//      remove_this
#ifdef KUIDT_INIT
#define HAS_KUID
#else
#define __kuid_val(x) (x)
#define __kgid_val(x) (x)
#endif

//      end_remove_this
#define MARS_ARGV_MAX 4

extern loff_t global_total_space;
extern loff_t global_remaining_space;

extern int global_logrot_auto;
extern int global_free_space_0;
extern int global_free_space_1;
extern int global_free_space_2;
extern int global_free_space_3;
extern int global_free_space_4;
extern int global_sync_want;
extern int global_sync_nr;
extern int global_sync_limit;
extern int mars_rollover_interval;
extern int mars_scan_interval;
extern int mars_propagate_interval;
extern int mars_sync_flip_interval;
extern int mars_peer_abort;
extern int mars_emergency_mode;
extern int mars_reset_emergency;
extern int mars_keep_msg;

extern int mars_fast_fullsync;

#define MARS_DENT(TYPE)							\
	struct list_head dent_link;					\
	struct list_head brick_list;					\
	struct TYPE *d_parent;						\
	char *d_argv[MARS_ARGV_MAX];  /* for internal use, will be automatically deallocated*/ \
	char *d_args; /* ditto uninterpreted */				\
	char *d_name; /* current path component */			\
	char *d_rest; /* some "meaningful" rest of d_name*/		\
	char *d_path; /* full absolute path */				\
	struct say_channel *d_say_channel; /* for messages */		\
	loff_t d_corr_A; /* logical size correction */			\
	loff_t d_corr_B; /* logical size correction */			\
	int   d_depth;							\
	unsigned int d_type; /* from readdir() => often DT_UNKNOWN => don't rely on it, use new_stat.mode instead */ \
	int   d_class;    /* for pre-grouping order */			\
	int   d_serial;   /* for pre-grouping order */			\
	int   d_version;  /* dynamic programming per call of mars_ent_work() */ \
	int   d_child_count;						\
	bool d_killme;							\
	bool d_use_channel;						\
	struct kstat new_stat;						\
	char *new_link;							\
	struct mars_global *d_global;					\
	void (*d_private_destruct)(void *private);			\
	void *d_private;						\
	/* this comment is for keeping TRAILING_SEMICOLON happy */

struct mars_dent {
	MARS_DENT(mars_dent);
};

extern const struct meta mars_kstat_meta[];
extern const struct meta mars_dent_meta[];

struct mars_global {
	struct rw_semaphore dent_mutex;
	struct rw_semaphore brick_mutex;
	struct generic_switch global_power;
	struct list_head dent_anchor;
	struct list_head brick_anchor;
	wait_queue_head_t main_event;
	int global_version;
	int deleted_my_border;
	int deleted_border;
	int deleted_min;
	bool main_trigger;
};

extern void bind_to_dent(struct mars_dent *dent, struct say_channel **ch);

typedef int (*mars_dent_checker_fn)(struct mars_dent *parent, const char *name, int namlen, unsigned int d_type, int *prefix, int *serial, bool *use_channel);
typedef int (*mars_dent_worker_fn)(struct mars_global *global, struct mars_dent *dent, bool prepare, bool direction);

extern int mars_dent_work(struct mars_global *global, char *dirname, int allocsize, mars_dent_checker_fn checker, mars_dent_worker_fn worker, void *buf, int maxdepth);
extern struct mars_dent *_mars_find_dent(struct mars_global *global, const char *path);
extern struct mars_dent *mars_find_dent(struct mars_global *global, const char *path);
extern int mars_find_dent_all(struct mars_global *global, char *prefix, struct mars_dent ***table);
extern void mars_kill_dent(struct mars_dent *dent);
extern void mars_free_dent(struct mars_dent *dent);
extern void mars_free_dent_all(struct mars_global *global, struct list_head *anchor);

// low-level brick instantiation

extern struct mars_brick *mars_find_brick(struct mars_global *global, const void *brick_type, const char *path);
extern struct mars_brick *mars_make_brick(struct mars_global *global, struct mars_dent *belongs, const void *_brick_type, const char *path, const char *name);
extern int mars_free_brick(struct mars_brick *brick);
extern int mars_kill_brick(struct mars_brick *brick);
extern int mars_kill_brick_all(struct mars_global *global, struct list_head *anchor, bool use_dent_link);
extern int mars_kill_brick_when_possible(struct mars_global *global, struct list_head *anchor, bool use_dent_link, const struct mars_brick_type *type, bool even_on);

// mid-level brick instantiation (identity is based on path strings)

extern char *_vpath_make(int line, const char *fmt, va_list *args);
extern char *_path_make(int line, const char *fmt, ...);
extern char *_backskip_replace(int line, const char *path, char delim, bool insert, const char *fmt, ...);

#define vpath_make(_fmt, _args)			\
	_vpath_make(__LINE__, _fmt, _args)
#define path_make(_fmt, _args...)		\
	_path_make(__LINE__, _fmt, ##_args)
#define backskip_replace(_path, _delim, _insert, _fmt, _args...)	\
	_backskip_replace(__LINE__, _path, _delim, _insert, _fmt, ##_args)

extern struct mars_brick *path_find_brick(struct mars_global *global, const void *brick_type, const char *fmt, ...);

/* Create a new brick and connect its inputs to a set of predecessors.
 * When @timeout > 0, switch on the brick as well as its predecessors.
 */
extern struct mars_brick *make_brick_all(
	struct mars_global *global,
	struct mars_dent *belongs,
	int (*setup_fn)(struct mars_brick *brick, void *private),
	void *private,
	const char *new_name,
	const struct generic_brick_type *new_brick_type,
	const struct generic_brick_type *prev_brick_type[],
	int switch_override, // -1 = off, 0 = leave in current state, +1 = create when necessary, +2 = create + switch on
	const char *new_fmt,
	const char *prev_fmt[],
	int prev_count,
	...
	);

// general MARS infrastructure

/* General fs wrappers (for abstraction)
 */
extern int mars_stat(const char *path, struct kstat *stat, bool use_lstat);
extern int mars_mkdir(const char *path);
extern int mars_unlink(const char *path);
extern int mars_symlink(const char *oldpath, const char *newpath, const struct timespec *stamp, uid_t uid);
extern char *mars_readlink(const char *newpath);
extern int mars_rename(const char *oldpath, const char *newpath);
extern void mars_remaining_space(const char *fspath, loff_t *total, loff_t *remaining);

/////////////////////////////////////////////////////////////////////////

extern struct mars_global *mars_global;

extern bool mars_check_inputs(struct mars_brick *brick);
extern bool mars_check_outputs(struct mars_brick *brick);

extern int  mars_power_button(struct mars_brick *brick, bool val, bool force_off);

/////////////////////////////////////////////////////////////////////////

// statistics

extern int global_show_statist;

void show_statistics(struct mars_global *global, const char *class);

/////////////////////////////////////////////////////////////////////////

// quirk

extern int mars_mem_percent;

extern int light_checker(struct mars_dent *parent, const char *_name, int namlen, unsigned int d_type, int *prefix, int *serial, bool *use_channel);

void from_remote_trigger(void);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_sy(void);
extern void exit_sy(void);

extern int init_sy_net(void);
extern void exit_sy_net(void);

#endif
