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

#define MARS_ARGV_MAX 4

/* This _should_ be updated when _compatible_ features
 * are added. When somebody may _rely_ on the new feature,
 * then this _must_ be updated.
 */
/* 1 = traditional
 * 2 = push operation available
 * 3 = new alivelinks residing in /mars/actual-$host
 * 4 = new join-cluster and random peer threads
 * 5 = fix race on peer thread creation
 */
#define OPTIONAL_STRATEGY_VERSION 5

/* transient, to re-disappear */
extern int compat_deletions;

extern int usable_features_version;
extern int usable_strategy_version;
extern int usable_marsadm_version_major;
extern int usable_marsadm_version_minor;

extern int mars_min_update;

extern loff_t global_total_space;
extern loff_t global_remaining_space;

extern int global_logrot_auto;
extern int global_free_space_0;
extern int global_free_space_1;
extern int global_free_space_2;
extern int global_free_space_3;
extern int global_free_space_4;
extern int global_sync_nr;
extern int global_sync_limit;
extern int mars_rollover_interval;
extern int mars_scan_interval;
extern int mars_propagate_interval;
extern int mars_sync_flip_interval;
extern int mars_running_additional_peers;
extern int mars_run_additional_peers;
extern int mars_peer_abort;
extern int mars_emergency_mode;
extern int mars_reset_emergency;
extern int mars_keep_msg;

extern int mars_fast_fullsync;

#ifdef CONFIG_MARS_DEBUG
extern int mars_test_additional_peers;
#endif

#define MARS_IP_STR      "/mars/ips/ip-"
extern void invalidate_user_cache(void);

extern char *my_id(void);
extern int   my_id_len(void);
extern const char *my_uuid;

extern void wait_main_round(void);
extern void launch_peer(const char *peer_name,
			const char *peer_ip,
			const char *rebase_dir,
			bool oneshot);

struct mars_dent;
typedef void (*dent_skip_fn)(struct mars_dent *);

unsigned int dent_hash(const char *str, int len);

#define DENT_HASH_ANCHOR(global,index)					\
({									\
	struct list_head *table = (global)->dent_hash_table[(index) / MARS_GLOBAL_HASH_TABLE];	\
									\
	table + ((index) % MARS_GLOBAL_HASH_TABLE);			\
})

#define MARS_DENT(TYPE)							\
	struct list_head dent_link;					\
	struct list_head dent_hash_link;				\
	struct list_head brick_list;					\
	struct TYPE *d_parent;						\
	dent_skip_fn d_skip_fn;						\
	char *d_argv[MARS_ARGV_MAX];  /* for internal use, will be automatically deallocated*/ \
	char *d_args; /* ditto uninterpreted */				\
	char *d_name; /* current path component */			\
	char *d_rest; /* some "meaningful" rest of d_name*/		\
	char *d_path; /* full absolute path */				\
	struct say_channel *d_say_channel; /* for messages */		\
	loff_t d_corr_A; /* logical size correction */			\
	loff_t d_corr_B; /* logical size correction */			\
	atomic_t d_count;						\
	int   d_depth;							\
	unsigned int d_type; /* from readdir() => often DT_UNKNOWN => don't rely on it, use new_stat.mode instead */ \
	int   d_class;    /* for pre-grouping order */			\
	int   d_serial;   /* for pre-grouping order */			\
	int   d_version;  /* dynamic programming per call of mars_ent_work() */ \
	int   d_child_count;						\
	unsigned int d_hash;						\
	int   d_proto;							\
	char d_once_error;						\
	bool d_no_scan;							\
	bool d_running;							\
	bool d_killme;							\
	bool d_use_channel;						\
	bool d_unordered;						\
	struct kstat new_stat;						\
	struct kstat old_stat;						\
	char *new_link;							\
	char *old_link;							\
	struct mars_global *d_subtree;					\
	void (*d_private_destruct)(void *private);			\
	void *d_private;

struct mars_dent {
	MARS_DENT(mars_dent);
};

extern const struct meta mars_kstat_meta[];
extern const struct meta mars_dent_meta[];

#define MARS_GLOBAL_HASH_BASE 16
#define MARS_GLOBAL_HASH_TABLE (PAGE_SIZE / sizeof(struct list_head))
#define MARS_GLOBAL_HASH (MARS_GLOBAL_HASH_BASE * MARS_GLOBAL_HASH_TABLE)

struct mars_global {
	struct rw_semaphore dent_mutex;
	struct rw_semaphore brick_mutex;
	struct generic_switch global_power;
	struct list_head dent_anchor;
	struct list_head brick_anchor;
	wait_queue_head_t main_event;
	int global_version;
	int deleted_my_border;
	int old_deleted_my_border;
	int deleted_border;
	int deleted_min;
	int trigger_mode;
	/* statistics */
	int nr_readdir;
	int nr_readitem;
	int nr_ordered;
	int nr_unordered;
	bool has_subtrees;
	bool main_trigger;
	struct list_head *dent_hash_table[MARS_GLOBAL_HASH_BASE];
};

extern void _init_mars_global(struct mars_global *global);
extern void exit_mars_global(struct mars_global *global);

#define init_mars_global(__global)				\
do {								\
	_init_mars_global(__global);				\
	init_rwsem(&(__global)->dent_mutex);			\
	init_rwsem(&(__global)->brick_mutex);			\
} while(0)

#define alloc_mars_global()					\
({								\
	struct mars_global *__global;				\
								\
	__global = brick_mem_alloc(sizeof(struct mars_global));	\
	init_mars_global(__global);				\
	__global;						\
 })

#define free_mars_global(_global_)				\
({								\
	struct mars_global *__global = (_global_);		\
								\
	if (__global) {						\
		(_global_) = NULL;				\
		exit_mars_global(__global);			\
		brick_mem_free(__global);			\
	}							\
})

extern void bind_to_dent(struct mars_dent *dent, struct say_channel **ch);

typedef int (*mars_dent_checker_fn)(struct mars_dent *parent, const char *name, int namlen, unsigned int d_type, int *prefix, int *serial, bool *use_channel);
typedef int (*mars_dent_worker_fn)(struct mars_global *global, struct mars_dent *dent, bool prepare, bool direction);

extern int mars_dent_work(struct mars_global *global,
			  char *dirname,
			  int allocsize,
			  mars_dent_checker_fn checker,
			  mars_dent_worker_fn worker,
			  void *buf,
			  int maxdepth,
			  bool use_subtree);
extern int mars_get_dent_list(struct mars_global *global,
			      const char *path_list,
			      int allocsize,
			      mars_dent_checker_fn checker,
			      int maxdepth);
extern struct mars_dent *mars_find_dent(struct mars_global *global, const char *path);
extern void mars_kill_dent(struct mars_global *global, struct mars_dent *dent);
extern void mars_free_dent(struct mars_global *global, struct mars_dent *dent);
extern void mars_free_dent_all(struct mars_global *global);

/* network transfer of dents */

struct mars_socket;
extern int mars_send_dent_list(struct mars_global *global, struct mars_socket *msock);
extern int mars_recv_dent_list(struct mars_global *global, struct mars_socket *msock);

// low-level brick instantiation

int mars_connect(struct mars_input *a, struct mars_output *b);
int mars_disconnect(struct mars_input *a);

extern struct mars_brick *mars_find_brick(struct mars_global *global, const void *brick_type, const char *path);
extern struct mars_brick *mars_make_brick(struct mars_global *global,
					  struct mars_dent *belongs,
					  const void *_brick_type,
					  const char *resource_name,
					  const char *path);
extern int mars_free_brick(struct mars_brick *brick);
extern int mars_kill_brick(struct mars_brick *brick);
extern int mars_kill_brick_all(struct mars_global *global, struct list_head *anchor, bool use_dent_link);
extern int mars_kill_brick_when_possible(struct mars_global *global,
					 const struct mars_brick_type *type_list[],
					 bool even_on);

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
	const char *resource_name,
	int (*setup_fn)(struct mars_brick *brick, void *private),
	void *private,
	const struct generic_brick_type *new_brick_type,
	int switch_override, // -1 = off, 0 = leave in current state, +1 = create when necessary, +2 = create + switch on
	const char *new_fmt,
	const char *prev_fmt[],
	int prev_count,
	...
	);

// general MARS infrastructure

#define MARS_ERR_ONCE(dent, args...) if (!dent->d_once_error++) MARS_ERR(args)

static inline
bool is_deleted_link(const char *str)
{
	return (!str || !str[0]);
}

bool push_link(const char *peer_name,
	       const char *peer_ip,
	       const char *src,
	       const char *dst);
bool push_check(const char *peer_name,
		const char *peer_ip,
		const char *path);

/* General fs wrappers (for abstraction)
 */
extern bool mars_is_mountpoint(const char *pathname);
extern int mars_stat(const char *path, struct kstat *stat, bool use_lstat);
extern void mars_sync(void);
extern int mars_mkdir(const char *path);
extern int mars_rmdir(const char *path);
extern int mars_unlink(const char *path);
extern char *mars_readlink(const char *newpath, struct lamport_time *stamp);
extern int mars_rename(const char *oldpath, const char *newpath);
extern int mars_chmod(const char *path, mode_t mode);
extern void mars_remaining_space(const char *fspath, loff_t *total, loff_t *remaining);

/* Timestamp Ordering */

#define MARS_DELETED_STR ".deleted"

extern char *ordered_readlink(const char *path, struct lamport_time *stamp);

extern int ordered_unlink(const char *path,
			  const struct lamport_time *stamp,
			  int serial,
			  int mode);
extern int ordered_symlink(const char *oldpath,
			   const char *newpath,
			   const struct lamport_time *stamp);

/////////////////////////////////////////////////////////////////////////

extern struct mars_global *mars_global;

extern bool mars_check_inputs(struct mars_brick *brick);
extern bool mars_check_outputs(struct mars_brick *brick);

extern int  mars_power_button(struct mars_brick *brick, bool val, bool force_off);

/////////////////////////////////////////////////////////////////////////

// statistics

extern int global_show_statist;
extern int global_show_connections;

void show_statistics(struct mars_global *global, const char *class);

/////////////////////////////////////////////////////////////////////////

// quirk

extern int mars_mem_percent;
extern int mars_mem_gb;

extern int main_checker(struct mars_dent *parent, const char *_name, int namlen, unsigned int d_type, int *prefix, int *serial, bool *use_channel);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_sy(void);
extern void exit_sy(void);

extern int init_sy_net(void);
extern void exit_sy_net(void);


#endif
