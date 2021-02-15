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

#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS      (PAGE_SHIFT + 4)
#define REGION_SIZE           (1 << REGION_SIZE_BITS)
#define LOGGER_QUEUES         4

#include <linux/time.h>

#include "mars.h"
#include "lib_log.h"
#include "lib_pairing_heap.h"
#include "lib_queue.h"
#include "lib_timing.h"
#include "lib_rank.h"
#include "lib_limiter.h"

#ifdef CONFIG_MARS_DEBUG
#define ADDITIONAL_COUNTERS
#endif

///////////////////////// global tuning ////////////////////////

/* 0 = early completion of all writes
 * 1 = early completion of non-sync
 * 2 = late completion
 */
extern int trans_logger_completion_semantics;
extern int trans_logger_do_crc;
extern int trans_logger_allow_compress;
extern int trans_logger_mem_usage; // in KB
extern int trans_logger_pressure_limit;
extern int trans_logger_disable_pressure; /* only for testing */
extern int trans_logger_report_interval;
extern int trans_logger_writeback_maxage;
extern int trans_logger_max_interleave;
extern int trans_logger_resume;
extern int trans_logger_replay_timeout; // in s
extern atomic_t   global_mshadow_count;
extern atomic64_t global_mshadow_used;

struct writeback_group {
	struct rw_semaphore mutex;
	struct trans_logger_brick *leader;
	loff_t biggest;
	struct list_head group_anchor;
	// tuning
	struct mars_limiter limiter;
	int until_percent;
};

extern struct writeback_group global_writeback;

////////////////////////////////////////////////////////////////////

_PAIRING_HEAP_TYPEDEF(logger,)

struct logger_queue {
	QUEUE_ANCHOR(logger,loff_t,logger);
	struct trans_logger_brick *q_brick;
	const char *q_insert_info;
	const char *q_pushback_info;
	const char *q_fetch_info;
	struct banning q_banning;
	int no_progress_count;
	int pushback_count;
};

struct logger_head {
	struct list_head lh_head;
	loff_t *lh_pos;
	struct pairing_heap_logger ph;
};

////////////////////////////////////////////////////////////////////

#ifdef CONFIG_MARS_LOGROT

#define TL_INPUT_READ         0
#define TL_INPUT_WRITEBACK    0
#define TL_INPUT_LOG1         1
#define TL_INPUT_LOG2         2
#define TL_INPUT_NR           3

#else

#define TL_INPUT_READ         0
#define TL_INPUT_WRITEBACK    0
#define TL_INPUT_LOG1         1
#define TL_INPUT_LOG2         1
#define TL_INPUT_NR           2

#endif

#define TL_REPLAY_RUNNING     0
#define TL_REPLAY_FINISHED    1
#define TL_REPLAY_INCOMPLETE  2

struct writeback_info {
	struct trans_logger_brick *w_brick;
	struct logger_head w_lh;
	loff_t w_pos;
	int    w_len;
	int    w_error;
	struct list_head w_collect_list;   // list of collected orig requests
	struct list_head w_sub_read_list;  // for saving the old data before overwrite
	struct list_head w_sub_write_list; // for overwriting
	atomic_t w_sub_read_count;
	atomic_t w_sub_write_count;
	atomic_t w_sub_log_count;
	void (*read_endio)(struct generic_callback *cb);
	void (*write_endio)(struct generic_callback *cb);
};

struct trans_logger_mref_aspect {
	GENERIC_ASPECT(mref);
	struct trans_logger_brick *my_brick;
	struct trans_logger_input *my_input;
	struct trans_logger_input *log_input;
	struct logger_head lh;
	struct list_head hash_head;
	//struct list_head q_head;
	struct list_head pos_head;
	struct list_head replay_head;
	struct list_head collect_head;
	struct pairing_heap_logger ph;
	struct trans_logger_mref_aspect *shadow_ref;
	struct trans_logger_mref_aspect *orig_mref_a;
	void  *shadow_data;
	int    orig_flags;
	int    wb_error;
	bool   do_dealloc;
	bool   do_buffered;
	bool   is_hashed;
	bool   is_stable;
	bool   is_dirty;
	bool   is_collected;
	bool   is_fired;
	bool   is_completed;
	bool   is_endio;
	bool   is_persistent;
	bool   is_emergency;
	struct lamport_time stamp;
	loff_t log_pos;
	struct generic_callback cb;
	struct writeback_info *wb;
	struct list_head sub_list;
	struct list_head sub_head;
	int    total_sub_count;
	int    alloc_len;
	atomic_t current_sub_count;
};

struct trans_logger_hash_anchor;

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
	// parameters
	struct lamport_time logger_epoch;
	struct mars_limiter *replay_limiter;
	int shadow_mem_limit; // max # master shadows
	bool replay_mode;   // mode of operation
	bool continuous_replay_mode;   // mode of operation
	bool log_reads;   // additionally log pre-images
	bool cease_logging; // direct IO without logging (only in case of EMERGENCY)
	bool debug_shortcut; // only for testing! never use in production!
	loff_t replay_start_pos; // where to start replay
	loff_t replay_end_pos;   // end of replay
	int new_input_nr;   // whereto we should switchover ASAP
	int replay_tolerance; // how many bytes to ignore at truncated logfiles
	// readonly from outside
	loff_t replay_current_pos;   // end of replay
	int log_input_nr;   // where we are currently logging to
	int old_input_nr;   // where old IO requests may be on the fly
	int replay_code;    // replay errors (if any)
	bool stopped_logging; // direct IO without logging (only in case of EMERGENCY)
	// private
	int disk_io_error;         // replay errors from callbacks
	struct trans_logger_hash_anchor **hash_table;
	struct list_head group_head;
	loff_t old_margin;
	struct rw_semaphore replay_mutex;
	struct list_head replay_list;
	struct task_struct *thread;
	wait_queue_head_t worker_event;
	wait_queue_head_t caller_event;
	// statistics
	atomic64_t shadow_mem_used;
	atomic_t replay_count;
	atomic_t any_fly_count;
	atomic_t log_fly_count;
#ifdef ADDITIONAL_COUNTERS
	atomic_t hash_count;
	atomic_t mshadow_count;
	atomic_t sshadow_count;
	atomic_t outer_balance_count;
	atomic_t inner_balance_count;
	atomic_t sub_balance_count;
	atomic_t wb_balance_count;
	atomic_t total_hash_insert_count;
	atomic_t total_hash_find_count;
	atomic_t total_hash_extend_count;
	atomic_t total_replay_count;
	atomic_t total_replay_conflict_count;
	atomic_t total_cb_count;
	atomic_t total_read_count;
	atomic_t total_write_count;
	atomic_t total_flush_count;
	atomic_t total_writeback_count;
	atomic_t total_writeback_cluster_count;
	atomic_t total_shortcut_count;
	atomic_t total_mshadow_count;
	atomic_t total_sshadow_count;
	atomic_t total_mshadow_buffered_count;
	atomic_t total_sshadow_buffered_count;
	atomic_t total_round_count;
	atomic_t total_restart_count;
	atomic_t total_delay_count;
#endif
	int pressure_mode;
	// queues
	struct logger_queue q_phase[LOGGER_QUEUES];
	struct rank_data rkd[LOGGER_QUEUES];
#ifdef CONFIG_MARS_DEBUG
	int bail[LOGGER_QUEUES];
	int selected;
#endif
	int caller_flag;
	int worker_flag;
	bool   delay_callers;
	/* termination */
	bool terminate;
	bool terminated;
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
};

#define MAX_HOST_LEN 32

struct trans_logger_info {
	// to be maintained / initialized from outside
	void (*inf_callback)(struct trans_logger_info *inf);
	void  *inf_private;
	char   inf_host[MAX_HOST_LEN];
	int    inf_index;
	int    inf_sequence;     // logfile sequence number

	// maintained by trans_logger
	loff_t inf_min_pos;  // current replay position (both in replay mode and in logging mode)
	loff_t inf_max_pos;  // dito, indicating the "dirty" area which could be potentially "inconsistent"
	loff_t inf_log_pos; // position of transaction logging (may be ahead of replay position)
	struct lamport_time inf_min_pos_stamp; // when the data has been _successfully_ overwritten
	struct lamport_time inf_max_pos_stamp; // when the data has _started_ overwrite (maybe "trashed" in case of errors / aborts)
	struct lamport_time inf_log_pos_stamp; // stamp from transaction log
	bool inf_is_replaying;
	bool inf_is_logging;
};

struct trans_logger_input {
	MARS_INPUT(trans_logger);
	// parameters
	// informational
	struct trans_logger_info inf;
	// readonly from outside
	atomic_t log_ref_count;
	atomic_t pos_count;
	bool is_operating;
	long long last_jiffies;

	// private
	struct log_status logst;
	struct list_head pos_list;
	long long inf_min_jiffies;
	long long inf_min_old;
	long long inf_last_jiffies;
	struct semaphore inf_mutex;
};

MARS_TYPES(trans_logger);

#endif
