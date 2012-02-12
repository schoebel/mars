// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS      (PAGE_SHIFT + 4)
#define REGION_SIZE           (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX        8192
//#define TRANS_HASH_MAX        16384

#include <linux/time.h>

#include "lib_log.h"
#include "lib_pairing_heap.h"
#include "lib_queue.h"

////////////////////////////////////////////////////////////////////

_PAIRING_HEAP_TYPEDEF(logger,)

struct logger_queue {
	QUEUE_ANCHOR(logger,loff_t,logger);
	struct trans_logger_brick *q_brick;
	const char *q_insert_info;
	const char *q_pushback_info;
	const char *q_fetch_info;

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

struct hash_anchor {
	struct rw_semaphore hash_mutex;
	struct list_head hash_anchor;
};

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
	int    orig_rw;
	int    wb_error;
	bool   do_dealloc;
	bool   do_buffered;
	bool   is_hashed;
	bool   is_dirty;
	bool   is_collected;
	bool   is_fired;
	bool   is_completed;
	struct timespec stamp;
	loff_t log_pos;
	struct generic_callback cb;
	struct writeback_info *wb;
	struct list_head sub_list;
	struct list_head sub_head;
	int    total_sub_count;
	int    alloc_len;
	atomic_t current_sub_count;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
	// parameters
	int shadow_mem_limit; // max # master shadows
	int limit_congest;// limit phase1 congestion.
	int max_mref_size;// shorten mrefs to this maxlen
	int align_size;   // alignment between requests
	int chunk_size;   // must be at least 8K (better 64k)
	int flush_delay;  // delayed firing of incomplete chunks
	int completion_semantics; // 0 = early completion of all writes, 1 = early completion of non-sync, 2 = late completion
	int max_flying;   // limit # of log write requests in parallel
	bool do_replay;   // mode of operation
	bool do_continuous_replay;   // mode of operation
	bool log_reads;   // additionally log pre-images
	bool minimize_latency; // ... at the cost of throughput. ==0 means immediate flushing
	bool debug_shortcut; // only for testing! never use in production!
	loff_t replay_start_pos; // where to start replay
	loff_t replay_end_pos;   // end of replay
	int new_input_nr;   // whereto we should switchover ASAP
	// readonly from outside
	int log_input_nr;   // where we are currently logging to
	int old_input_nr;   // where old IO requests may be on the fly
	int replay_code;    // replay errors (if any)
	// private
	loff_t old_margin;
	spinlock_t replay_lock;
	struct list_head replay_list;
	struct task_struct *thread;
	wait_queue_head_t worker_event;
	wait_queue_head_t caller_event;
	// statistics
	atomic64_t shadow_mem_used;
	atomic_t replay_count;
	atomic_t fly_count;
	atomic_t hash_count;
	atomic_t pos_count;
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
	// queues
	struct logger_queue q_phase0;
	struct logger_queue q_phase1;
	struct logger_queue q_phase2;
	struct logger_queue q_phase3;
	bool   did_pushback;
	bool   did_work;
	bool   delay_callers;
	struct hash_anchor hash_table[TRANS_HASH_MAX];
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
};

struct trans_logger_input {
	MARS_INPUT(trans_logger);
	// parameters
	loff_t log_start_pos; // where to start logging
	// informational
	long long last_jiffies;
	char *inf_host;
	int inf_sequence;     // logfile sequence number
	bool is_prepared;
	// readonly from outside
	loff_t replay_min_pos;  // current replay position (both in replay mode and in logging mode)
	loff_t replay_max_pos;  // dito, indicating the "dirty" area which could be potentially "inconsistent"
	bool is_operating;

	// private
	struct log_status logst;
	spinlock_t pos_lock;
	struct list_head pos_list;
};

MARS_TYPES(trans_logger);

#endif
