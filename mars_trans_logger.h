// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS 22
#define REGION_SIZE (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX 512

#include <linux/time.h>
#include "log_format.h"
#include "pairing_heap.h"

////////////////////////////////////////////////////////////////////

_PAIRING_HEAP_TYPEDEF(mref,)

struct logger_queue {
	struct logger_queue *q_dep;
	struct trans_logger_output *q_output;
	struct list_head q_anchor;
	struct pairing_heap_mref *heap_high;
	struct pairing_heap_mref *heap_low;
	loff_t heap_border;
	long long q_last_action; // jiffies
	spinlock_t q_lock;
	atomic_t q_queued;
	atomic_t q_flying;
	const char *q_insert_info;
	const char *q_pushback_info;
	const char *q_fetch_info;
	// tunables
	int q_batchlen;
	int q_max_queued;
	int q_max_flying;
	int q_max_jiffies;
	int q_max_contention;
	int q_over_pressure;
	int q_io_prio;
	bool q_ordering;
};

////////////////////////////////////////////////////////////////////

struct hash_anchor {
	rwlock_t hash_lock;
	struct list_head hash_anchor;
};

struct trans_logger_mref_aspect {
	GENERIC_ASPECT(mref);
	struct trans_logger_output *output;
	struct list_head hash_head;
	struct list_head q_head;
	struct list_head pos_head;
	struct pairing_heap_mref ph;
	struct trans_logger_mref_aspect *shadow_ref;
	bool   do_dealloc;
	bool   is_hashed;
	bool   is_valid;
	bool   is_outdated;
	struct timespec stamp;
	loff_t log_pos;
	struct generic_callback cb;
	struct trans_logger_mref_aspect *orig_mref_a;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
	// parameters
	int sequence;     // logfile sequence number
	int limit_congest;// limit phase1 congestion.
	int align_size;   // alignment between requests
	int chunk_size;   // must be at least 8K (better 64k)
	int flush_delay;  // delayed firing of incomplete chunks
	bool do_replay;   // mode of operation
	bool log_reads;   // additionally log pre-images
	bool debug_shortcut; // only for testing! never use in production!
	loff_t start_pos; // where to start replay
	loff_t end_pos;   // end of replay
	// readonly from outside
	loff_t current_pos; // current logging position
	loff_t replay_pos;  // current replay position
	// private
	struct log_status logst;
	struct list_head pos_list;
	spinlock_t pos_lock;
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
	atomic_t replay_count;
	atomic_t fly_count;
	atomic_t hash_count;
	atomic_t mshadow_count;
	atomic_t sshadow_count;
	atomic_t outer_balance_count;
	atomic_t inner_balance_count;
	atomic_t sub_balance_count;
	atomic_t total_read_count;
	atomic_t total_write_count;
	atomic_t total_writeback_count;
	atomic_t total_shortcut_count;
	atomic_t total_mshadow_count;
	atomic_t total_sshadow_count;
	struct task_struct *thread;
	wait_queue_head_t event;
	struct generic_object_layout replay_layout;
	// queues
	struct logger_queue q_phase1;
	struct logger_queue q_phase2;
	struct logger_queue q_phase3;
	struct logger_queue q_phase4;
	bool   did_pushback;
	struct hash_anchor hash_table[TRANS_HASH_MAX];
};

struct trans_logger_input {
	MARS_INPUT(trans_logger);
};

MARS_TYPES(trans_logger);

#endif
