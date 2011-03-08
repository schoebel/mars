// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS 22
#define REGION_SIZE (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX 128

#include <linux/time.h>
#include "log_format.h"
#include "pairing_heap.h"

////////////////////////////////////////////////////////////////////

_PAIRING_HEAP_TYPEDEF(mref,)

struct logger_queue {
	struct list_head q_anchor;
	struct pairing_heap_mref *heap_high;
	struct pairing_heap_mref *heap_low;
	loff_t heap_border;
	spinlock_t q_lock;
	atomic_t q_queued;
	atomic_t q_flying;
	long long q_last_action; // jiffies
	// tunables
	int q_max_queued;
	int q_max_flying;
	int q_max_jiffies;
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
	struct pairing_heap_mref ph;
	struct trans_logger_mref_aspect *shadow_ref;
	void   *orig_data;
	bool   is_hashed;
	struct timespec stamp;
	struct generic_callback cb;
	struct trans_logger_mref_aspect *orig_mref_a;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
	struct log_status logst;
	// parameters
	int sequence;     // logfile sequence number
	int limit_congest;// limit phase1 congestion.
	bool do_replay;   // mode of operation
	bool log_reads;   // additionally log pre-images
	loff_t start_pos; // where to start replay
	loff_t end_pos;   // end of replay
	// readonly from outside
	loff_t current_pos; // current replay position
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
	struct hash_anchor hash_table[TRANS_HASH_MAX];
	atomic_t hash_count;
	atomic_t fly_count;
	atomic_t mshadow_count;
	atomic_t sshadow_count;
	struct task_struct *thread;
	wait_queue_head_t event;
	// queues
	struct logger_queue q_phase1;
	struct logger_queue q_phase2;
	struct logger_queue q_phase3;
	struct logger_queue q_phase4;
};

struct trans_logger_input {
	MARS_INPUT(trans_logger);
};

MARS_TYPES(trans_logger);

#endif
