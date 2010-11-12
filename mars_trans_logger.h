// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS 22
#define REGION_SIZE (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX 32

#include <linux/time.h>
#include "pairing_heap.h"

struct log_header {
	struct timespec l_stamp;
	loff_t l_pos;
	int    l_len;
	int    l_code;
};

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
	int q_last_action; // jiffies
	// tunables
	int q_max_flying;
	bool q_ordering;
};

////////////////////////////////////////////////////////////////////

struct hash_anchor {
	rwlock_t hash_lock;
	struct list_head hash_anchor;
};

struct trans_logger_mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
	struct list_head hash_head;
	struct list_head q_head;
	struct pairing_heap_mref ph;
	struct trans_logger_mars_ref_aspect *shadow_ref;
	void *orig_data;
	struct trans_logger_output *output;
	struct timespec stamp;
	struct generic_callback cb;
	struct trans_logger_mars_ref_aspect *orig_mref_a;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
	// parameters
	bool log_reads;
	int allow_reads_after; // phase2 and later is only started after this time (in jiffies)
	int limit_congest;     // limit phase1 congestion.
	int max_queue;    // delay phase2 & later only if this number of waiting requests is not exceeded
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
	struct hash_anchor hash_table[TRANS_HASH_MAX];
	atomic_t hash_count;
	atomic_t fly_count;
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
	struct mars_info info;
	loff_t log_pos;
	struct mars_ref_object *log_mref;
	int validflag_offset;
	int reallen_offset;
	int payload_offset;
	int payload_len;
	struct trans_logger_output hidden_output;
	struct generic_object_layout ref_object_layout;
};

MARS_TYPES(trans_logger);

#endif
