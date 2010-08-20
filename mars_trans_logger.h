// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS 22
#define REGION_SIZE (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX 32

#include <linux/time.h>

struct log_header {
	struct timespec l_stamp;
	loff_t l_pos;
	int    l_len;
	int    l_code;
};

////////////////////////////////////////////////////////////////////

struct logger_queue {
	spinlock_t q_lock;
	struct list_head q_anchor;
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
	struct trans_logger_mars_ref_aspect *shadow_ref;
	void *orig_data;
	struct trans_logger_output *output;
	struct timespec stamp;
	struct generic_callback cb;
	struct trans_logger_mars_ref_aspect *orig_mref_a;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
	struct hash_anchor hash_table[TRANS_HASH_MAX];
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
