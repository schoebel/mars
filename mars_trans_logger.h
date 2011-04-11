// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

#define REGION_SIZE_BITS 22
#define REGION_SIZE (1 << REGION_SIZE_BITS)
#define TRANS_HASH_MAX 512

//#define BITMAP_CHECKS
#ifdef BITMAP_CHECKS
#include <linux/bitmap.h>
#endif

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
	loff_t heap_margin;
	loff_t last_pos;
	long long q_last_insert; // jiffies
	spinlock_t q_lock;
	atomic_t q_queued;
	atomic_t q_flying;
	atomic_t q_total;
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

struct writeback_info {
	struct trans_logger_output *w_output;
	loff_t w_pos;
	int    w_len;
	struct list_head w_collect_list;   // list of collected orig requests
	struct list_head w_sub_read_list;  // for saving the old data before overwrite
	struct list_head w_sub_write_list; // for overwriting
	atomic_t w_sub_read_count;
	atomic_t w_sub_write_count;
	void (*read_endio)(struct generic_callback *cb);
	void (*write_endio)(struct generic_callback *cb);
};

struct trans_logger_mref_aspect {
	GENERIC_ASPECT(mref);
	struct trans_logger_output *output;
	struct list_head hash_head;
	struct list_head q_head;
	struct list_head pos_head;
	struct list_head replay_head;
	struct list_head collect_head;
	struct pairing_heap_mref ph;
	struct trans_logger_mref_aspect *shadow_ref;
	void  *shadow_data;
	bool   do_dealloc;
	bool   do_buffered;
	bool   is_hashed;
	bool   is_dirty;
	bool   is_collected;
	bool   ignore_this;
	struct timespec stamp;
	loff_t log_pos;
	loff_t fetch_margin;
	struct generic_callback cb;
	struct trans_logger_mref_aspect *orig_mref_a;
	struct writeback_info *wb;
	struct trans_logger_mref_aspect *base_mref_a;
	struct list_head sub_list;
	struct list_head sub_head;
	int    total_sub_count;
	atomic_t current_sub_count;
#ifdef BITMAP_CHECKS
	int  shadow_offset;
	int  bitmap_write;
	int  bitmap_write_slave;
	int  bitmap_read;
	int  start_phase1;
	int  end_phase1;
	int  start_phase2;
	int  sub_count;
	unsigned long dirty_bitmap[4];
	unsigned long touch_bitmap[4];
	unsigned long slave_bitmap[4];
	unsigned long work_bitmap[4];
#endif
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
	bool do_continuous_replay;   // mode of operation
	bool log_reads;   // additionally log pre-images
	bool debug_shortcut; // only for testing! never use in production!
	loff_t replay_start_pos; // where to start replay
	loff_t replay_end_pos;   // end of replay
	loff_t log_start_pos; // where to start logging
	// readonly from outside
	loff_t replay_pos;  // current replay position (both in replay mode and in logging mode)
	loff_t current_pos; // current logging position (usually ahead of replay_pos)
	int replay_code;    // replay errors (if any)
	// private
	loff_t old_margin;
	struct log_status logst;
	spinlock_t pos_lock;
	spinlock_t replay_lock;
	struct list_head pos_list;
	struct list_head replay_list;
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
	atomic_t wb_balance_count;
	atomic_t total_read_count;
	atomic_t total_write_count;
	atomic_t total_writeback_count;
	atomic_t total_shortcut_count;
	atomic_t total_mshadow_count;
	atomic_t total_sshadow_count;
	struct task_struct *thread;
	wait_queue_head_t event;
	struct generic_object_layout writeback_layout;
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
