// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_BUF_H
#define MARS_BUF_H

#include <linux/list.h>
#include <asm/atomic.h>

//#define MARS_BUF_HASH_MAX 512
#define MARS_BUF_HASH_MAX 2048

#define LIST_FREE    0
#define LIST_FORGET  1
#define LIST_LRU     2
#define LIST_MAX     3

struct buf_mref_aspect {
	GENERIC_ASPECT(mref);
	struct buf_head *rfa_bf;
	//struct list_head rfa_bf_head;
	struct list_head rfa_pending_head;
	//struct list_head tmp_head;
	struct generic_callback cb;
};

struct cache_anchor {
	spinlock_t       hash_lock;
	struct list_head hash_anchor;
};

struct buf_brick {
	MARS_BRICK(buf);
	/* brick parameters */
	int backing_order;
	int backing_size;
	int max_count;
	bool optimize_chains;
	
	/* internals */
	spinlock_t brick_lock;
	atomic_t alloc_count;
	atomic_t list_count[LIST_MAX];
	atomic_t hashed_count;
	atomic_t nr_io_pending;
	atomic_t nr_collisions;
	struct generic_object_layout mref_object_layout;
	struct mars_info base_info;
	bool got_info;

	// lists for caching
	struct list_head list_anchor[LIST_MAX];   // members are hashed and not in use
	struct list_head forget_anchor;   // like lru_anchor, but likely
	struct cache_anchor cache_anchors[MARS_BUF_HASH_MAX]; // hash table

	// statistics
	unsigned long last_jiffies;
	atomic_t hit_count;
	atomic_t miss_count;
	atomic_t opt_count;
	atomic_t chain_count;
	atomic_t post_count;
	atomic_t write_count;
	atomic_t io_count;
};

struct buf_input {
	MARS_INPUT(buf);
};

struct buf_output {
	MARS_OUTPUT(buf);
};

MARS_TYPES(buf);

struct buf_head {
	void             *bf_data; // this MUST come first
	spinlock_t        bf_lock;
	struct buf_brick *bf_brick;
	loff_t            bf_pos;
	loff_t            bf_base_index;
	int               bf_flags;
	int               bf_error;
	atomic_t          bf_hash_count; // # references pinning the hash
	atomic_t          bf_mref_count; // # mrefs (only used for checking, no real semantics)
	atomic_t          bf_io_count;   // # IOs in flight
	// statistics / data for strategic decisions
	atomic_t          bf_mfu_stat;
	atomic_t          bf_chain_len;
	bool              bf_chain_detected;
	// lists for caching
	//struct list_head bf_mref_anchor; // all current mref members
	struct list_head  bf_list_head;
	struct list_head  bf_hash_head;
	unsigned long     bf_jiffies;
	int               bf_member;
	// lists for IO
	struct list_head  bf_io_pending_anchor;
	struct list_head  bf_postpone_anchor;
};

#endif
