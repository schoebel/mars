// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_BUF_H
#define MARS_BUF_H

#include <linux/list.h>
#include <asm/atomic.h>

#define MARS_BUF_HASH_MAX 512

struct buf_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
	struct buf_head  *mia_bf;
	struct list_head  mia_tmp_head;
	bool mia_end_io_called;
};

struct buf_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
	struct buf_head *bfa_bf;
	struct list_head bfc_pending_head;
	int nr_io_pending;
};

struct buf_brick {
	MARS_BRICK(buf);
	/* brick parameters */
	int backing_order;
	int backing_size;
	int max_count;
	
	/* internals */
	int current_count;
	int alloc_count;
	struct generic_object_layout mio_object_layout;

	spinlock_t buf_lock;

	// lists for caching
	struct list_head free_anchor;  // members are not hashed
	struct list_head lru_anchor;   // members are hashed
	struct list_head cache_anchors[MARS_BUF_HASH_MAX]; // hash table

	// for creation of bios
	struct mars_info base_info;
	int got_info;
	int bvec_max;
};

struct buf_input {
	MARS_INPUT(buf);
};

struct buf_output {
	MARS_OUTPUT(buf);
};

MARS_TYPES(buf);

struct buf_head {
	struct buf_brick *bf_brick;
	void             *bf_data;
	loff_t           bf_pos;
	int              bf_flags;
	atomic_t         bf_count;
	int              bf_bio_status;
	atomic_t         bf_bio_count;
	// lists for caching
	//struct list_head bf_mbuf_anchor; // all current mbuf members
	struct list_head bf_lru_head;
	struct list_head bf_hash_head;
	// lists for IO
	struct list_head bf_io_pending_anchor;
	struct list_head bf_again_write_pending_anchor;
};

#endif
