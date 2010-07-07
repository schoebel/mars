// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_BUF_H
#define MARS_BUF_H

#include <linux/list.h>

#define MARS_BUF_HASH_MAX 512

struct buf_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
};

struct buf_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
	struct list_head bf_member_head;
	struct list_head bf_pending_head;
	struct buf_head *bf;
};

struct buf_brick {
	MARS_BRICK(buf);
	int backing_order;
	int backing_size;
	int max_count;
	int current_count;
	int alloc_count;
	struct mars_io_object_layout *mio_layout;

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
	int io_aspect_slot;
	int buf_aspect_slot;
};

MARS_TYPES(buf);

struct buf_head {
	struct buf_brick *bf_brick;
	void  *bf_data;
	loff_t bf_pos;
	int    bf_flags;
	int    bf_count;
	// lists for caching
	struct list_head bf_mbuf_anchor; // all current mbuf members
	struct list_head bf_lru_head;
	struct list_head bf_hash_head;
	// lists for IO
	struct list_head bf_read_pending_anchor;
	struct list_head bf_write_pending_anchor;
	struct list_head bf_again_write_pending_anchor;
};

#endif
