// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_IF_H
#define MARS_IF_H

#include <linux/semaphore.h>

#define HT_SHIFT 6 //????
#define MARS_MAX_SEGMENT_SIZE (1U << (9+HT_SHIFT))

#define MAX_BIO 32

#define IF_HASH_MAX   256
#define IF_HASH_CHUNK (1024 * 1024)

struct if_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head plug_head;
	struct list_head hash_head;
	int hash_index;
	int bio_count;
	int current_len;
	int max_len;
	bool is_kmapped;
	struct page *orig_page;
	struct bio *orig_bio[MAX_BIO];
	struct generic_callback cb;
	struct if_input *input;
};

struct if_input {
	MARS_INPUT(if);
	// TODO: move this to if_brick (better systematics)
	struct list_head plug_anchor;
	struct request_queue *q;
	struct gendisk *disk;
	struct block_device *bdev;
	atomic_t open_count;
	atomic_t io_count;
	atomic_t plugged_count;
	// only for statistics
	atomic_t read_count;
	atomic_t write_count;
	atomic_t mref_read_count;
	atomic_t mref_write_count;
	spinlock_t req_lock;
	struct semaphore kick_sem;
	struct generic_object_layout mref_object_layout;
	struct mars_info info;
	spinlock_t hash_lock[IF_HASH_MAX];
	struct list_head hash_table[IF_HASH_MAX];
};

struct if_output {
	MARS_OUTPUT(if);
};

struct if_brick {
	MARS_BRICK(if);
	// parameters
	int max_plugged;
	int readahead;
	bool skip_sync;
	// inspectable
	bool has_closed;
	// private
	struct if_output hidden_output;
};

MARS_TYPES(if);

#endif
