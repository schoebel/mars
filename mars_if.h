// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_IF_H
#define MARS_IF_H

#include <linux/semaphore.h>

#define HT_SHIFT 6 //????
#define MARS_MAX_SEGMENT_SIZE (1U << (9+HT_SHIFT))

#define MAX_BIO 8

struct if_mref_aspect {
	GENERIC_ASPECT(mref);
	//struct list_head tmp_head;
	struct list_head plug_head;
	int maxlen;
	int bio_count;
#if 1
	int xxx;
	int yyy;
#endif
	struct page *orig_page;
	struct bio *orig_bio[MAX_BIO];
	struct generic_callback cb;
	struct if_input *input;
};

struct if_input {
	MARS_INPUT(if);
	struct list_head plug_anchor;
	struct request_queue *q;
	struct gendisk *disk;
	struct block_device *bdev;
	atomic_t open_count;
	spinlock_t req_lock;
	struct semaphore kick_sem;
	struct generic_object_layout mref_object_layout;
};

struct if_output {
	MARS_OUTPUT(if);
};

struct if_brick {
	MARS_BRICK(if);
	bool has_closed;
	struct if_output hidden_output;
};

MARS_TYPES(if);

#endif
