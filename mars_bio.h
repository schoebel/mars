// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_BIO_H
#define MARS_BIO_H

#include <linux/blkdev.h>

struct bio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	struct bio *bio;
	struct bio_output *output;
	int status_code;
	int hash_pos;
	int alloc_len;
	bool do_dealloc;
};

struct bio_brick {
	MARS_BRICK(bio);
	// tunables
	int ra_pages;
	int bg_threshold;
	int bg_maxfly;
	bool do_noidle;
	bool do_sync;
	bool do_unplug;
	// readonly
	loff_t total_size;
	atomic_t fly_count[MARS_PRIO_NR];
	atomic_t background_count;
	atomic_t completed_count;
	atomic_t total_completed_count[MARS_PRIO_NR];
	atomic_t total_background_count;
	// private
	spinlock_t lock;
	struct list_head background_list;
	struct list_head completed_list;
	wait_queue_head_t event;
	struct file *filp;
	struct block_device *bdev;
	struct task_struct *thread;
	int bvec_max;
};

struct bio_input {
	MARS_INPUT(bio);
};

struct bio_output {
	MARS_OUTPUT(bio);
};

MARS_TYPES(bio);

#endif
