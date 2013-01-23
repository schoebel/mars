// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_BIO_H
#define MARS_BIO_H

#define BIO_SUBMIT_MAX_LATENCY    250 // 250 us
#define BIO_IO_R_MAX_LATENCY    40000 //  40 ms
#define BIO_IO_W_MAX_LATENCY   100000 // 100 ms

extern struct threshold bio_submit_threshold;
extern struct threshold bio_io_threshold[2];

#include <linux/blkdev.h>

struct bio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	struct bio *bio;
	struct bio_output *output;
	unsigned long long start_stamp;
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
	atomic_t queue_count[MARS_PRIO_NR];
	atomic_t completed_count;
	atomic_t total_completed_count[MARS_PRIO_NR];
	// private
	spinlock_t lock;
	struct list_head queue_list[MARS_PRIO_NR];
	struct list_head submitted_list[2];
	struct list_head completed_list;
	wait_queue_head_t submit_event;
	wait_queue_head_t response_event;
	struct mapfree_info *mf;
	struct block_device *bdev;
	brick_thread_t *submit_thread;
	brick_thread_t *response_thread;
	int bvec_max;
	bool submitted;
};

struct bio_input {
	MARS_INPUT(bio);
};

struct bio_output {
	MARS_OUTPUT(bio);
};

MARS_TYPES(bio);

#endif
