/*
 * MARS Long Distance Replication Software
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef XIO_BIO_H
#define XIO_BIO_H

#define BIO_SUBMIT_MAX_LATENCY		250 /*	250 us */
#define BIO_IO_R_MAX_LATENCY		40000 /*   40 ms */
#define BIO_IO_W_MAX_LATENCY		100000 /*  100 ms */

extern struct threshold bio_submit_threshold;
extern struct threshold bio_io_threshold[2];

#include <linux/blkdev.h>

struct bio_aio_aspect {
	GENERIC_ASPECT(aio);
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
	XIO_BRICK(bio);
	/*  tunables */
	int ra_pages;
	int bg_threshold;
	int bg_maxfly;
	bool do_noidle;
	bool do_sync;
	bool do_unplug;

	/*  readonly */
	loff_t total_size;
	atomic_t fly_count[XIO_PRIO_NR];
	atomic_t queue_count[XIO_PRIO_NR];
	atomic_t completed_count;
	atomic_t total_completed_count[XIO_PRIO_NR];

	/*  private */
	spinlock_t lock;
	struct list_head queue_list[XIO_PRIO_NR];
	struct list_head submitted_list[2];
	struct list_head completed_list;

	wait_queue_head_t submit_event;
	wait_queue_head_t response_event;
	struct mapfree_info *mf;
	struct block_device *bdev;
	struct task_struct *submit_thread;
	struct task_struct *response_thread;
	int bvec_max;
	bool submitted;
};

struct bio_input {
	XIO_INPUT(bio);
};

struct bio_output {
	XIO_OUTPUT(bio);
};

XIO_TYPES(bio);

#endif
