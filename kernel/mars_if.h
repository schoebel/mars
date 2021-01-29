/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef MARS_IF_H
#define MARS_IF_H

#include "lib_limiter.h"

#include <linux/semaphore.h>

#define MARS_MAX_SEGMENT_SIZE (PAGE_SIZE)

#define MAX_BIO 32

//#define USE_TIMER (HZ/10) // use this ONLY for debugging

///////////////////////// global tuning ////////////////////////

extern int if_nr_requests;
extern int if_throttle_start_size; // in kb
extern struct mars_limiter if_throttle;

/////////////////////////////////////////////////

/* I don't want to enhance / intrude into struct bio for compatibility reasons
 * (support for a variety of kernel versions).
 * The following is just a silly workaround which could be removed again.
 */
struct bio_wrapper {
	struct bio *bio;
	atomic_t bi_comp_cnt;
	unsigned long start_time;
};

struct if_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head plug_head;
	struct list_head hash_head;
	int hash_index;
	int bio_count;
	int current_len;
	int max_len;
	struct page *orig_page;
	struct bio_wrapper *orig_biow[MAX_BIO];
	struct if_input *input;
};

struct if_hash_anchor;

struct if_input {
	MARS_INPUT(if);
	// TODO: move this to if_brick (better systematics)
	struct list_head plug_anchor;
	struct request_queue *q;
	struct gendisk *disk;
	struct block_device *bdev;
#ifdef USE_TIMER
	struct timer_list timer;
#endif
	loff_t capacity;
	atomic_t plugged_count;
	/* debugging statistics */
#ifdef CONFIG_MARS_DEBUG
	atomic_t total_reada_count;
	atomic_t total_read_count;
	atomic_t total_write_count;
	atomic_t total_empty_count;
	atomic_t total_fire_count;
	atomic_t total_skip_sync_count;
	atomic_t total_mref_read_count;
	atomic_t total_mref_write_count;
#endif
	/* private */
#ifdef MARS_HAS_OLD_QUEUE_LOCK
	spinlock_t req_lock;
#endif
	struct semaphore kick_sem;
	struct if_hash_anchor *hash_table;
};

struct if_output {
	MARS_OUTPUT(if);
};

struct if_brick {
	MARS_BRICK(if);
	// parameters
	loff_t dev_size;
	int max_plugged;
	int readahead;
	bool skip_sync;
	// inspectable
	atomic_t open_count;
	atomic_t read_flying_count;
	atomic_t write_flying_count;
	struct lamport_time completion_stamp;
	struct mars_limiter io_limiter;
	int error_code;
	// private
	struct semaphore switch_sem;
	struct say_channel *say_channel;
	struct mars_info info;
};

MARS_TYPES(if);

#endif
