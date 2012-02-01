// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_AIO_H
#define MARS_AIO_H

#include <linux/aio.h>
#include <linux/syscalls.h>

//#define USE_CLEVER_SYNC // TODO: NYI (should result in better write performance)
#ifdef USE_CLEVER_SYNC

#include "lib_pairing_heap.h"

_PAIRING_HEAP_TYPEDEF(sync,);

struct q_sync {
	struct pairing_heap_sync *heap[MARS_PRIO_NR];
};

#endif

struct aio_mref_aspect {
	GENERIC_ASPECT(mref);
#ifdef USE_CLEVER_SYNC
	struct pairing_heap_sync heap_head;
#endif
	struct list_head io_head;
	long long start_jiffies;
	int resubmit;
	int alloc_len;
	bool do_dealloc;
};

struct aio_brick {
	MARS_BRICK(aio);
	// parameters
	int readahead;
	bool o_direct;
	bool o_fdsync;
	bool wait_during_fdsync;
};

struct aio_input {
	MARS_INPUT(aio);
};

struct aio_threadinfo {
	struct list_head mref_list[MARS_PRIO_NR];
	struct aio_output *output;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
	bool terminated;
	atomic_t total_enqueue_count;
	atomic_t total_dequeue_count;
};

struct aio_output {
	MARS_OUTPUT(aio);
        // private
	struct file *filp;
	int fd; // FIXME: remove this!
	struct aio_threadinfo tinfo[3];
	aio_context_t ctxp;
	wait_queue_head_t fdsync_event;
	bool fdsync_active;
	// statistics
	atomic_t total_read_count;
	atomic_t total_write_count;
	atomic_t total_alloc_count;
	atomic_t total_delay_count;
	atomic_t total_msleep_count;
	atomic_t total_fdsync_count;
	atomic_t total_fdsync_wait_count;
	atomic_t read_count;
	atomic_t write_count;
	atomic_t alloc_count;
};

MARS_TYPES(aio);

#endif
