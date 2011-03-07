// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_AIO_H
#define MARS_AIO_H

#include <linux/aio.h>
#include <linux/syscalls.h>

struct aio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	long long timeout;
	int resubmit;
	bool do_dealloc;
};

struct aio_brick {
	MARS_BRICK(aio);
};

struct aio_input {
	MARS_INPUT(aio);
};

struct aio_threadinfo {
	struct list_head mref_list;
	struct list_head delay_list;
	struct aio_output *output;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
	bool terminated;
};

struct aio_output {
	MARS_OUTPUT(aio);
	// parameters
	bool o_direct;
	bool o_fdsync;
        // private
	struct file *filp;
	int fd; // FIXME: remove this!
	struct aio_threadinfo tinfo[3];
	aio_context_t ctxp;
};

MARS_TYPES(aio);

#endif
