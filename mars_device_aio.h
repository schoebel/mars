// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_DEVICE_AIO_H
#define MARS_DEVICE_AIO_H

#include <linux/aio.h>
#include <linux/syscalls.h>

struct device_aio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	int resubmit;
	bool do_dealloc;
};

struct device_aio_brick {
	MARS_BRICK(device_aio);
};

struct device_aio_input {
	MARS_INPUT(device_aio);
};

struct aio_threadinfo {
	struct list_head mref_list;
	struct device_aio_output *output;
	struct task_struct *thread;
	struct mm_struct *mm;
	wait_queue_head_t event;
	spinlock_t lock;
};

struct device_aio_output {
	MARS_OUTPUT(device_aio);
	// parameters
	bool o_direct;
	bool o_fdsync;
        // private
	struct file *filp;
	int fd; // FIXME: remove this!
	struct aio_threadinfo tinfo[3];
	aio_context_t ctxp;
};

MARS_TYPES(device_aio);

#endif
