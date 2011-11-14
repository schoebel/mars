// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_SIO_H
#define MARS_SIO_H

#define WITH_THREAD 16

struct sio_mref_aspect {
	GENERIC_ASPECT(mref);
	struct list_head io_head;
	int alloc_len;
	bool do_dealloc;
};

struct sio_brick {
	MARS_BRICK(sio);
	// parameters
	bool o_direct;
	bool o_fdsync;
};

struct sio_input {
	MARS_INPUT(sio);
};

struct sio_threadinfo {
	struct sio_output *output;
	struct list_head mref_list;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
	unsigned long last_jiffies;
};

struct sio_output {
	MARS_OUTPUT(sio);
        // private
	struct file *filp;
	struct sio_threadinfo tinfo[WITH_THREAD+1];
	spinlock_t g_lock;
	int index;
};

MARS_TYPES(sio);

#endif
