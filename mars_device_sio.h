// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_DEVICE_SIO_H
#define MARS_DEVICE_SIO_H

#define WITH_THREAD 16

struct device_sio_mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
	struct list_head io_head;
};

struct device_sio_brick {
	MARS_BRICK(device_sio);
};

struct device_sio_input {
	MARS_INPUT(device_sio);
};

struct sio_threadinfo {
	struct device_sio_output *output;
	struct list_head mref_list;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
	unsigned long last_jiffies;
};

struct device_sio_output {
	MARS_OUTPUT(device_sio);
	struct file *filp;
	struct sio_threadinfo tinfo[WITH_THREAD+1];
	spinlock_t g_lock;
	int index;
};

MARS_TYPES(device_sio);

#endif
