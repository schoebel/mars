// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_DEVICE_SIO_H
#define MARS_DEVICE_SIO_H

#define WITH_THREAD 16

struct device_sio_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
	struct list_head io_head;
};

struct device_sio_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
};

struct device_sio_mars_buf_callback_aspect {
	GENERIC_ASPECT(mars_buf_callback);
};

struct device_sio_brick {
	MARS_BRICK(device_sio);
};

struct device_sio_input {
	MARS_INPUT(device_sio);
};

#ifdef WITH_THREAD
struct sio_threadinfo {
	struct device_sio_output *output;
	struct list_head mio_list;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
};
#endif

struct device_sio_output {
	MARS_OUTPUT(device_sio);
	struct file *filp;
#ifdef WITH_THREAD
	struct sio_threadinfo tinfo[WITH_THREAD+1];
	spinlock_t g_lock;
	int index;
#endif
};

MARS_TYPES(device_sio);

#endif
