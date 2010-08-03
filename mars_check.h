// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_CHECK_H
#define MARS_CHECK_H

struct check_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
	struct list_head mio_head;
	int (*old_mars_endio)(struct mars_io_object *mio, int error);
	void *old_private;
	unsigned long last_jiffies;
};

struct check_mars_buf_aspect {
	GENERIC_ASPECT(mars_buf);
	struct list_head mbuf_head;
	void (*old_buf_endio)(struct mars_buf_object *mbuf);
	void *old_private;
	unsigned long last_jiffies;
};

struct check_brick {
	MARS_BRICK(check);
};

struct check_input {
	MARS_INPUT(check);
};

struct check_output {
	MARS_OUTPUT(check);
	spinlock_t lock;
	int instance_nr;
	struct task_struct *watchdog;
	struct list_head mio_anchor;
	struct list_head mbuf_anchor;
};

MARS_TYPES(check);

#endif
