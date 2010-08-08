// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_CHECK_H
#define MARS_CHECK_H

//#define CHECK_LOCK

struct check_mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
#ifdef CHECK_LOCK
	struct list_head mref_head;
#endif
	void (*old_buf_endio)(struct mars_ref_object *mref);
	void *old_private;
	unsigned long last_jiffies;
	int call_count;
};

struct check_brick {
	MARS_BRICK(check);
};

struct check_input {
	MARS_INPUT(check);
};

struct check_output {
	MARS_OUTPUT(check);
	int instance_nr;
	struct task_struct *watchdog;
#ifdef CHECK_LOCK
	spinlock_t check_lock;
	struct list_head mio_anchor;
	struct list_head mref_anchor;
#endif
};

MARS_TYPES(check);

#endif
