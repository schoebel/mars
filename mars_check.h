// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_CHECK_H
#define MARS_CHECK_H

#define CHECK_LOCK

struct check_mars_ref_aspect {
	GENERIC_ASPECT(mars_ref);
#ifdef CHECK_LOCK
	struct list_head mref_head;
#endif
	struct generic_callback cb;
	struct check_output *output;
	unsigned long last_jiffies;
	atomic_t call_count;
	atomic_t callback_count;
	bool installed;
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
#ifdef CHECK_LOCK
	struct task_struct *watchdog;
	spinlock_t check_lock;
	struct list_head mref_anchor;
#endif
};

MARS_TYPES(check);

#endif
