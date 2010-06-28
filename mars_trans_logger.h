// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_TRANS_LOGGER_H
#define MARS_TRANS_LOGGER_H

struct trans_logger_mars_io_aspect {
	GENERIC_ASPECT(mars_io);
	struct list_head io_head;
};

struct trans_logger_brick {
	MARS_BRICK(trans_logger);
};

struct trans_logger_input {
	MARS_INPUT(trans_logger);
};

struct trans_logger_output {
	MARS_OUTPUT(trans_logger);
	int aspect_slot;
	struct list_head mio_list;
	struct task_struct *thread;
	wait_queue_head_t event;
	spinlock_t lock;
};

MARS_TYPES(trans_logger);

#endif
