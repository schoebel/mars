// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_COPY_H
#define MARS_COPY_H

#include <linux/wait.h>
#include <linux/semaphore.h>

#define INPUT_A_IO   0
#define INPUT_A_COPY 1
#define INPUT_B_IO   2
#define INPUT_B_COPY 3

//#define COPY_CHUNK      (64 * 1024)
#define COPY_CHUNK      PAGE_SIZE
#define MAX_COPY_PARA   (10 * 1024 * 1024 / COPY_CHUNK)

enum {
	COPY_STATE_START = 0,
	COPY_STATE_READ1 = 1,
	COPY_STATE_READ2 = 2,
	COPY_STATE_WRITE,
	COPY_STATE_CLEANUP,
};

struct copy_mref_aspect {
	GENERIC_ASPECT(mref);
	struct copy_brick *brick;
	int queue;
};

struct copy_brick {
	MARS_BRICK(copy);
	// parameters
	volatile loff_t copy_start;
	volatile loff_t copy_end; // stop working if == 0
	int io_prio;
	int append_mode; // 1 = passively, 2 = actively
	bool verify_mode;
	bool utilize_mode; // utilize already copied data
	// readonly from outside
	loff_t copy_last;
	bool low_dirty;
	// internal
	volatile bool trigger;
	volatile unsigned long clash;
	atomic_t io_flight;
	atomic_t copy_flight;
	long long last_jiffies;
	wait_queue_head_t event;
	struct semaphore mutex;
	struct task_struct *thread;
	char state[MAX_COPY_PARA];
	struct mref_object *table[MAX_COPY_PARA][2];
	struct generic_object_layout mref_object_layout;
};

struct copy_input {
	MARS_INPUT(copy);
};

struct copy_output {
	MARS_OUTPUT(copy);
};

MARS_TYPES(copy);

#endif
