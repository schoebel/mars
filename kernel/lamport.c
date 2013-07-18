// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>

#include "lamport.h"


struct semaphore lamport_sem = __SEMAPHORE_INITIALIZER(lamport_sem, 1); // TODO: replace with spinlock if possible (first check)
struct timespec lamport_now = {};

void get_lamport(struct timespec *now)
{
	int diff;

	down(&lamport_sem);

	*now = CURRENT_TIME;
	diff = timespec_compare(now, &lamport_now);
	if (diff >= 0) {
		timespec_add_ns(now, 1);
		memcpy(&lamport_now, now, sizeof(lamport_now));
		timespec_add_ns(&lamport_now, 1);
	} else {
		timespec_add_ns(&lamport_now, 1);
		memcpy(now, &lamport_now, sizeof(*now));
	}

	up(&lamport_sem);
}

EXPORT_SYMBOL_GPL(get_lamport);

void set_lamport(struct timespec *old)
{
	int diff;

	down(&lamport_sem);

	diff = timespec_compare(old, &lamport_now);
	if (diff >= 0) {
		memcpy(&lamport_now, old, sizeof(lamport_now));
		timespec_add_ns(&lamport_now, 1);
	}

	up(&lamport_sem);
}
EXPORT_SYMBOL_GPL(set_lamport);
