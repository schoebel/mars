// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef LAMPORT_H
#define LAMPORT_H

#include <linux/time.h>

extern void get_lamport(struct timespec *now);
extern void set_lamport(struct timespec *old);

#endif
