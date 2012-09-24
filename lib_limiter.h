// (c) 2012 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_LIB_LIMITER_H
#define MARS_LIB_LIMITER_H

#include "brick.h"

#include <linux/utsname.h>

#define LIMITER_TIME_RESOLUTION NSEC_PER_SEC

struct mars_limiter {
	/* hierarchy tree */
	struct mars_limiter *lim_father;
	/* tunables */
	int lim_max_rate;
	/* readable */
	int lim_rate;
	unsigned long long lim_stamp;
	/* internal */
	int lim_accu;
};

extern int mars_limit(struct mars_limiter *lim, int amount);

extern inline
void mars_limit_sleep(struct mars_limiter *lim, int amount)
{
	int sleep = mars_limit(lim, amount);
	if (sleep > 0) {
		if (sleep > 1000)
			sleep = 1000;
		brick_msleep(sleep);
	}
}

#endif
