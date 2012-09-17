// (c) 2012 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef MARS_LIB_LIMITER_H
#define MARS_LIB_LIMITER_H

#include <linux/utsname.h>

#define LIMITER_TIME_RESOLUTION NSEC_PER_SEC

struct mars_limiter {
	/* tunables */
	int lim_max_rate;
	/* internal */
	int lim_accu;
	unsigned long long lim_stamp;
};

extern inline
int mars_limit(struct mars_limiter *lim, int amount)
{
	int res = 0;
	unsigned long long now;

	now = cpu_clock(raw_smp_processor_id());

	if (lim->lim_max_rate > 0 && likely(lim->lim_stamp)) {
		long long elapsed = now - lim->lim_stamp;
		long long rate;

		/* Races are possible, but taken into account.
		 * There is no real harm from rarely lost updates.
		 */
		lim->lim_accu += amount;

		rate = (long long)lim->lim_accu * LIMITER_TIME_RESOLUTION / elapsed;

		if (rate > lim->lim_max_rate) {
			res = 1001 - lim->lim_max_rate * 1000 / rate;
		}

		elapsed -= LIMITER_TIME_RESOLUTION * 2;
		if (elapsed > LIMITER_TIME_RESOLUTION) {
			lim->lim_stamp += elapsed;
			if (lim->lim_accu > 0)
				lim->lim_accu -= (long long)lim->lim_max_rate * elapsed / LIMITER_TIME_RESOLUTION;
		}
	} else {
		lim->lim_accu = amount;
		lim->lim_stamp = now;
	}
	return res;
}

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
