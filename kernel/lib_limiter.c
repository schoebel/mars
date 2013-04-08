// (c) 2012 Thomas Schoebel-Theuer / 1&1 Internet AG

#include "lib_limiter.h"

#include <linux/kernel.h>
#include <linux/module.h>

int mars_limit(struct mars_limiter *lim, int amount)
{
	int delay = 0;
	long long now;

	now = cpu_clock(raw_smp_processor_id());

	/* Compute the maximum delay along the path
	 * down to the root of the hierarchy tree.
	 */
	while (lim != NULL) {
		if (likely(lim->lim_stamp)) {
			long long elapsed = now - lim->lim_stamp;
			int rate;
			
			/* Races are possible, but taken into account.
			 * There is no real harm from rarely lost updates.
			 */
			if (likely(amount > 0))
				lim->lim_accu += amount;
			
			rate = (long long)lim->lim_accu * LIMITER_TIME_RESOLUTION / elapsed;
			lim->lim_rate = rate;
			
			// limit exceeded?
			if (lim->lim_max_rate > 0 && rate > lim->lim_max_rate) {
				int this_delay = 1000 - (long long)lim->lim_max_rate * 1000 / rate;
				// compute maximum
				if (this_delay > delay)
					delay = this_delay;
			}
			
			elapsed -= LIMITER_TIME_RESOLUTION * 2;
			if (elapsed > LIMITER_TIME_RESOLUTION) {
				lim->lim_stamp += elapsed;
				if (lim->lim_accu > 0) {
					lim->lim_accu -= (long long)lim->lim_max_rate * elapsed / LIMITER_TIME_RESOLUTION;
				}
			}
		} else {
			if (unlikely(amount < 0))
				amount = 0;
			lim->lim_accu = amount;
			lim->lim_stamp = now;
			lim->lim_rate = 0;
		}
		lim = lim->lim_father;
	}
	return delay;
}
EXPORT_SYMBOL_GPL(mars_limit);
