/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2014 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2014 1&1 Internet AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "lib_limiter.h"
#include "lamport.h"

#include <linux/kernel.h>
#include <linux/module.h>

/* For precisions, _internal_ time is in multiples of the following basic time units */

#define LIMITER_TIME_RESOLUTION NSEC_PER_SEC

#define DEFAULT_MIN_WINDOW (LIMITER_TIME_RESOLUTION * 1)
#define DEFAULT_MAX_WINDOW (LIMITER_TIME_RESOLUTION * 4)

#define MIN_DIVIDER        (DEFAULT_MIN_WINDOW / 10)
#define MAX_DIVIDER        (DEFAULT_MAX_WINDOW * 10)

#define CLAMP_WINDOW(x)					\
	(x) < MIN_DIVIDER ? MIN_DIVIDER :		\
	(x) > MAX_DIVIDER ? MAX_DIVIDER :		\
	    (x)

#define MS_TO_TR(x)         ((__s64)(x) * (LIMITER_TIME_RESOLUTION / 1000))
#define TR_TO_MS(x)         ((x) / (LIMITER_TIME_RESOLUTION / 1000))

int mars_limit(struct mars_limiter *lim, int amount)
{
	int delay = 0;
	struct lamport_time now;

	if (unlikely(amount < 0))
		amount = 0;

	get_real_lamport(&now);

	/* Compute the maximum delay along the path
	 * down to the root of the hierarchy tree.
	 */
	while (lim != NULL) {
		struct lamport_time diff = lamport_time_sub(now, lim->lim_stamp);
		__s64 window = lamport_time_to_ns(&diff);
		__s64 rate_raw;
		int rate;
		int max_rate;

		/* Sometimes, raw CPU clocks may do weired things...
		 * Small windows in the denominator could fake unrealistic rates.
		 * Do not divide by too small numbers.
		 */
		window = CLAMP_WINDOW(window);

		if (unlikely(lim->lim_min_window_ms <= TR_TO_MS(MAX_DIVIDER)))
			lim->lim_min_window_ms = TR_TO_MS(DEFAULT_MIN_WINDOW);
		if (unlikely(lim->lim_max_window_ms <= lim->lim_min_window_ms))
			lim->lim_max_window_ms = lim->lim_min_window_ms + TR_TO_MS(DEFAULT_MAX_WINDOW);

		/* Update total statistics.
		 * They will intentionally wrap around.
		 * Userspace must take care of that.
		 */
		if (likely(amount > 0)) {
			lim->lim_total_amount += amount;
			lim->lim_total_ops++;
		}

		/* Only use incremental accumulation at repeated calls, but
		 * never after longer pauses.
		 */
		if (!lim->lim_stamp.tv_sec ||
		    window > MS_TO_TR(lim->lim_max_window_ms)) {
			/* reset, start over with new measurement cycle */
			memset(&diff, 0, sizeof(diff));
			lim->lim_stamp = now;
			lim->lim_ops_accu = 0;
			lim->lim_amount_accu = 0;
			lim->lim_ops_rate = 0;
			lim->lim_amount_rate = 0;
			window = MIN_DIVIDER;
		} else {
			__s64 diff_window;

			/* Try to keep the window between min_window and 2 * min_window.
			 * We wait until min_window has been exceeded _twice_,
			 * and then reduce the window by only 1 * min_window.
			 */
			diff_window = window - MS_TO_TR(lim->lim_min_window_ms);
			if (diff_window > MS_TO_TR(lim->lim_min_window_ms)) {
				__s64 used_up;
				__s64 add_window = 0;

				used_up = lim->lim_amount_accu * diff_window / window;
				if (used_up > 0) {
					add_window = diff_window;
					lim->lim_amount_accu -= used_up;
					if (unlikely(lim->lim_amount_accu < 0))
						lim->lim_amount_accu = 0;
				}

				used_up = lim->lim_ops_accu * diff_window / window;
				if (used_up > 0) {
					if (diff_window > add_window)
						add_window = diff_window;
					lim->lim_ops_accu -= used_up;
					if (unlikely(lim->lim_ops_accu < 0))
						lim->lim_ops_accu = 0;
				}
  
				if (add_window > 0) {
					lamport_time_add_ns(&lim->lim_stamp, add_window);
					/* recompute the new window */
					diff = lamport_time_sub(now, lim->lim_stamp);
					window = lamport_time_to_ns(&diff);
					window = CLAMP_WINDOW(window);
				}
			}
		}

		/* Races are possible, but taken into account.
		 * There is no real harm from rarely lost updates.
		 */
		if (likely(amount > 0)) {
			lim->lim_amount_accu += amount;
			lim->lim_ops_accu++;
		}

		/* compute amount values */
		rate_raw = lim->lim_amount_accu * LIMITER_TIME_RESOLUTION / window;
		rate = rate_raw;
		if (unlikely(rate_raw > INT_MAX)) {
			rate = INT_MAX;
		}
		lim->lim_amount_rate = rate;

		/* amount limit exceeded? */
		max_rate = lim->lim_max_amount_rate;
		if (max_rate > 0 && rate > max_rate) {
			int this_delay = (window * rate / max_rate - window);

			// compute maximum
			if (this_delay > delay && this_delay > 0)
				delay = this_delay;
		}

		/* compute ops values */
		rate_raw = lim->lim_ops_accu * LIMITER_TIME_RESOLUTION / window;
		rate = rate_raw;
		if (unlikely(rate_raw > INT_MAX)) {
			rate = INT_MAX;
		}
		lim->lim_ops_rate = rate;

		/* ops limit exceeded? */
		max_rate = lim->lim_max_ops_rate;
		if (max_rate > 0 && rate > max_rate) {
			int this_delay = (window * rate / max_rate - window);

			// compute maximum
			if (this_delay > delay && this_delay > 0)
				delay = this_delay;
		}

		lim = lim->lim_father;
	}
	return TR_TO_MS(delay);
}

void mars_limit_sleep(struct mars_limiter *lim, int amount)
{
	int sleep = mars_limit(lim, amount);

	if (sleep > 0) {
		if (unlikely(lim->lim_max_delay_ms <= 0))
			lim->lim_max_delay_ms = 1000;
		if (sleep > lim->lim_max_delay_ms)
			sleep = lim->lim_max_delay_ms;
		brick_msleep(sleep);
	}
}

void mars_limit_reset(struct mars_limiter *lim)
{
	if (!lim)
		return;
	memset(&lim->lim_stamp, 0, sizeof(lim->lim_stamp));
	mars_limit(lim, 0);
}
