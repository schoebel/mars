/*
 * MARS Long Distance Replication Software
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
 */

#ifndef LIB_LIMITER_H
#define LIB_LIMITER_H

#include <linux/utsname.h>

struct rate_limiter {
	/* hierarchy tree */
	struct rate_limiter *lim_father;

	/* tunables */
	int lim_max_rate;
	int lim_max_delay;
	int lim_min_window;
	int lim_max_window;

	/* readable */
	int lim_rate;
	int lim_cumul;
	int lim_count;
	int lim_total_ops;
	int lim_total_sum;
	long long lim_stamp;

	/* internal */
	long long lim_accu;
};

extern int rate_limit(struct rate_limiter *lim, int amount);

extern void rate_limit_sleep(struct rate_limiter *lim, int amount);

#endif
