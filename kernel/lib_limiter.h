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

#ifndef MARS_LIB_LIMITER_H
#define MARS_LIB_LIMITER_H

#include "brick.h"
#include "lamport.h"

#include <linux/utsname.h>

struct mars_limiter {
	/* hierarchy tree */
	struct mars_limiter *lim_father;
	/* tunables */
	int lim_max_ops_rate;
	int lim_max_amount_rate;
	int lim_max_delay;
	int lim_min_window;
	int lim_max_window;
	/* readable */
	int lim_ops_rate;
	int lim_amount_rate;
	int lim_ops_cumul;
	int lim_amount_cumul;
	int lim_total_ops;
	int lim_total_amount;
	struct lamport_time lim_stamp;
	/* internal */
	long long lim_ops_accu;
	long long lim_amount_accu;
};

extern int mars_limit(struct mars_limiter *lim, int amount);

extern void mars_limit_sleep(struct mars_limiter *lim, int amount);

void mars_limit_reset(struct mars_limiter *lim);

#endif
