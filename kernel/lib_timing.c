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


#include "lib_timing.h"

#include <linux/kernel.h>
#include <linux/module.h>

#ifdef CONFIG_MARS_DEBUG

int report_timing(struct timing_stats *tim, char *str, int maxlen)
{
	int len = 0;
	int time = 1;
	int resol = 1;
	static const char *units[] = {
		"us",
		"ms",
		"s",
		"ERROR"
	};
	const char *unit = units[0];
	int unit_index = 0;
	int i;

	for (i = 0; i < TIMING_MAX; i++) {
		int this_len = scnprintf(str, maxlen, "<%d%s = %d (%lld) ", resol, unit, tim->tim_count[i], (long long)tim->tim_count[i] * time);
		str += this_len;
		len += this_len;
		maxlen -= this_len;
		if (maxlen <= 1)
			break;
		resol <<= 1;
		time <<= 1;
		if (resol >= 1000) {
			resol = 1;
			unit = units[++unit_index];
		}
	}
	return len;
}
EXPORT_SYMBOL_GPL(report_timing);

#endif

struct threshold global_io_threshold = {
	.thr_limit = 30 * 1000000, // 30 seconds
	.thr_factor = 100,
	.thr_plus = 0,
};
EXPORT_SYMBOL_GPL(global_io_threshold);

