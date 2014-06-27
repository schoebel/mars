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

// (c) 2012 Thomas Schoebel-Theuer

//#define BRICK_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>

#include "lib_rank.h"

void ranking_compute(struct rank_data *rkd, const struct rank_info rki[], int x)
{
	int points = 0;
	int i;
	
	for (i = 0; ; i++) {
		int x0;
		int x1;
		int y0;
		int y1;
		
		x0 = rki[i].rki_x;
		if (x < x0)
			break;

		x1 = rki[i+1].rki_x;

		if (unlikely(x1 == RKI_DUMMY)) {
			points = rki[i].rki_y;
			break;
		}

		if (x > x1)
			continue;
		
		y0 = rki[i].rki_y;
		y1 = rki[i+1].rki_y;

		// linear interpolation
		points = ((long long)(x - x0) * (long long)(y1 - y0)) / (x1 - x0) + y0;
		break;
	}
	rkd->rkd_tmp += points;
}
EXPORT_SYMBOL_GPL(ranking_compute);

int ranking_select(struct rank_data rkd[], int rkd_count)
{
	int res = -1;
	long long max = LLONG_MIN / 2;
	int i;

	for (i = 0; i < rkd_count; i++) {
		struct rank_data *tmp = &rkd[i];
		long long rest = tmp->rkd_current_points;
		if (rest <= 0)
			continue;
		//rest -= tmp->rkd_got;
		if (rest > max) {
			max = rest;
			res = i;
		}
	}
	/* Prevent underflow in the long term
	 * and reset the "clocks" after each round of
	 * weighted round-robin selection.
	 */
	if (max < 0 && res >= 0) {
		for (i = 0; i < rkd_count; i++)
			rkd[i].rkd_got += max;
	}
	return res;
}
EXPORT_SYMBOL_GPL(ranking_select);
