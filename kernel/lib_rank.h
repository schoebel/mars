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

#ifndef LIB_RANK_H
#define LIB_RANK_H

/* Generic round-robin scheduler based on ranking information.
 */

#define RKI_DUMMY INT_MIN

struct rank_info {
	int rki_x;
	int rki_y;
};

struct rank_data {
	// public readonly
	long long rkd_current_points;
	// private
	long long rkd_tmp;
	long long rkd_got;
};

/* Ranking phase.
 *
 * Calls should follow the following usage pattern:
 *
 *     ranking_start(...);
 *     for (...) {
 *             ranking_compute(&rkd[this_time], ...);
 *             // usually you need at least 1 call for each rkd[] element,
 *             // but you can call more often to include ranking information
 *             // from many different sources.
 *             // Note: instead / additionally, you may also use
 *             // ranking_add() or ranking_override().
 *     }
 *     ranking_stop(...);
 *
 * => now the new ranking values are computed and already active
 * for the round-robin ranking_select() mechanism described below.
 *
 * Important: the rki[] array describes a ranking function at some
 * example points (x_i,y_i) which must be ordered according to x_i
 * in ascending order. And, of course, you need to supply at least
 * two sample points (otherwise a linear function cannot
 * be described).
 * The array _must_ always end with a dummy record where the x_i has the
 * value RKI_DUMMY.
 */

extern inline
void ranking_start(struct rank_data rkd[], int rkd_count)
{
	int i;
	for (i = 0; i < rkd_count; i++) {
		rkd[i].rkd_tmp = 0;
	}
}

extern void ranking_compute(struct rank_data *rkd, const struct rank_info rki[], int x);

/* This may be used to (exceptionally) add some extra salt...
 */
extern inline
void ranking_add(struct rank_data *rkd, int y)
{
	rkd->rkd_tmp += y;
}

/* This may be used to (exceptionally) override certain ranking values.
 */
extern inline
void ranking_override(struct rank_data *rkd, int y)
{
	rkd->rkd_tmp = y;
}

extern inline
void ranking_stop(struct rank_data rkd[], int rkd_count)
{
	int i;
	for (i = 0; i < rkd_count; i++) {
		rkd[i].rkd_current_points = rkd[i].rkd_tmp;
	}
}


/* This is a round-robin scheduler taking her weights
 * from the previous ranking phase (the more ranking points,
 * the more frequently a candidate will be selected).
 *
 * Typical usage pattern (independent from the above ranking phase
 * usage pattern):
 *
 *    while (__there_is_work_to_be_done(...)) {
 *            int winner = ranking_select(...);
 *            if (winner >= 0) {
 *                    __do_something(winner);
 *                    ranking_select_done(..., winner, 1); // or higher, winpoints >= 1 must hold
 *            }
 *            ...
 *    }
 *
 */

extern int ranking_select(struct rank_data rkd[], int rkd_count);

extern inline
void ranking_select_done(struct rank_data rkd[], int winner, int win_points)
{
	if (winner >= 0) {
		if (win_points < 1)
			win_points = 1;
		rkd[winner].rkd_got += win_points;
	}
}

#endif
