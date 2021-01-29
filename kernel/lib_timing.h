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

#ifndef MARS_LIB_TIMING_H
#define MARS_LIB_TIMING_H

#include "brick.h"
#include "lamport.h"

#include <linux/sched.h>

/* Simple infrastructure for timing of arbitrary operations and creation
 * of some simple histogram statistics.
 */

#define TIMING_MAX 24

struct timing_stats {
#ifdef CONFIG_MARS_DEBUG
	int tim_count[TIMING_MAX];
#endif
};

#define _TIME_THIS(_stamp1, _stamp2, _CODE)				\
	({								\
		struct lamport_time __tmp_diff;				\
									\
		get_real_lamport(&(_stamp1));				\
									\
		_CODE;							\
									\
		 get_real_lamport(&(_stamp2));				\
		__tmp_diff = lamport_time_sub((_stamp2), (_stamp1));	\
		lamport_time_to_ns(&__tmp_diff);			\
	})


#define TIME_THIS(_CODE)						\
	({								\
		struct lamport_time _stamp1;				\
		struct lamport_time _stamp2;				\
		_TIME_THIS(_stamp1, _stamp2, _CODE);			\
	})


#ifdef CONFIG_MARS_DEBUG

#define _TIME_STATS(_timing, _stamp1, _stamp2, _CODE)			\
	({								\
		s64 _time;						\
		s64 _tmp;						\
		int _i;							\
									\
		_time = _TIME_THIS(_stamp1, _stamp2, _CODE);		\
									\
		_tmp = _time / 1000;	/* convert to us */		\
		_i = 0;							\
		while (_tmp > 0 && _i < TIMING_MAX - 1) {		\
			_tmp >>= 1;					\
			_i++;						\
		}							\
		(_timing)->tim_count[_i]++;				\
		_time;							\
	})

#define TIME_STATS(_timing, _CODE)					\
	({								\
		struct lamport_time _stamp1;				\
		struct lamport_time _stamp2;				\
		_TIME_STATS(_timing, _stamp1, _stamp2, _CODE);		\
	})

extern int report_timing(struct timing_stats *tim, char *str, int maxlen);

#else  // CONFIG_MARS_DEBUG

#define _TIME_STATS(_timing, _stamp1, _stamp2, _CODE)			\
	((void)_timing, get_real_lamport(&(_stamp1)), (_stamp1) = (_stamp2), _CODE, 0)

#define TIME_STATS(_timing, _CODE)		\
	((void)_timing, _CODE, 0)

#define report_timing(tim,str,maxlen)   ((void)tim, 0)

#endif // CONFIG_MARS_DEBUG

/* A banning represents some overloaded resource.
 *
 * Whenever overload is detected, you should call banning_hit()
 * telling that the overload is assumed / estimated to continue
 * for some duration in time.
 *
 * ATTENTION! These operations are deliberately raceful.
 * They are meant to deliver _hints_ (e.g. for IO scheduling
 * decisions etc), not hard facts!
 *
 * If you need locking, just surround these operations
 * with locking by yourself.
 */
struct banning {
	struct lamport_time ban_last_hit;
	// statistical
	int ban_renew_count;
	int ban_count;
	bool ban_hit;
};

static inline
bool banning_hit(struct banning *ban, long long duration)
{
	struct lamport_time now;
	struct lamport_time new_hit;
	bool hit;

	get_real_lamport(&now);
	hit = lamport_time_compare(&ban->ban_last_hit, &now) >= 0;
	new_hit = now;
	lamport_time_add_ns(&new_hit, duration);
	ban->ban_renew_count++;
	ban->ban_hit = true;
	if (!lamport_time_to_ns(&ban->ban_last_hit) ||
	    lamport_time_compare(&ban->ban_last_hit, &new_hit) < 0) {
		ban->ban_last_hit = new_hit;
		ban->ban_count++;
	}
	return hit;
}

static inline
bool banning_is_hit(struct banning *ban)
{
	struct lamport_time now;

	/* always report at least once after a hit */
	if (ban->ban_hit) {
		ban->ban_hit = false;
		return true;
	}

	get_real_lamport(&now);
	return lamport_time_compare(&ban->ban_last_hit, &now) >= 0 &&
	  lamport_time_to_ns(&ban->ban_last_hit);
}

extern inline
void banning_reset(struct banning *ban)
{
	memset(&ban->ban_last_hit, 0, sizeof(ban->ban_last_hit));
}

/* Threshold: trigger a banning whenever some latency threshold
 * is exceeded.
 */
struct threshold {
	struct banning *thr_ban;
	struct threshold *thr_parent; /* support hierarchies */
	// tunables
	int  thr_limit;   // in us
	int  thr_factor;  // in %
	int  thr_plus;    // in us
	// statistical
	int thr_max;      // in ms
	int thr_triggered;
	int thr_true_hit;
};

static inline
void threshold_check(struct threshold *thr, long long latency)
{
	int ms = latency >> 6; // ignore small rounding error
	while (thr) {
		if (ms > thr->thr_max)
			thr->thr_max = ms;
		if (thr->thr_limit &&
		    latency > (long long)thr->thr_limit * 1000) {
			thr->thr_triggered++;
			if (thr->thr_ban &&
			    !banning_hit(thr->thr_ban, latency * thr->thr_factor / 100 + thr->thr_plus * 1000))
				thr->thr_true_hit++;
		}
		thr = thr->thr_parent;
	}
}

extern struct threshold global_io_threshold;

#endif
