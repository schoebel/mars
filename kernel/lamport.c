/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2017 Thomas Schoebel-Theuer
 * Copyright (C) 2011-2017 1&1 Internet AG
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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rwsem.h>

#include "lamport.h"

/* This implementation is a variant of the following:
 *
@article{Lamport78,
  author = {Leslie Lamport},
  title = {Time, Clocks, and the Ordering of Events in a Distributed System},
  journal = {CACM},
  volume = {21},
  number = {7},
  year = {1978},
  pages = {558--565}
}
 * We always get both the local real time and the Lamport time in parallel.
 * The Lamport timestamp cannot fall behind the real timestamp, but
 * it may go ahead (into the "future") when clocks in the distributed
 * system are not synchronized precisely enough (e.g. via ntp).
 *
 * Thus we have a physical Lamport clock with the additional property
 * that it cannot fall behind local realtime.
 */

/* TODO CHECK: would a different locking method be better?
 * rwlocks? RCU?
 *
 * I did not really check it, due to lack of time.
 *
 * The reason why I chose rw_semaphore (against some contemporary
 * "common belief") is the following:
 *
 * A Lamport clock is a _global_ object by definition (with respect
 * to an SMP system => attention we have two levels of parallelism:
 * one at the Distributed System level, and SMP at the node level).
 *
 * Thus it _can_ happen that the Lamport clock forms a bottleneck,
 * e.g. when O(n) MARS ressources are syncing in parallel over a fast
 * network.
 *
 * Looking only at the "best case" where spinlocks or RCU might be faster
 * is therefore fundamentally broken. Instead, not only the
 * average case has to be observed, but also the worst case.
 *
 * We have some 40-core SMP/NUMA machines now (2017) at 1&1, and the number
 * will likely increase to 72 cores this year.
 * I know of cases where spinlock contention is really happening on
 * such machines in practice. If it happens, it almost kills the machine.
 *
 * When O(n) processors are spinning for the same bottleneck only _once_
 * each, already O(n^2) CPU cycles are burnt. When the bottleneck is
 * a _continuous_ one (e.g. multiple long-lasting MARS syncs in parallel),
 * then the whole machine may loose its efficiency and burn more than 90%
 * of its total CPU power in spinlocks.
 *
 * Thus I think some kind of scheduling lock is needed because the worst
 * case is an important one when the number of processors is high.
 *
 * Don't test this on workstations or notebooks, please test it on
 * the _most_ _powerful_ _servers_ you can get.
 *
 * THINK: is performance really the right measure in the long-term future?
 *
 * I think we should consider the _power_ _consumption_ (nJ / LamportOperation)
 * as a candidate for a more important measure in future.
 *
 * Please improve this code, but please use the right optimisation goal.
 */
struct rw_semaphore lamport_sem = __RWSEM_INITIALIZER(lamport_sem);

struct timespec lamport_stamp = {};

void get_lamport(struct timespec *real_now, struct timespec *lamport_now)
{
	struct timespec _real_now;
	struct timespec _lamport_now;

	/* Get a consistent copy of _both_ clocks */
	down_read(&lamport_sem);
	_lamport_now = lamport_stamp;
	/* Theoretically, the next statement could be moved behind the unlock.
	 * However, then we will loose strictness of real timestamps,
	 * or even may produce contradictory orderings between real and
	 * Lamport timestamps, respectively, in relation to pseudo-parallel
	 * calls to get_lamport().
	 */
	_real_now = CURRENT_TIME;
	up_read(&lamport_sem);

	if (real_now)
		*real_now = _real_now;
	/* use the maximum of both clocks as Lamport timestamp */
	if (timespec_compare(&_real_now, &_lamport_now) >= 0)
		*lamport_now = _real_now;
	else
		*lamport_now = _lamport_now;
}

EXPORT_SYMBOL_GPL(get_lamport);

void set_lamport(struct timespec *lamport_old)
{
	/* Always advance the internal Lamport timestamp a little bit
	 * in order to ensure strict monotonicity between set_lamport() calls.
	 */
	down_write(&lamport_sem);
	if (timespec_compare(lamport_old, &lamport_stamp) > 0)
		lamport_stamp = *lamport_old;
	else
		timespec_add_ns(&lamport_stamp, 1);
	up_write(&lamport_sem);
}
EXPORT_SYMBOL_GPL(set_lamport);

void set_lamport_nonstrict(struct timespec *lamport_old)
{
	/*  Speculate that advaning is not necessary, to avoid the lock
	 */
	if (timespec_compare(lamport_old, &lamport_stamp) > 0) {
		down_write(&lamport_sem);
		if (timespec_compare(lamport_old, &lamport_stamp) > 0)
			lamport_stamp = *lamport_old;
		up_write(&lamport_sem);
	}
}
EXPORT_SYMBOL_GPL(set_lamport_nonstrict);

/* After advancing the Lamport time, re-get the new values.
 * This is almost equivalent to a sequence of set_lamport() ; get_lamport()
 * but more efficient because the lock is taken only once.
 */
void set_get_lamport(struct timespec *lamport_old, struct timespec *real_now, struct timespec *lamport_now)
{
	struct timespec _real_now;

	down_write(&lamport_sem);
	if (timespec_compare(lamport_old, &lamport_stamp) > 0)
		*lamport_now = *lamport_old;
	else
		*lamport_now = timespec_add(lamport_stamp, (struct timespec){0, 1});
	lamport_stamp = *lamport_now;
	_real_now = CURRENT_TIME;
	up_write(&lamport_sem);

	if (real_now)
		*real_now = _real_now;
	/* use the maximum of both clocks as Lamport timestamp */
	if (timespec_compare(&_real_now, lamport_now) > 0)
		*lamport_now = _real_now;
}
EXPORT_SYMBOL_GPL(set_get_lamport);
