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

#ifndef MARS_LIB_MAPFREE_H
#define MARS_LIB_MAPFREE_H

/* Mapfree infrastructure.
 *
 * Purposes:
 *
 * 1) Open files only once when possible, do ref-counting on struct mapfree_info
 *
 * 2) Automatically call invalidate_mapping_pages() in the background on
 *    "unused" areas to free resources.
 *    Used areas can be indicated by calling mapfree_set() frequently.
 *    Usage model: tailored to sequential logfiles.
 *
 * 3) Do it all in a completely decoupled manner, in order to prevent resource deadlocks.
 *
 * 4) Also to prevent deadlocks: always set mapping_set_gfp_mask() accordingly.
 */

#include <linux/rwsem.h>

#include "mars.h"

extern int mapfree_period_sec;
extern int mapfree_grace_keep_mb;

enum dirty_stage {
	DIRTY_SUBMITTED,
	DIRTY_COMPLETED,
	DIRTY_FINISHED,
	/* Keep this the last element */
	DIRTY_MAX
};

struct dirty_length {
	rwlock_t dl_lock;
	u64      dl_appends;
	loff_t   dl_length;
};

struct mapfree_info {
	struct list_head mf_head;
	struct list_head mf_dirty_anchor;
	char            *mf_name;
	struct file     *mf_filp;
	int              mf_flags;
	int              mf_mode;
	atomic_t         mf_count;
	/* private */
	struct rw_semaphore mf_mutex;
	loff_t           mf_min[2];
	loff_t           mf_last;
	loff_t           mf_max;
	long long        mf_jiffies;
	unsigned int     mf_hash;
	bool             mf_finished;
	struct dirty_length mf_length[DIRTY_MAX];
};

struct mapfree_info *mapfree_get(const char *filename, int flags, int *error);

void mapfree_put(struct mapfree_info *mf);

void mapfree_set(struct mapfree_info *mf, loff_t min, loff_t max);

void mapfree_pages(struct mapfree_info *mf, int grace_keep);

loff_t mapfree_real_size(struct mapfree_info *mf);

////////////////// dirty IOs in append mode  //////////////////

void mf_dirty_append(struct mapfree_info *mf, enum dirty_stage stage, loff_t newlen);
void mf_dirty_reduce(struct mapfree_info *mf, enum dirty_stage stage, loff_t newlen);
loff_t mf_dirty_length(struct mapfree_info *mf, enum dirty_stage stage);

////////////////// dirty IOs on the fly  //////////////////

loff_t mf_get_any_dirty(const char *filename, int stage);

////////////////// module init stuff /////////////////////////

int __init init_mars_mapfree(void);

void exit_mars_mapfree(void);

#endif
