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


#include "lib_mapfree.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/file.h>

// time to wait between background mapfree operations
int mapfree_period_sec = 10;
EXPORT_SYMBOL_GPL(mapfree_period_sec);

// some grace space where no regular cleanup should occur
int mapfree_grace_keep_mb = 16;
EXPORT_SYMBOL_GPL(mapfree_grace_keep_mb);

static
DECLARE_RWSEM(mapfree_mutex);

static
LIST_HEAD(mapfree_list);

void mapfree_pages(struct mapfree_info *mf, int grace_keep)
{
	struct address_space *mapping;
	pgoff_t start;
	pgoff_t end;

	if (unlikely(!mf))
	    goto done;
	if (unlikely(!mf->mf_filp || !(mapping = mf->mf_filp->f_mapping)))
		goto done;

	if (grace_keep < 0) { // force full flush
		start = 0;
		end = -1;
	} else {
		loff_t tmp;
		loff_t min;
		
		down_write(&mf->mf_mutex);

		min = tmp = mf->mf_min[0];
		if (likely(mf->mf_min[1] < min))
			min = mf->mf_min[1];
		if (tmp) {
			mf->mf_min[1] = tmp;
			mf->mf_min[0] = 0;
		}

		up_write(&mf->mf_mutex);

		min -= (loff_t)grace_keep * (1024 * 1024); // megabytes
		end = 0;

		if (min > 0 || mf->mf_last) {
			start = mf->mf_last / PAGE_SIZE;
			// add some grace overlapping
			if (likely(start > 0))
				start--;
			mf->mf_last = min;
			end   = min / PAGE_SIZE;
		} else  { // there was no progress for at least 2 rounds
			start = 0;
			if (!grace_keep) // also flush thoroughly
				end = -1;
		}

		MARS_DBG("file = '%s' start = %lu end = %lu\n", SAFE_STR(mf->mf_name), start, end);
	}

	if (end > start || end == -1) {
		invalidate_mapping_pages(mapping, start, end);
	}

done:;
}

static
void _mapfree_put(struct mapfree_info *mf)
{
	if (atomic_dec_and_test(&mf->mf_count)) {
		MARS_DBG("closing file '%s' filp = %p\n", mf->mf_name, mf->mf_filp);
		list_del_init(&mf->mf_head);
		CHECK_HEAD_EMPTY(&mf->mf_dirty_anchor);
		if (likely(mf->mf_filp)) {
			mapfree_pages(mf, -1);
			filp_close(mf->mf_filp, NULL);
		}
		brick_string_free(mf->mf_name);
		brick_mem_free(mf);
	}
}

void mapfree_put(struct mapfree_info *mf)
{
	if (likely(mf)) {
		down_write(&mapfree_mutex);
		_mapfree_put(mf);
		up_write(&mapfree_mutex);
	}
}
EXPORT_SYMBOL_GPL(mapfree_put);

struct mapfree_info *mapfree_get(const char *name, int flags)
{
	struct mapfree_info *mf = NULL;
	struct list_head *tmp;

	if (!(flags & O_DIRECT)) {
		down_read(&mapfree_mutex);
		for (tmp = mapfree_list.next; tmp != &mapfree_list; tmp = tmp->next) {
			struct mapfree_info *_mf = container_of(tmp, struct mapfree_info, mf_head);
			if (_mf->mf_flags == flags && !strcmp(_mf->mf_name, name)) {
				mf = _mf;
				atomic_inc(&mf->mf_count);
				break;
			}
		}
		up_read(&mapfree_mutex);
	
		if (mf) {
			struct inode *inode = mf->mf_filp->f_mapping->host;
			loff_t length;
			int i;

			/* In some cases like truncated logfiles,
			 * account for any shortenings.
			 */
			length = i_size_read(inode);
			mf->mf_max = length;
			for (i = 0; i < DIRTY_MAX; i++)
				mf_dirty_reduce(mf, i, length);

			goto done;
		}
	}

	for (;;) {
		struct address_space *mapping;
		struct inode *inode;
		loff_t length;
		int i;
		int ra = 1;
		int prot = 0600;
		mm_segment_t oldfs;

		mf = brick_zmem_alloc(sizeof(struct mapfree_info));
		if (unlikely(!mf)) {
			MARS_ERR("no mem, name = '%s'\n", name);
			continue;
		}

		mf->mf_name = brick_strdup(name);
		if (unlikely(!mf->mf_name)) {
			MARS_ERR("no mem, name = '%s'\n", name);
			brick_mem_free(mf);
			continue;
		}

		mf->mf_flags = flags;
		INIT_LIST_HEAD(&mf->mf_head);
		INIT_LIST_HEAD(&mf->mf_dirty_anchor);
		atomic_set(&mf->mf_count, 1);
		init_rwsem(&mf->mf_mutex);
		mf->mf_max = -1;

		oldfs = get_fs();
		set_fs(get_ds());
		mf->mf_filp = filp_open(name, flags, prot);
		set_fs(oldfs);

		MARS_DBG("file '%s' flags = %d prot = %d filp = %p\n", name, flags, prot, mf->mf_filp);

		if (unlikely(!mf->mf_filp || IS_ERR(mf->mf_filp))) {
			int err = PTR_ERR(mf->mf_filp);
			MARS_ERR("can't open file '%s' status=%d\n", name, err);
			mf->mf_filp = NULL;
			_mapfree_put(mf);
			mf = NULL;
			break;
		}

		if (unlikely(!(mapping = mf->mf_filp->f_mapping) ||
			     !(inode = mapping->host))) {
			MARS_ERR("file '%s' has no mapping\n", name);
			mf->mf_filp = NULL;
			_mapfree_put(mf);
			mf = NULL;
			break;
		}

		mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));

		length = i_size_read(inode);
		mf->mf_max = length;
		for (i = 0; i < DIRTY_MAX; i++) {
			rwlock_init(&mf->mf_length[i].dl_lock);
			mf->mf_length[i].dl_length = length;
		}

		if (S_ISBLK(inode->i_mode)) {
#ifdef MARS_HAS_BDI_GET
			struct backing_dev_info *bdi =
			  I_BDEV(inode)->bd_bdi;
			MARS_INF("changing blkdev readahead from %lu to %d\n",
				 bdi->ra_pages, ra);
			bdi->ra_pages = ra;
#else /* deprecated old code */
			MARS_INF("changing blkdev readahead from %lu to %d\n", inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages, ra);
			inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages = ra;
#endif
		}

		if (flags & O_DIRECT) {	// never share them
			break;
		}

		// maintain global list of all open files
		down_write(&mapfree_mutex);
		for (tmp = mapfree_list.next; tmp != &mapfree_list; tmp = tmp->next) {
			struct mapfree_info *_mf = container_of(tmp, struct mapfree_info, mf_head);
			if (unlikely(_mf->mf_flags == flags && !strcmp(_mf->mf_name, name))) {
				MARS_WRN("race on creation of '%s' detected\n", name);
				_mapfree_put(mf);
				mf = _mf;
				atomic_inc(&mf->mf_count);
				goto leave;
			}
		}
		list_add_tail(&mf->mf_head, &mapfree_list);
	leave:
		up_write(&mapfree_mutex);
		break;
	}
 done:
	return mf;
}
EXPORT_SYMBOL_GPL(mapfree_get);

void mapfree_set(struct mapfree_info *mf, loff_t min, loff_t max)
{
	if (likely(mf)) {
		down_write(&mf->mf_mutex);
		if (!mf->mf_min[0] || mf->mf_min[0] > min)
			mf->mf_min[0] = min;
		if (max >= 0 && mf->mf_max < max)
			mf->mf_max = max;
		up_write(&mf->mf_mutex);
	}
}
EXPORT_SYMBOL_GPL(mapfree_set);

static
int mapfree_thread(void *data)
{
	while (!brick_thread_should_stop()) {
		struct mapfree_info *mf = NULL;
		struct list_head *tmp;
		long long eldest = 0;

		brick_msleep(500);

		if (mapfree_period_sec <= 0)
			continue;
		
		down_read(&mapfree_mutex);

		for (tmp = mapfree_list.next; tmp != &mapfree_list; tmp = tmp->next) {
			struct mapfree_info *_mf = container_of(tmp, struct mapfree_info, mf_head);
			if (unlikely(!_mf->mf_jiffies)) {
				_mf->mf_jiffies = jiffies;
				continue;
			}
			if ((long long)jiffies - _mf->mf_jiffies > mapfree_period_sec * HZ &&
			    (!mf || _mf->mf_jiffies < eldest)) {
				mf = _mf;
				eldest = _mf->mf_jiffies;
			}
		}
		if (mf)
			atomic_inc(&mf->mf_count);

		up_read(&mapfree_mutex);

		if (!mf) {
			continue;
		}

		mapfree_pages(mf, mapfree_grace_keep_mb);

		mf->mf_jiffies = jiffies;
		mapfree_put(mf);
	}
	return 0;
}

////////////////// dirty IOs in append mode  //////////////////

static
struct dirty_length *_get_dl(struct mapfree_info *mf, enum dirty_stage stage)
{
#ifdef MARS_DEBUGGING
	if (unlikely(stage < 0)) {
		MARS_ERR("bad stage=%d\n", stage);
		stage = 0;
	}
	if (unlikely(stage >= DIRTY_MAX)) {
		MARS_ERR("bad stage=%d\n", stage);
		stage = DIRTY_MAX - 1;
	}
#endif
	return &mf->mf_length[stage];
}

void mf_dirty_append(struct mapfree_info *mf, enum dirty_stage stage, loff_t newlen)
{
	struct dirty_length *dl = _get_dl(mf, stage);
	unsigned long flags;

	traced_writelock(&dl->dl_lock, flags);
	if (dl->dl_length < newlen)
		dl->dl_length = newlen;
	traced_writeunlock(&dl->dl_lock, flags);
}

void mf_dirty_reduce(struct mapfree_info *mf, enum dirty_stage stage, loff_t newlen)
{
	struct dirty_length *dl = _get_dl(mf, stage);
	unsigned long flags;

	traced_writelock(&dl->dl_lock, flags);
	if (dl->dl_length > newlen)
		dl->dl_length = newlen;
	traced_writeunlock(&dl->dl_lock, flags);
}

loff_t mf_dirty_length(struct mapfree_info *mf, enum dirty_stage stage)
{
	struct dirty_length *dl = _get_dl(mf, stage);

#ifdef CONFIG_64BIT
	/* Avoid locking by assuming that 64bit reads are atomic in itself */
	smp_read_barrier_depends();
	return ACCESS_ONCE(dl->dl_length);
#else /* cannot rely on atomic read of two 32bit values */
	loff_t res;
	unsigned long flags;

	traced_readlock(&dl->dl_lock, flags);
	res = dl->dl_length;
	traced_readunlock(&dl->dl_lock, flags);
	return res;
#endif
}

////////////////// dirty IOs on the fly  //////////////////

loff_t mf_get_any_dirty(const char *filename, int stage)
{
	loff_t res = -1;
	struct list_head *tmp;

	down_read(&mapfree_mutex);
	for (tmp = mapfree_list.next; tmp != &mapfree_list; tmp = tmp->next) {
		struct mapfree_info *mf = container_of(tmp, struct mapfree_info, mf_head);
		if (!strcmp(mf->mf_name, filename)) {
			res = mf_dirty_length(mf, stage);
			break;
		}
	}
	up_read(&mapfree_mutex);
	return res;
}
EXPORT_SYMBOL_GPL(mf_get_any_dirty);

////////////////// module init stuff /////////////////////////

static
struct task_struct *mf_thread = NULL;

int __init init_mars_mapfree(void)
{
	MARS_DBG("init_mapfree()\n");
	mf_thread = brick_thread_create(mapfree_thread, NULL, "mars_mapfree");
	if (unlikely(!mf_thread)) {
		MARS_ERR("could not create mapfree thread\n");
		return -ENOMEM;
	}
	return 0;
}

void exit_mars_mapfree(void)
{
	MARS_DBG("exit_mapfree()\n");
	if (likely(mf_thread)) {
		brick_thread_stop(mf_thread);
		mf_thread = NULL;
	}
}
