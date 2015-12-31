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
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/file.h>

// time to wait between background mapfree operations
int mapfree_period_sec = 10;

// some grace space where no regular cleanup should occur
int mapfree_grace_keep_mb = 16;

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
	if (unlikely(!mf->mf_filp))
		goto done;

	mapping = mf->mf_filp->f_mapping;
	if (unlikely(!mapping))
		goto done;

	if (grace_keep < 0) { // force full flush
		start = 0;
		end = -1;
	} else {
		unsigned long flags;
		loff_t tmp;
		loff_t min;
		
		spin_lock_irqsave(&mf->mf_lock, flags);

		min = tmp = mf->mf_min[0];
		if (likely(mf->mf_min[1] < min))
			min = mf->mf_min[1];
		if (tmp) {
			mf->mf_min[1] = tmp;
			mf->mf_min[0] = 0;
		}

		spin_unlock_irqrestore(&mf->mf_lock, flags);

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

		MARS_DBG("file = '%s' start = %lu end = %lu\n", mf->mf_name, start, end);
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
	
		if (mf)
			goto done;
	}

	for (;;) {
		struct address_space *mapping;
		struct inode *inode = NULL;
		int ra = 1;
		int prot = 0600;
		mm_segment_t oldfs;

		mf = brick_zmem_alloc(sizeof(struct mapfree_info));

		mf->mf_name = brick_strdup(name);

		mf->mf_flags = flags;
		INIT_LIST_HEAD(&mf->mf_head);
		INIT_LIST_HEAD(&mf->mf_dirty_anchor);
		atomic_set(&mf->mf_count, 1);
		spin_lock_init(&mf->mf_lock);
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

		mapping = mf->mf_filp->f_mapping;
		if (likely(mapping))
			inode = mapping->host;
		if (unlikely(!mapping || !inode)) {
			MARS_ERR("file '%s' has no mapping\n", name);
			mf->mf_filp = NULL;
			_mapfree_put(mf);
			mf = NULL;
			break;
		}

		mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));

		mf->mf_max = i_size_read(inode);

		if (S_ISBLK(inode->i_mode)) {
			MARS_INF("changing blkdev readahead from %lu to %d\n", inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages, ra);
			inode->i_bdev->bd_disk->queue->backing_dev_info.ra_pages = ra;
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

void mapfree_set(struct mapfree_info *mf, loff_t min, loff_t max)
{
	unsigned long flags;

	if (likely(mf)) {
		spin_lock_irqsave(&mf->mf_lock, flags);
		if (!mf->mf_min[0] || mf->mf_min[0] > min)
			mf->mf_min[0] = min;
		if (max >= 0 && mf->mf_max < max)
			mf->mf_max = max;
		spin_unlock_irqrestore(&mf->mf_lock, flags);
	}
}

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

////////////////// dirty IOs on the fly  //////////////////

void mf_insert_dirty(struct mapfree_info *mf, struct dirty_info *di)
{
	unsigned long flags;

	if (likely(di->dirty_mref && mf)) {
		spin_lock_irqsave(&mf->mf_lock, flags);
		list_del(&di->dirty_head);
		list_add(&di->dirty_head, &mf->mf_dirty_anchor);
		spin_unlock_irqrestore(&mf->mf_lock, flags);
	}
}

void mf_remove_dirty(struct mapfree_info *mf, struct dirty_info *di)
{
	unsigned long flags;

	if (!list_empty(&di->dirty_head) && mf) {
		spin_lock_irqsave(&mf->mf_lock, flags);
		list_del_init(&di->dirty_head);
		spin_unlock_irqrestore(&mf->mf_lock, flags);
	}
}

void mf_get_dirty(struct mapfree_info *mf, loff_t *min, loff_t *max, int min_stage, int max_stage)
{
	unsigned long flags;

	struct list_head *tmp;

	if (unlikely(!mf))
	    goto done;

	spin_lock_irqsave(&mf->mf_lock, flags);
	for (tmp = mf->mf_dirty_anchor.next; tmp != &mf->mf_dirty_anchor; tmp = tmp->next) {
		struct dirty_info *di = container_of(tmp, struct dirty_info, dirty_head);
		struct mref_object *mref = di->dirty_mref;
		if (unlikely(!mref)) {
			continue;
		}
		if (di->dirty_stage < min_stage || di->dirty_stage > max_stage) {
			continue;
		}
		if (mref->ref_pos < *min) {
			*min = mref->ref_pos;
		}
		if (mref->ref_pos + mref->ref_len > *max) {
			*max = mref->ref_pos + mref->ref_len;
		}
	}
	spin_unlock_irqrestore(&mf->mf_lock, flags);
done:;
}

void mf_get_any_dirty(const char *filename, loff_t *min, loff_t *max, int min_stage, int max_stage)
{
	struct list_head *tmp;

	down_read(&mapfree_mutex);
	for (tmp = mapfree_list.next; tmp != &mapfree_list; tmp = tmp->next) {
		struct mapfree_info *mf = container_of(tmp, struct mapfree_info, mf_head);
		if (!strcmp(mf->mf_name, filename)) {
			mf_get_dirty(mf, min, max, min_stage, max_stage);
		}
	}
	up_read(&mapfree_mutex);
}

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
