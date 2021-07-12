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

/* needed for symlink checking */
#include "sy_old/strategy.h"

// time to wait between background mapfree operations
int mapfree_period_sec = 10;
EXPORT_SYMBOL_GPL(mapfree_period_sec);

// some grace space where no regular cleanup should occur
int mapfree_grace_keep_mb = 16;
EXPORT_SYMBOL_GPL(mapfree_grace_keep_mb);

struct mf_hash_anchor {
	struct rw_semaphore hash_mutex;
	struct list_head    hash_anchor;
	struct task_struct *hash_thread;
};

#define MAPFREE_HASH 16

static inline
unsigned int mf_hash(const char *name)
{
	unsigned char digest[MARS_DIGEST_SIZE] = {};
	unsigned int res = 0;

	mars_digest(MREF_CHKSUM_CRC32C | MREF_CHKSUM_MD5_OLD,
		    NULL,
		    digest,
		    name, strlen(name));

	res = *(unsigned int *)&digest % MAPFREE_HASH;

	return res;
}

static
struct mf_hash_anchor mf_table[MAPFREE_HASH];

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
	if (likely(mf && mf->mf_hash < MAPFREE_HASH)) {
		unsigned int hash = mf->mf_hash;

		down_write(&mf_table[hash].hash_mutex);
		_mapfree_put(mf);
		up_write(&mf_table[hash].hash_mutex);
	}
}
EXPORT_SYMBOL_GPL(mapfree_put);

loff_t mapfree_real_size(struct mapfree_info *mf)
{
	loff_t length = 0;
	if (likely(mf && mf->mf_filp && mf->mf_filp->f_mapping)) {
		struct inode *inode = mf->mf_filp->f_mapping->host;

		length = i_size_read(inode);
	}
	return length;
}

struct mapfree_info *mapfree_get(const char *name, int flags, int *error)
{
	struct kstat check_stat = {};
	struct mapfree_info *mf = NULL;
	struct list_head *tmp;
	unsigned int hash = mf_hash(name);

	flags |= O_CLOEXEC;
	if (!(flags & O_DIRECT) &&
	    mars_stat(name, &check_stat, false) >= 0 &&
	    (S_ISBLK(check_stat.mode))) {
		down_read(&mf_table[hash].hash_mutex);
		for (tmp = mf_table[hash].hash_anchor.next;
		     tmp != &mf_table[hash].hash_anchor;
		     tmp = tmp->next) {
			struct mapfree_info *_mf = container_of(tmp, struct mapfree_info, mf_head);
			if (_mf->mf_flags == flags && !strcmp(_mf->mf_name, name)) {
				mf = _mf;
				atomic_inc(&mf->mf_count);
				break;
			}
		}
		up_read(&mf_table[hash].hash_mutex);
	
		if (mf) {
			loff_t length = mapfree_real_size(mf);
			int i;

			/* In some cases like truncated logfiles,
			 * account for any shortenings.
			 */
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

		mf->mf_hash = hash;
		mf->mf_name = brick_strdup(name);
		if (unlikely(!mf->mf_name)) {
			MARS_ERR("no mem, name = '%s'\n", name);
			brick_mem_free(mf);
			continue;
		}

		/* allow replacement of a .deleted symlink */
		if (flags & O_CREAT) {
			const char *check = mars_readlink(name, NULL);

			if (check && !strcmp(check, MARS_DELETED_STR))
				mars_unlink(name);

			brick_string_free(check);
		}

		mf->mf_flags = flags;
		INIT_LIST_HEAD(&mf->mf_head);
		INIT_LIST_HEAD(&mf->mf_dirty_anchor);
		atomic_set(&mf->mf_count, 1);
		init_rwsem(&mf->mf_mutex);
		mf->mf_max = -1;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		mf->mf_filp = filp_open(name, flags, prot);
		set_fs(oldfs);

		MARS_DBG("file '%s' flags = %d prot = %d filp = %p\n", name, flags, prot, mf->mf_filp);

		if (unlikely(!mf->mf_filp || IS_ERR(mf->mf_filp))) {
			int err = PTR_ERR(mf->mf_filp);

			if (error)
				*error = err;
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
		down_write(&mf_table[hash].hash_mutex);
		for (tmp = mf_table[hash].hash_anchor.next;
		     tmp != &mf_table[hash].hash_anchor;
		     tmp = tmp->next) {
			struct mapfree_info *_mf = container_of(tmp, struct mapfree_info, mf_head);
			if (unlikely(_mf->mf_flags == flags && !strcmp(_mf->mf_name, name))) {
				MARS_WRN("race on creation of '%s' detected\n", name);
				_mapfree_put(mf);
				mf = _mf;
				atomic_inc(&mf->mf_count);
				goto leave;
			}
		}
		list_add_tail(&mf->mf_head, &mf_table[hash].hash_anchor);
	leave:
		up_write(&mf_table[hash].hash_mutex);
		break;
	}
 done:
	return mf;
}
EXPORT_SYMBOL_GPL(mapfree_get);

void mapfree_set(struct mapfree_info *mf, loff_t min, loff_t max)
{
	if (likely(mf && mf->mf_hash < MAPFREE_HASH)) {
		struct mf_hash_anchor *mha = &mf_table[mf->mf_hash];

		down_write(&mha->hash_mutex);
		if (!mf->mf_min[0] || mf->mf_min[0] > min)
			mf->mf_min[0] = min;
		if (max >= 0 && mf->mf_max < max)
			mf->mf_max = max;
		up_write(&mha->hash_mutex);
	}
}
EXPORT_SYMBOL_GPL(mapfree_set);

static
int mapfree_thread(void *data)
{
	struct mf_hash_anchor *mha = data;

	while (!brick_thread_should_stop()) {
		struct mapfree_info *mf = NULL;
		struct list_head *tmp;
		long long eldest = 0;

		brick_msleep(500);

		if (mapfree_period_sec <= 0)
			continue;
		
		down_read(&mha->hash_mutex);

		for (tmp = mha->hash_anchor.next;
		     tmp != &mha->hash_anchor;
		     tmp = tmp->next) {
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

		up_read(&mha->hash_mutex);

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
	dl->dl_appends++;
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

	/* Use the real length when no writes are flying.
	 */
	if (stage > 0) {
		struct dirty_length *d0 = _get_dl(mf, 0);
		u64 nr1 = READ_ONCE(dl->dl_appends);
		u64 nr0 = READ_ONCE(d0->dl_appends);

		if (nr0 <= nr1) {
			loff_t real_size = mapfree_real_size(mf);

			/* check for races once again */
			nr1 = READ_ONCE(dl->dl_appends);
			nr0 = READ_ONCE(d0->dl_appends);
			if (nr0 <= nr1)
				return real_size;
		}
	}
	return READ_ONCE(dl->dl_length);
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
	unsigned int hash = mf_hash(filename);
	loff_t res = -1;
	struct list_head *tmp;

	down_read(&mf_table[hash].hash_mutex);
	for (tmp = mf_table[hash].hash_anchor.next;
	     tmp != &mf_table[hash].hash_anchor;
	     tmp = tmp->next) {
		struct mapfree_info *mf = container_of(tmp, struct mapfree_info, mf_head);
		if (!strcmp(mf->mf_name, filename)) {
			res = mf_dirty_length(mf, stage);
			break;
		}
	}
	up_read(&mf_table[hash].hash_mutex);
	return res;
}
EXPORT_SYMBOL_GPL(mf_get_any_dirty);

////////////////// module init stuff /////////////////////////

int __init init_mars_mapfree(void)
{
	int i;

	MARS_DBG("init_mapfree()\n");
	for (i = 0; i < MAPFREE_HASH; i++) {
		struct task_struct *thread;

		init_rwsem(&mf_table[i].hash_mutex);
		INIT_LIST_HEAD(&mf_table[i].hash_anchor);
		thread = brick_thread_create(mapfree_thread,
					     &mf_table[i],
					     "mars_mf%d", i);
		if (unlikely(!thread)) {
			MARS_ERR("could not create mapfree thread %d\n", i);
			return -ENOMEM;
		}
		mf_table[i].hash_thread = thread;
	}
	return 0;
}

void exit_mars_mapfree(void)
{
	int i;

	MARS_DBG("exit_mapfree()\n");
	for (i = 0; i < MAPFREE_HASH; i++) {
		if (likely(mf_table[i].hash_thread)) {
			brick_thread_stop(mf_table[i].hash_thread);
			mf_table[i].hash_thread = NULL;
		}
		CHECK_HEAD_EMPTY(&mf_table[i].hash_anchor);
	}
}
