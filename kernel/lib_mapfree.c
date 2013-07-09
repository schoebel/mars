// (c) 2012 Thomas Schoebel-Theuer / 1&1 Internet AG

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

int mapfree_period_sec = 10;
EXPORT_SYMBOL_GPL(mapfree_period_sec);

static
DECLARE_RWSEM(mapfree_mutex);

static
LIST_HEAD(mapfree_list);

static
void mapfree_pages(struct mapfree_info *mf, bool force)
{
	struct address_space *mapping;
	pgoff_t start;
	pgoff_t end;

	if (unlikely(!mf->mf_filp || !(mapping = mf->mf_filp->f_mapping)))
		goto done;

	if (force) {
		mf->mf_grace_free = 0;
		start = 0;
		end = -1;
	} else {
		unsigned long flags;
		loff_t tmp;
		loff_t min;
		
		traced_lock(&mf->mf_lock, flags);

		min = tmp = mf->mf_min[0];
		if (likely(mf->mf_min[1] < min))
			min = mf->mf_min[1];
		if (tmp) {
			mf->mf_min[1] = tmp;
			mf->mf_min[0] = 0;
		}

		traced_unlock(&mf->mf_lock, flags);

		if (min || mf->mf_last) {
			start = mf->mf_last / PAGE_SIZE;
			// add some grace overlapping
			if (likely(start > 0))
				start--;
			mf->mf_last = min;
			end   = min / PAGE_SIZE;
		} else  { // there was no progress for at least 2 rounds
			start = 0;
			end = -1;
		}

		MARS_DBG("file = '%s' start = %lu end = %lu\n", SAFE_STR(mf->mf_name), start, end);
	}

	if (end >= start || end == -1) {
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
		if (likely(mf->mf_filp)) {
			mapfree_pages(mf, true);
			filp_close(mf->mf_filp, NULL);
		}
		brick_string_free(mf->mf_name);
		brick_mem_free(mf);
	}
}

void mapfree_put(struct mapfree_info *mf)
{
	down_write(&mapfree_mutex);
	_mapfree_put(mf);
	up_write(&mapfree_mutex);
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
	
		if (mf)
			goto done;
	}

	for (;;) {
		struct address_space *mapping;
		struct inode *inode;
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

		if (unlikely(!(mapping = mf->mf_filp->f_mapping) ||
			     !(inode = mapping->host))) {
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
EXPORT_SYMBOL_GPL(mapfree_get);

void mapfree_set(struct mapfree_info *mf, loff_t min, loff_t max)
{
	unsigned long flags;

	traced_lock(&mf->mf_lock, flags);
	if (!mf->mf_min[0] || mf->mf_min[0] > min)
		mf->mf_min[0] = min;
	if (max >= 0 && mf->mf_max < max)
		mf->mf_max = max;
	traced_unlock(&mf->mf_lock, flags);
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

		mapfree_pages(mf, mf->mf_grace_free > 1000);

		mf->mf_jiffies = jiffies;
		mapfree_put(mf);
	}
	return 0;
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

void __exit exit_mars_mapfree(void)
{
	MARS_DBG("exit_mapfree()\n");
	if (likely(mf_thread)) {
		brick_thread_stop(mf_thread);
		mf_thread = NULL;
	}
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS mapfree infrastructure");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars_mapfree);
module_exit(exit_mars_mapfree);
#endif
