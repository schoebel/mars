// (c) 2012 Thomas Schoebel-Theuer / 1&1 Internet AG
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

#include "mars.h"

extern int mapfree_period_sec;

struct mapfree_info {
	struct list_head mf_head;
	char            *mf_name;
	struct file     *mf_filp;
	int              mf_flags;
	atomic_t         mf_count;
	spinlock_t       mf_lock;
	loff_t           mf_min[2];
	loff_t           mf_last;
	loff_t           mf_max;
	long long        mf_jiffies;
};

struct mapfree_info *mapfree_get(const char *filename, int flags);

void mapfree_put(struct mapfree_info *mf);

void mapfree_set(struct mapfree_info *mf, loff_t min, loff_t max);

////////////////// module init stuff /////////////////////////

int __init init_mars_mapfree(void);

void __exit exit_mars_mapfree(void);

#endif
