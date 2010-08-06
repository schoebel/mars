// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

// Buf brick

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/delay.h>

#include "mars.h"

///////////////////////// own type definitions ////////////////////////

#include "mars_buf.h"

///////////////////////// own helper functions ////////////////////////

static inline int buf_hash(struct buf_brick *brick, unsigned int base_index)
{
	return base_index % MARS_BUF_HASH_MAX;
}

static struct buf_head *hash_find(struct buf_brick *brick, unsigned int base_index)
{
	
	int hash = buf_hash(brick, base_index);
	struct list_head *start = &brick->cache_anchors[hash];
	struct list_head *tmp;
	struct buf_head *res;
	for (tmp = start->next; ; tmp = tmp->next) {
		if (tmp == start)
			return NULL;
		res = container_of(tmp, struct buf_head, bf_hash_head);
		if (res->bf_base_index == base_index)
			break;
	}
	return res;
}

static inline void hash_insert(struct buf_brick *brick, struct buf_head *elem)
{
	int hash = buf_hash(brick, elem->bf_base_index);
	struct list_head *start = &brick->cache_anchors[hash];
	list_add(&elem->bf_hash_head, start);
}

static inline void free_buf(struct buf_brick *brick, struct buf_head *bf)
{
	free_pages((unsigned long)bf->bf_data, brick->backing_order);
	kfree(bf);
}

/* brick->buf_lock must be held
 */
static inline void __prune_cache(struct buf_brick *brick, int max_count, unsigned long *flags)
{
#if 0
	return;
#endif
	while (brick->alloc_count >= max_count) {
		struct buf_head *bf;
		if (list_empty(&brick->free_anchor))
			break;
		bf = container_of(brick->free_anchor.next, struct buf_head, bf_lru_head);
		list_del_init(&bf->bf_lru_head);
		brick->alloc_count--;
		
		traced_unlock(&brick->buf_lock, *flags);
		free_buf(brick, bf);
		traced_lock(&brick->buf_lock, *flags);
	}
}

static inline void __lru_free_one(struct buf_brick *brick)
{
	struct buf_head *bf;
	if (list_empty(&brick->lru_anchor))
		return;
	bf = container_of(brick->lru_anchor.prev, struct buf_head, bf_lru_head);
	list_del_init(&bf->bf_lru_head);
	list_del_init(&bf->bf_hash_head);
	brick->current_count--;
	list_add(&bf->bf_lru_head, &brick->free_anchor);
}


static inline void __lru_free(struct buf_brick *brick)
{
	while (brick->current_count >= brick->max_count) {
		if (list_empty(&brick->lru_anchor))
			break;
		__lru_free_one(brick);
	}
}


static inline int get_info(struct buf_brick *brick)
{
	struct buf_input *input = brick->inputs[0];
	int status = GENERIC_INPUT_CALL(input, mars_get_info, &brick->base_info);
	if (status >= 0) {
		brick->got_info = 1;
	}
	return status;
}

/* Convert from arbitrary/odd kernel address/length to struct page,
 * create bio from it, round up/down to full sectors.
 * return the length (may be smaller or even larger than requested)
 */
static int make_bio(struct buf_brick *brick, struct bio **_bio, void *data, loff_t pos, int len)
{
	unsigned long long sector;
	int sector_offset;
	int page_offset;
	int page_len;
	int bvec_count;
	int status;
	int i;
	struct page *page;
	struct bio *bio = NULL;
	struct block_device *bdev;

	if (unlikely(!brick->got_info)) {
		struct request_queue *q;
		status = get_info(brick);
		if (status < 0)
			goto out;
		bdev = brick->base_info.backing_file->f_mapping->host->i_sb->s_bdev;
		q = bdev_get_queue(bdev);
		brick->bvec_max = queue_max_hw_sectors(q) >> (PAGE_SHIFT - 9);
	} else {
		bdev = brick->base_info.backing_file->f_mapping->host->i_sb->s_bdev;
	}

	if (unlikely(len <= 0)) {
		MARS_ERR("bad bio len %d\n", len);
		status = -EINVAL;
		goto out;
	}

	sector = pos >> 9;                     // TODO: make dynamic
	sector_offset = pos & ((1 << 9) - 1);  // TODO: make dynamic

	// round down to start of first sector
	data -= sector_offset;
	len += sector_offset;
	pos -= sector_offset;

	// round up to full sector
	len = (((len - 1) >> 9) + 1) << 9; // TODO: make dynamic

	// map onto pages. TODO: allow higher-order pages (performance!)
	page_offset = pos & (PAGE_SIZE - 1);
	page_len = len + page_offset;
	bvec_count = (page_len - 1) / PAGE_SIZE + 1;
	if (bvec_count > brick->bvec_max)
		bvec_count = brick->bvec_max;

	bio = bio_alloc(GFP_MARS, bvec_count);
	status = -ENOMEM;
	if (!bio)
		goto out;

	status = 0;
	for (i = 0; i < bvec_count && len > 0; i++) {
		int myrest = PAGE_SIZE - page_offset;
		int mylen = len;

		if (mylen > myrest)
			mylen = myrest;

		page = virt_to_page(data);

		bio->bi_io_vec[i].bv_page = page;
		bio->bi_io_vec[i].bv_len = mylen;
		bio->bi_io_vec[i].bv_offset = page_offset;

		data += mylen;
		len -= mylen;
		status += mylen;
		page_offset = 0;
	}

	if (unlikely(len)) {
		bio_put(bio);
		bio = NULL;
		MARS_ERR("computation of bvec_count %d was wrong, diff=%d\n", bvec_count, len);
		status = -EIO;
		goto out;
	}

	bio->bi_vcnt = i;
	bio->bi_idx = 0;
	bio->bi_size = status;
	bio->bi_sector = sector;
	bio->bi_bdev = bdev;
	bio->bi_private = NULL; // must be filled in later
	bio->bi_end_io = NULL; // must be filled in later
	bio->bi_rw = 0; // must be filled in later
	// ignore rounding-down on return
	if (status >= sector_offset)
		status -= sector_offset;

out:
	*_bio = bio;
	return status;
}

static inline struct buf_head *_alloc_bf(struct buf_brick *brick)
{
	struct buf_head *bf = kzalloc(sizeof(struct buf_head), GFP_MARS);
	if (!bf)
		goto done;

	bf->bf_data = (void*)__get_free_pages(GFP_MARS, brick->backing_order);
	if (unlikely(!bf->bf_data)) {
		kfree(bf);
		bf = NULL;
	}

done:
	return bf;
}

static void __pre_alloc_bf(struct buf_brick *brick, int max)
{
	while (max-- > 0) {
		struct buf_head *bf = _alloc_bf(brick);
		unsigned long flags;

		if (unlikely(!bf))
			break;

		traced_lock(&brick->buf_lock, flags);

		list_add(&bf->bf_lru_head, &brick->free_anchor);
		brick->alloc_count++;

		traced_unlock(&brick->buf_lock, flags);
	}
}

////////////////// own brick / input / output operations //////////////////

static int buf_get_info(struct buf_output *output, struct mars_info *info)
{
	struct buf_input *input = output->brick->inputs[0];
	return GENERIC_INPUT_CALL(input, mars_get_info, info);
}

static int buf_ref_get(struct buf_output *output, struct mars_ref_object *mref)
{
	struct buf_brick *brick = output->brick;
	struct buf_mars_ref_aspect *mref_a;
	struct buf_head *bf;
	loff_t base_pos;
	int base_offset;
	int max_len;
	unsigned long flags;
	int status = -EILSEQ;

	might_sleep();

	if (mref->orig_bio) {
		MARS_ERR("illegal: mref has a bio assigend\n");
	}

	if (unlikely(brick->alloc_count < brick->max_count)) {
		// grab all memory in one go => avoid memory fragmentation
		__pre_alloc_bf(brick, brick->max_count - brick->alloc_count);
	}
	/* Grab reference.
	 */
	_CHECK_SPIN(&mref->ref_count, !=, 0);
	atomic_inc(&mref->ref_count);

	mref_a = buf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a))
		goto done;
	
	base_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
	base_offset = (mref->ref_pos - base_pos);
	if (unlikely(base_offset < 0 || base_offset >= brick->backing_size)) {
		MARS_ERR("bad base_offset %d\n", base_offset);
	}

	max_len = brick->backing_size - base_offset;
	if (mref->ref_len > max_len)
		mref->ref_len = max_len;

	traced_lock(&brick->buf_lock, flags);

again:
	bf = hash_find(brick, ((unsigned int)base_pos) >> brick->backing_order);
	if (bf) {
		atomic_inc(&brick->hit_count);
	} else {
		atomic_inc(&brick->miss_count);
		MARS_DBG("buf_get() hash nothing found\n");
		if (list_empty(&brick->free_anchor)) {
			__lru_free_one(brick);
		}
		if (unlikely(list_empty(&brick->free_anchor))) {
			MARS_INF("alloc new buf_head %d\n", brick->alloc_count);

			traced_unlock(&brick->buf_lock, flags);

			status = -ENOMEM;
			bf = _alloc_bf(brick);
			if (!bf)
				goto done;

			traced_lock(&brick->buf_lock, flags);
			
			list_add(&bf->bf_lru_head, &brick->free_anchor);
			brick->alloc_count++;
			
			/* during the open lock, somebody might have raced
			 * against us at the same base_pos...
			 */
			goto again;
		}
			
		bf = container_of(brick->free_anchor.next, struct buf_head, bf_lru_head);
		list_del(&bf->bf_lru_head);
#if 0
		if (unlikely(
			   !list_empty(&bf->bf_hash_head) ||
			   !list_empty(&bf->bf_io_pending_anchor) ||
			   !list_empty(&bf->bf_again_write_pending_anchor)
			   )) {
			MARS_ERR("free bf ist member in lists!\n");
		}
#endif
		MARS_DBG("buf_get() bf=%p\n", bf);

		bf->bf_brick = brick;
		atomic_set(&bf->bf_bio_count, 0);
		//INIT_LIST_HEAD(&bf->bf_mref_anchor);
		INIT_LIST_HEAD(&bf->bf_lru_head);
		INIT_LIST_HEAD(&bf->bf_hash_head);
		INIT_LIST_HEAD(&bf->bf_io_pending_anchor);
		INIT_LIST_HEAD(&bf->bf_again_write_pending_anchor);

		bf->bf_pos = base_pos;
		bf->bf_base_index = ((unsigned int)base_pos) >> brick->backing_order;
		bf->bf_flags = 0;
		atomic_set(&bf->bf_count, 0);

		hash_insert(brick, bf);
		brick->current_count++;
	}

	mref_a->bfa_bf = bf;
	CHECK_SPIN(&bf->bf_count, 0);
	atomic_inc(&bf->bf_count);
	MARS_DBG("bf=%p initial bf_count=%d\n", bf, atomic_read(&bf->bf_count));

	list_del_init(&bf->bf_lru_head);
	mref->ref_flags = bf->bf_flags;

	traced_unlock(&brick->buf_lock, flags);

	mref->ref_data = bf->bf_data + base_offset;

	CHECK_SPIN(&mref->ref_count, 1);

	return mref->ref_len;

done:
	return status;
}

//#define FAST
static void __bf_put(struct buf_head *bf)
{
	struct buf_brick *brick;
	int bf_count;
	unsigned long flags;

	MARS_DBG("bf=%p bf_count=%d\n", bf, bf_count);
	CHECK_SPIN(&bf->bf_count, 1);

#ifdef FAST
	if (!atomic_dec_and_test(&bf->bf_count))
		return;
	MARS_DBG("ZERO_COUNT\n");
#endif

	brick = bf->bf_brick;

	traced_lock(&brick->buf_lock, flags);

#ifdef FAST
        /* NOTE: this may race against the above atomic_dec_and_test().
	 * But in worst case, nothing happens.
	 * So this race is ok.
	 */
	bf_count = atomic_read(&bf->bf_count);
#else
	if (!atomic_dec_and_test(&bf->bf_count)) {
		traced_unlock(&brick->buf_lock, flags);
		return;
	}
	MARS_DBG("ZERO_COUNT\n");
	bf_count = 0;
#endif
	if (likely(bf_count <= 0)) {
		struct list_head *where = &brick->lru_anchor;
		if (unlikely(bf_count < 0)) {
			atomic_set(&bf->bf_count, 0);
			MARS_ERR("bf_count UNDERRUN %d\n", bf_count);
		}
#if 1
		if (unlikely(!list_empty(&bf->bf_io_pending_anchor))) {
			MARS_ERR("bf_io_pending_anchor is not empty!\n");
		}
		if (unlikely(!list_empty(&bf->bf_again_write_pending_anchor))) {
			MARS_ERR("bf_again_write_pending_anchor is not empty!\n");
		}
#endif
		if (unlikely(!(bf->bf_flags & MARS_REF_UPTODATE))) {
			list_del_init(&bf->bf_hash_head);
			brick->current_count--;
			where = &brick->free_anchor;
		}
		list_del(&bf->bf_lru_head);
		list_add(&bf->bf_lru_head, where);
	} // else no harm can happen

	// lru freeing (this is completeley independent from bf)
	__lru_free(brick);
	__prune_cache(brick, brick->max_count * 2, &flags);

	traced_unlock(&brick->buf_lock, flags);
}

static void _buf_ref_put(struct buf_mars_ref_aspect *mref_a)
{
	struct mars_ref_object *mref = mref_a->object;
	struct buf_head *bf;

	CHECK_SPIN(&mref->ref_count, 1);

	if (!atomic_dec_and_test(&mref->ref_count))
		return;

	bf = mref_a->bfa_bf;
	if (bf) {
		MARS_DBG("buf_ref_put() mref=%p mref_a=%p bf=%p\n", mref, mref_a, bf);
		__bf_put(bf);
	}

	buf_free_mars_ref(mref);
}

static void buf_ref_put(struct buf_output *output, struct mars_ref_object *mref)
{
	struct buf_mars_ref_aspect *mref_a;
	mref_a = buf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_FAT("cannot get aspect\n");
		return;
	}
	_buf_ref_put(mref_a);
}

static void _buf_endio(struct mars_ref_object *mref)
{
	int error = mref->cb_error;
	struct bio *bio = mref->orig_bio;
	MARS_DBG("_buf_endio() mref=%p bio=%p\n", mref, bio);
	if (bio) {
		if (error < 0) {
			MARS_ERR("_buf_endio() error=%d bi_size=%d\n", error, bio->bi_size);
		}
		if (error > 0)
			error = 0;
		bio_endio(bio, error);
		bio_put(bio);
	} else {
		//...
	}
}

static void _buf_bio_callback(struct bio *bio, int code);

static int _buf_make_bios(struct buf_brick *brick, struct buf_head *bf, void *start_data, loff_t start_pos, int start_len, int rw)
{
	struct buf_input *input;
	LIST_HEAD(tmp);
	int status = EINVAL;
	int iters = 0;

#if 1
	loff_t bf_end = bf->bf_pos + brick->backing_size;
	loff_t end_pos;
	if (start_pos < bf->bf_pos || start_pos >= bf_end) {
		MARS_ERR("bad start_pos %llu (%llu ... %llu)\n", start_pos, bf->bf_pos, bf_end);
		goto done;
	}
	end_pos = start_pos + start_len;
	if (end_pos <= bf->bf_pos || end_pos > bf_end) {
		MARS_ERR("bad end_pos %llu (%llu ... %llu)\n", end_pos, bf->bf_pos, bf_end);
		goto done;
	}
	if (!start_data) {
		MARS_ERR("bad start_data\n");
		goto done;
	}
	if (start_len <= 0) {
		MARS_ERR("bad start_len %d\n", start_len);
		goto done;
	}
#endif
	status = -ENOMEM;
	while (start_len > 0) {
		struct mars_ref_object *mref;
		struct buf_mars_ref_aspect *mref_a;
		struct bio *bio = NULL;
		int len;

		mref = buf_alloc_mars_ref(brick->outputs[0], &brick->mref_object_layout);
		if (unlikely(!mref))
			break;

		mref_a = buf_mars_ref_get_aspect(brick->outputs[0], mref);
		if (unlikely(!mref_a)) {
			buf_free_mars_ref(mref);
			break;
		}

		list_add(&mref_a->tmp_head, &tmp);
		mref_a->bfa_bf = bf;

		len = make_bio(brick, &bio, start_data, start_pos, start_len);
		if (unlikely(len <= 0 || !bio)) {
			buf_free_mars_ref(mref);
			break;
		}

		bio->bi_private = mref_a;
		bio->bi_end_io = _buf_bio_callback;
		bio->bi_rw = rw;
		mref->cb_ref_endio = _buf_endio;

		mars_ref_attach_bio(mref, bio);

		start_data += len;
		start_pos += len;
		start_len -= len;
		iters++;
	}
	if (!start_len)
		status = 0;
#if 1
	if (iters != 1) {
		MARS_INF("start_pos=%lld start_len=%d iters=%d, status=%d\n", start_pos, start_len, iters, status);
	}
	iters = 0;
#endif

	input = brick->inputs[0];
	while (!list_empty(&tmp)) {
		struct mars_ref_object *mref;
		struct buf_mars_ref_aspect *mref_a;
		mref_a = container_of(tmp.next, struct buf_mars_ref_aspect, tmp_head);
		mref = mref_a->object;
		list_del_init(&mref_a->tmp_head);
		iters++;

		if (status < 0) { // clean up
			mref->cb_error = status;
			mref->cb_ref_endio(mref);
#if 0
			if (mref->orig_bio)
				bio_put(mref->orig_bio);
#endif
			buf_free_mars_ref(mref);
			continue;
		}

		/* Remember the number of bios we are submitting.
		 */
		CHECK_SPIN(&bf->bf_bio_count, 0);
		atomic_inc(&bf->bf_bio_count);

		MARS_DBG("starting buf IO mref=%p bio=%p bf=%p bf_count=%d bf_bio_count=%d\n", mref, mref->orig_bio, bf, atomic_read(&bf->bf_count), atomic_read(&bf->bf_bio_count));
#if 1
		GENERIC_INPUT_CALL(input, mars_ref_io, mref, rw);
#else
		// fake IO for testing
		mref->cb_error = status;
		mref->cb_ref_endio(mref);
#if 0
		if (mref->orig_bio)
			bio_put(mref->orig_bio);
#endif
		buf_free_mars_buf(mref);
#endif
	}
#if 1
	if (iters != 1) {
		MARS_INF("start_pos=%lld start_len=%d iters=%d, status=%d\n", start_pos, start_len, iters, status);
	}
	iters = 0;
#endif
done:
	return status;
}

/* This is called from the bio layer.
 */
static void _buf_bio_callback(struct bio *bio, int code)
{
	struct buf_mars_ref_aspect *mref_a;
	struct buf_head *bf;
	struct buf_brick *brick;
	void  *start_data = NULL;
	loff_t start_pos = 0;
	int    start_len = 0;
	int old_flags;
	unsigned long flags;
	LIST_HEAD(tmp);
#if 1
	int count = 0;
#endif

	mref_a = bio->bi_private;
	bf = mref_a->bfa_bf;

	MARS_DBG("_buf_bio_callback() mref=%p bio=%p bf=%p bf_count=%d bf_bio_count=%d code=%d\n", mref_a->object, bio, bf, atomic_read(&bf->bf_count), atomic_read(&bf->bf_bio_count), code);

	if (unlikely(code < 0)) {
		MARS_ERR("BIO ERROR %d (old=%d)\n", code, bf->bf_bio_status);
		// this can race, but we don't worry about the exact error code
		bf->bf_bio_status = code;
	}

	CHECK_SPIN(&bf->bf_bio_count, 1);
	if (!atomic_dec_and_test(&bf->bf_bio_count))
		return;

	MARS_DBG("_buf_bio_callback() ZERO_COUNT mref=%p bio=%p bf=%p code=%d\n", mref_a->object, bio, bf, code);

	brick = bf->bf_brick;

	// get an extra reference, to avoid freeing bf underneath during callbacks
	CHECK_SPIN(&bf->bf_count, 1);
	atomic_inc(&bf->bf_count);

	traced_lock(&brick->buf_lock, flags);

	// update flags. this must be done before the callbacks.
	old_flags = bf->bf_flags;
	if (!bf->bf_bio_status && (old_flags & MARS_REF_READING)) {
		bf->bf_flags |= MARS_REF_UPTODATE;
	}
	// clear the flags, callbacks must not see them. may be re-enabled later.
	bf->bf_flags &= ~(MARS_REF_READING | MARS_REF_WRITING);

	/* Remember current version of pending list.
	 * This is necessary because later the callbacks might
	 * change it underneath.
	 */
	if (!list_empty(&bf->bf_io_pending_anchor)) {
		struct list_head *next = bf->bf_io_pending_anchor.next;
		list_del_init(&bf->bf_io_pending_anchor);
		list_add_tail(&tmp, next);
	}

	/* Move pending jobs to work.
	 * This is in essence an automatic restart mechanism.
	 * do this before the callbacks, because they may start
	 * new IOs. If not done in the right order, this could violate
	 * IO ordering semantics.
	 */
	while (!list_empty(&bf->bf_again_write_pending_anchor)) {
		struct buf_mars_ref_aspect *mref_a = container_of(bf->bf_again_write_pending_anchor.next, struct buf_mars_ref_aspect, bfc_pending_head);
		struct mars_ref_object *mref = mref_a->object;
		if (mref_a->bfa_bf != bf) {
			MARS_ERR("bad pointers %p != %p\n", mref_a->bfa_bf, bf);
		}
#if 1
		if (!(++count % 1000)) {
			MARS_ERR("endless loop 1\n");
		}
#endif
		list_del_init(&mref_a->bfc_pending_head);
		list_add_tail(&mref_a->bfc_pending_head, &bf->bf_io_pending_anchor);

		// re-enable flags
		bf->bf_flags |= MARS_REF_WRITING;
		bf->bf_bio_status = 0;

		if (!start_len) {
			// first time: only flush the affected area
			start_data = mref->ref_data;
			start_pos = mref->ref_pos;
			start_len = mref->ref_len;
		} else if (start_data != mref->ref_data ||
			  start_pos != mref->ref_pos ||
			  start_len != mref->ref_len) {
			// another time: flush the whole buffer
			start_data = bf->bf_data;
			start_pos = bf->bf_pos;
			start_len = brick->backing_size;
		}
	}

	traced_unlock(&brick->buf_lock, flags);

	/* Signal success by calling all callbacks.
	 * Thanks to the tmp list, we can do this outside the spinlock.
	 */
	count = 0;
	while (!list_empty(&tmp)) {
		struct buf_mars_ref_aspect *mref_a = container_of(tmp.next, struct buf_mars_ref_aspect, bfc_pending_head);
		struct mars_ref_object *mref = mref_a->object;

		if (mref_a->bfa_bf != bf) {
			MARS_ERR("bad pointers %p != %p\n", mref_a->bfa_bf, bf);
		}
#if 1
		if (!(++count % 1000)) {
			MARS_ERR("endless loop 2\n");
		}
#endif
		CHECK_SPIN(&mref->ref_count, 1);
		list_del_init(&mref_a->bfc_pending_head);

		// update infos for callbacks, they may inspect it.
		mref->ref_flags = bf->bf_flags;
		mref->cb_error = bf->bf_bio_status;

		atomic_dec(&brick->nr_io_pending);

		mref->cb_ref_endio(mref);

		_buf_ref_put(mref_a);
	}

	if (start_len) {
		MARS_DBG("ATTENTION %d\n", start_len);
		_buf_make_bios(brick, bf, start_data, start_pos, start_len, WRITE);
	}
	// drop the extra reference from above
	__bf_put(bf);
}

static void buf_ref_io(struct buf_output *output, struct mars_ref_object *mref, int rw)
{
	struct buf_brick *brick = output->brick;
	struct buf_mars_ref_aspect *mref_a;
	struct buf_head *bf;
	void  *start_data = NULL;
	loff_t start_pos = 0;
	int    start_len = 0;
	int status = -EINVAL;
	bool delay = false;
	unsigned long flags;

	if (unlikely(!mref)) {
		MARS_FAT("internal problem: forgotten to supply mref\n");
		goto fatal;
	}
	mref_a = buf_mars_ref_get_aspect(output, mref);
	if (unlikely(!mref_a)) {
		MARS_ERR("internal problem: mref aspect does not work\n");
		goto fatal;
	}

	/* Grab an extra reference.
	 * This will be released later in _buf_bio_callback() after
	 * calling the callbacks.
	 */
	CHECK_SPIN(&mref->ref_count, 1);
	atomic_inc(&mref->ref_count);

	bf = mref_a->bfa_bf;
	if (unlikely(!bf)) {
		MARS_ERR("internal problem: forgotten bf\n");
		goto callback;
	}

	CHECK_SPIN(&bf->bf_count, 1);

	if (rw != READ) {
		if (unlikely(mref->ref_may_write == READ)) {
			MARS_ERR("sorry, forgotten to set ref_may_write\n");
			goto callback;
		}
		if (unlikely(!(bf->bf_flags & MARS_REF_UPTODATE))) {
			MARS_ERR("sorry, writing is only allowed on UPTODATE buffers\n");
			goto callback;
		}
	}

	mref->ref_rw = rw;

	traced_lock(&brick->buf_lock, flags);

#if 1
	if (jiffies - brick->last_jiffies >= 30 * HZ) {
		int hit = atomic_read(&brick->hit_count);
		int miss = atomic_read(&brick->miss_count);
		int perc = hit * 100 * 100 / (hit + miss);
		MARS_INF("STATISTICS: current=%d alloc=%d io_pending=%d hit=%d (%d.%02d%%) miss=%d io=%d\n", brick->current_count, brick->alloc_count, atomic_read(&brick->nr_io_pending), hit, perc / 100, perc % 100, miss, atomic_read(&brick->io_count));
		brick->last_jiffies = jiffies;
	}
#endif

	if (!list_empty(&mref_a->bfc_pending_head)) {
		MARS_ERR("trying to start IO on an already started mref\n");
		goto already_done;
	}

	if (rw) { // WRITE
		if (bf->bf_flags & MARS_REF_READING) {
			MARS_ERR("bad bf_flags %d\n", bf->bf_flags);
		}
		if (!(bf->bf_flags & MARS_REF_WRITING)) {
			// by definition, a writeout buffer is uptodate
			bf->bf_flags |= (MARS_REF_WRITING | MARS_REF_UPTODATE);
			bf->bf_bio_status = 0;
#if 1
			start_data = mref->ref_data;
			start_pos = mref->ref_pos;
			start_len = mref->ref_len;
#else // only for testing: write the full buffer
			start_data = (void*)((unsigned long)mref->ref_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
#endif
			list_add(&mref_a->bfc_pending_head, &bf->bf_io_pending_anchor);
			delay = true;
		} else {
			list_add(&mref_a->bfc_pending_head, &bf->bf_again_write_pending_anchor);
			delay = true;
			MARS_DBG("postponing %lld %d\n", mref->ref_pos, mref->ref_len);
		}
	} else { // READ
		if (bf->bf_flags & (MARS_REF_UPTODATE | MARS_REF_WRITING)) {
			goto already_done;
		}
		if (!(bf->bf_flags & MARS_REF_READING)) {
			bf->bf_flags |= MARS_REF_READING;
			bf->bf_bio_status = 0;

			// always read the whole buffer.
			start_data = (void*)((unsigned long)mref->ref_data & ~(unsigned long)(brick->backing_size - 1));
			start_pos = mref->ref_pos & ~(loff_t)(brick->backing_size - 1);
			start_len = brick->backing_size;
		}
		list_add(&mref_a->bfc_pending_head, &bf->bf_io_pending_anchor);
		delay = true;
	}

	mref->ref_flags = bf->bf_flags;
	mref->cb_error = bf->bf_bio_status;

	if (likely(delay)) {
		atomic_inc(&brick->nr_io_pending);
		atomic_inc(&brick->io_count);
	}

	traced_unlock(&brick->buf_lock, flags);

	if (!start_len) {
		// nothing to start, IO is already started.
		goto no_callback;
	}

	status = _buf_make_bios(brick, bf, start_data, start_pos, start_len, rw);
	if (likely(status >= 0)) {
		/* No immediate callback, this time.
		 * Callbacks will be called later from _buf_bio_callback().
		 */
		goto no_callback;
	}

	MARS_ERR("error %d during buf_ref_io()\n", status);
	buf_ref_put(output, mref);
	goto callback;

already_done:
	mref->ref_flags = bf->bf_flags;
	status = bf->bf_bio_status;

	traced_unlock(&brick->buf_lock, flags);

callback:
	mref->cb_error = status;

	mref->cb_ref_endio(mref);

no_callback:
	if (!delay) {
		buf_ref_put(output, mref);
	} // else the ref_put() will be later carried out upon IO completion.

fatal: // no chance to call callback: may produce hanging tasks :(
	;
}

//////////////// object / aspect constructors / destructors ///////////////

static int buf_mars_ref_aspect_init_fn(struct generic_aspect *_ini, void *_init_data)
{
	struct buf_mars_ref_aspect *ini = (void*)_ini;
	ini->bfa_bf = NULL;
	INIT_LIST_HEAD(&ini->bfc_pending_head);
	INIT_LIST_HEAD(&ini->tmp_head);
	return 0;
}

MARS_MAKE_STATICS(buf);

////////////////////// brick constructors / destructors ////////////////////

static int buf_brick_construct(struct buf_brick *brick)
{
	int i;
	brick->backing_order = 5; // TODO: make this configurable
	brick->backing_size = PAGE_SIZE << brick->backing_order;
	brick->max_count = 32; // TODO: make this configurable
	brick->current_count = 0;
	brick->alloc_count = 0;
	atomic_set(&brick->nr_io_pending, 0);
	spin_lock_init(&brick->buf_lock);
	INIT_LIST_HEAD(&brick->free_anchor);
	INIT_LIST_HEAD(&brick->lru_anchor);
	for (i = 0; i < MARS_BUF_HASH_MAX; i++) {
		INIT_LIST_HEAD(&brick->cache_anchors[i]);
	}
	return 0;
}

static int buf_output_construct(struct buf_output *output)
{
	return 0;
}

static int buf_brick_destruct(struct buf_brick *brick)
{
	unsigned long flags;

	traced_lock(&brick->buf_lock, flags);

	brick->max_count = 0;
	__lru_free(brick);
	__prune_cache(brick, 0, &flags);

	traced_unlock(&brick->buf_lock, flags);

	return 0;
}

///////////////////////// static structs ////////////////////////

static struct buf_brick_ops buf_brick_ops = {
};

static struct buf_output_ops buf_output_ops = {
	.make_object_layout = buf_make_object_layout,
	.mars_get_info = buf_get_info,
	.mars_ref_get = buf_ref_get,
	.mars_ref_put = buf_ref_put,
	.mars_ref_io = buf_ref_io,
};

static const struct buf_input_type buf_input_type = {
	.type_name = "buf_input",
	.input_size = sizeof(struct buf_input),
};

static const struct buf_input_type *buf_input_types[] = {
	&buf_input_type,
};

static const struct buf_output_type buf_output_type = {
	.type_name = "buf_output",
	.output_size = sizeof(struct buf_output),
	.master_ops = &buf_output_ops,
	.output_construct = &buf_output_construct,
	.aspect_types = buf_aspect_types,
	.layout_code = {
		[BRICK_OBJ_MARS_REF] = LAYOUT_ALL,
	}
};

static const struct buf_output_type *buf_output_types[] = {
	&buf_output_type,
};

const struct buf_brick_type buf_brick_type = {
	.type_name = "buf_brick",
	.brick_size = sizeof(struct buf_brick),
	.max_inputs = 1,
	.max_outputs = 1,
	.master_ops = &buf_brick_ops,
	.default_input_types = buf_input_types,
	.default_output_types = buf_output_types,
	.brick_construct = &buf_brick_construct,
	.brick_destruct = &buf_brick_destruct,
};
EXPORT_SYMBOL_GPL(buf_brick_type);

////////////////// module init stuff /////////////////////////

static int __init init_buf(void)
{
	printk(MARS_INFO "init_buf()\n");
	return buf_register_brick_type();
}

static void __exit exit_buf(void)
{
	printk(MARS_INFO "exit_buf()\n");
	buf_unregister_brick_type();
}

MODULE_DESCRIPTION("MARS buf brick");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_buf);
module_exit(exit_buf);
