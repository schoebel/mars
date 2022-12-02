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

#include <linux/module.h>

/* Needed since 9a07000400c853c
 * detected via d3d1e320d43a7ba
 */
#include <linux/sched.h>
#ifndef __sched
#include <linux/sched/xacct.h>
#endif

#include "mars.h"

#ifdef ENABLE_MARS_QIO

#include "lib_qio_rw.h"

#include <linux/backing-dev.h>

#define MARS_MAX_TRANSFER (128 * 1024)

#define MARS_MAX_RW_COUNT (MAX_RW_COUNT > MARS_MAX_TRANSFER ?	\
			   MARS_MAX_TRANSFER :\
			   MAX_RW_COUNT)

#define MARS_NOT_STARTED (-EHWPOISON)

/******** KONVETIONS ****/

//#define KONVENTION_RET_LEN

/* Some code stolen from fs/ext4/file.c ext4_file_read_iter()
 * and reduced / adapted to qio_rw.
 * TODO: adapt this to any upstream kernel changes.
 */
static
ssize_t qio_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	if (!iov_iter_count(to))
		return 0; /* skip atime */

	return generic_file_read_iter(iocb, to);
}

/* Some code stolen from fs/ext4/file.c ext4_file_write_iter() => ext4_buffered_write_iter()
 * and reduced / adapted to qio_rw.
 * TODO: adapt this to any upstream kernel changes.
 */
static
ssize_t qio_file_write_iter(struct kiocb *iocb, struct iov_iter *from,
			    bool wait_for_sync)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

	inode_lock(inode);

	current->backing_dev_info = inode_to_bdi(inode);
	ret = generic_perform_write(iocb->ki_filp, from, iocb->ki_pos);
	current->backing_dev_info = NULL;

	inode_unlock(inode);

	if (likely(ret > 0)) {
		iocb->ki_pos += ret;
		if (wait_for_sync)
			ret = generic_write_sync(iocb, ret);
	}

	return ret;
}

#ifndef KONVENTION_RET_LEN /* only for elder kernels */
static
int __fake_readahead(struct file *file,
		      loff_t pos, int len)
{
	int err = 0;
	pgoff_t index;

	for (index = pos / PAGE_SIZE;
	     index <= (pos + len - 1) / PAGE_SIZE;
	     index++) {
		struct page *tmp_page;

		/* Stolen from fs/f2fs/super.c f2fs_quota_read()
		 */
	repeat:
		tmp_page =
			read_cache_page_gfp(file->f_mapping,
					    index,
					    GFP_NOFS);
		if (IS_ERR(tmp_page) && PTR_ERR(tmp_page) == -ENOMEM) {
			congestion_wait(BLK_RW_ASYNC, HZ/50);
			goto repeat;
		}
	}
	return err;
}
#endif

#define QIO_MAX_KVEC (MARS_MAX_RW_COUNT / PAGE_SIZE + 2)

int qio_init_kvec(struct kvec iov[],
		  void *buf, size_t count)
{
	__u64 segment = (__u64)buf / PAGE_SIZE;
	__u64 first_usable_len;
	__u64 this_len;
	int nr = 0;

	first_usable_len = (__u64)buf - segment * PAGE_SIZE;
	if (!first_usable_len)
		first_usable_len = PAGE_SIZE;
	this_len = first_usable_len;
	if (count < first_usable_len)
		this_len = count;
	while (count > 0) {
		iov[nr].iov_base = buf;
		iov[nr].iov_len = this_len;
		buf += this_len;
		count -= this_len;
		nr++;
		this_len = count;
		if (this_len > PAGE_SIZE)
			this_len = PAGE_SIZE;
		if (this_len > count)
			this_len = count;
	}
	return nr;
}

/* Some code stolen from fs/read_write.c __kernel_read()
 * and adapted to qio_rw.
 * TODO: adapt this to any upstream kernel changes.
 */
static
ssize_t qio_read_start(struct file *file,
		       void *buf, size_t count,
		       loff_t *pos,
		       void *private,
		       bool nowait)
{
	const size_t real_count = min_t(size_t, count, MARS_MAX_RW_COUNT);
	struct qio_rw *qio_rw	= private;
	struct kiocb  *kiocb	= &qio_rw->kiocb;
	struct iov_iter *iter	= &qio_rw->from_to;
	ssize_t ret;
	int nr_segs;
	struct kvec iov[QIO_MAX_KVEC];

	if (WARN_ON_ONCE(!(file->f_mode & FMODE_READ)))
		return -EINVAL;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;

	nr_segs = qio_init_kvec(iov, buf, real_count);

	/*
	 * Also fail if ->read_iter and ->read are both wired up as that
	 * implies very convoluted semantics.
	 */
	if (unlikely(!file->f_op->read_iter || file->f_op->read))
		return -EOPNOTSUPP;

	qio_rw->qio_phase = QIO_RW_RD_STARTED;
	qio_rw->submission_ret = MARS_NOT_STARTED;
	qio_rw->completion_ret = MARS_NOT_STARTED;

	iov_iter_kvec(iter, READ, iov, nr_segs, real_count);

	init_sync_kiocb(kiocb, file);
	kiocb->ki_pos = *pos;
	kiocb->ki_flags = iocb_flags(file);

	/* Some important commentary from mm/filemap.c generic_file_read_iter()
	 */
/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iter:	destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 *
 * The IOCB_NOWAIT flag in iocb->ki_flags indicates that -EAGAIN shall
 * be returned when no data can be read without waiting for I/O requests
 * to complete; it doesn't prevent readahead.
 *
 * The IOCB_NOIO flag in iocb->ki_flags indicates that no new I/O
 * requests shall be made for the read or for readahead.  When no data
 * can be read, -EAGAIN shall be returned.  When readahead would be
 * triggered, a partial, possibly empty read shall be returned.
 *
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code (or 0 if IOCB_NOIO) if nothing was read
 */
	if (nowait) {
		kiocb->ki_flags |= IOCB_NOWAIT;
		/* AFAIKS the following is not necessary (but not tested
		 * for all combinations of kernels with QIO):
		 * kiocb->ki_flags |= IOCB_NOIO;
		 */
	}

	/* In place of file->f_op->read_iter()
	 * Our qio version should not block unnecessarily.
	 */
	ret = qio_file_read_iter(kiocb, iter);

#ifndef KONVENTION_RET_LEN
	/* only for elder kernels */
	if (ret == -EAGAIN) {
		int ahead_status;

		ahead_status = __fake_readahead(file, *pos, real_count);
		/* CHECK: can we better this? */
	}
#endif

	if (ret < 0) {
		qio_rw->submission_ret = ret;
		goto done;
	}
#ifdef KONVENTION_RET_LEN
	if (ret < real_count && ret > 0) {
		ret = -EAGAIN;
		qio_rw->submission_ret = ret;
		goto done;
	}
	if (ret > real_count) {
		ret = -EIO;
		qio_rw->submission_ret = ret;
		goto done;
	}
#else
	/* Adaptation of calling concentions */
	/* Hmm, how can we deal with any short reads?
	 * This type of workaround might cause problems.
	 */
	if (!ret)
		goto done;
#endif
	/* Success. */
	qio_rw->submission_ret = ret;
	*pos += ret;
	add_rchar(current, ret);
	inc_syscr(current);
 done:
	return ret;
}

/* Some code stolen from fs/read_write.c __kernel_write()
 * and adapted to qio_rw.
 * TODO: adapt this to any upstream kernel changes.
 */
static
ssize_t qio_write_start(struct file *file,
			void *buf, size_t count,
			loff_t *pos,
			void *private,
			bool wait_for_sync)
{
	const size_t real_count = min_t(size_t, count, MARS_MAX_RW_COUNT);
	struct qio_rw *qio_rw = private;
	struct kvec iov = {
		.iov_base	= (void *)buf,
		.iov_len	= real_count,
	};
	struct kiocb *kiocb	= &qio_rw->kiocb;
	struct iov_iter *iter	= &qio_rw->from_to;
	ssize_t ret;

	if (WARN_ON_ONCE(!(file->f_mode & FMODE_WRITE)))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	/*
	 * Also fail if ->write_iter and ->write are both wired up as that
	 * implies very convoluted semantics.
	 */
	if (unlikely(!file->f_op->write_iter || file->f_op->write))
		return -EOPNOTSUPP;

	qio_rw->qio_phase = QIO_RW_WR_STARTED;
	qio_rw->submission_ret = MARS_NOT_STARTED;
	qio_rw->completion_ret = MARS_NOT_STARTED;

	iov_iter_kvec(iter, WRITE, &iov, 1, iov.iov_len);

	init_sync_kiocb(kiocb, file);
	kiocb->ki_pos = *pos;
	kiocb->ki_flags = iocb_flags(file);

#if 0 // only for devel testing, to DISAPPEAR
	kiocb->ki_waitq = &qio_rw->wait;
	kiocb->ki_flags |= IOCB_WAITQ;
#endif

#ifndef CONFIG_MARS_TESTING_QIO_UNSAFE_PERFORMANCE
	/* Full kiocb->ki_flags |= IOCB_SYNC; not needed AFAIK */
	/* But the following is ABSOLUTELY needed: */
	kiocb->ki_flags |= IOCB_DSYNC;
#else
#warning DANGEROUS test code - this will ensure CORRUPTED DATA!
#endif
	kiocb->ki_flags |= IOCB_APPEND;

	/* In place of file->f_op->write_iter()
	 * Our qio version should not block unnecessarily.
	 */
	ret = qio_file_write_iter(kiocb, iter, wait_for_sync);

	if (ret < 0) {
		qio_rw->submission_ret = ret;
		goto done;
	}
#ifdef KONVENTION_RET_LEN
	if (ret < real_count && ret > 0) {
		ret = -EAGAIN;
		qio_rw->submission_ret = ret;
		goto done;
	}
	if (ret > real_count) {
		ret = -EIO;
		qio_rw->submission_ret = ret;
		goto done;
	}
#else
	/* Adaptation of calling concentions */
	if (!ret) {
		ret = real_count - iov.iov_len;
	}
#endif
	/* Success. */
	qio_rw->submission_ret = ret;
	*pos = kiocb->ki_pos;
	add_wchar(current, ret);
	inc_syscw(current);
 done:
	return ret;
}

static

ssize_t qio_rw_wait(struct file *file,
		    bool is_write,
		    bool needs_write_sync,
		    void *private)
{
	struct qio_rw *qio_rw = private;
	ssize_t ret;

	/* Corresponds to (not everywhere implemented) IOCB_NOWAIT
	 * thus we need to return the final result right now.
	 */
	ret = qio_rw->submission_ret;
	if (needs_write_sync) {
		ret = generic_write_sync(&qio_rw->kiocb, ret);
	}
	return ret;
}

void init_qio_rw(struct qio_rw *qio_rw)
{
	/* nothing to do here */
}

void exit_qio_rw(struct qio_rw *qio_rw)
{
	/* nothing to do here */
}

const struct qio_rw_operations qio_rw_operations = {
	.qio_read_start = qio_read_start,
	.qio_write_start = qio_write_start,
	.qio_rw_wait = qio_rw_wait,
};

#endif /* ENABLE_MARS_QIO */

int __init init_lib_qio_rw(void)
{
	return 0;
}

void exit_lib_qio_rw(void)
{
	/* nothing to do here */
}
