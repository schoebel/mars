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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/bitops.h>

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING
//#define IO_DEBUGGING

#include "lib_log.h"
#include "brick_wait.h"

__u32 enabled_log_compressions = 0;

__u32 used_log_compression = 0;

atomic_t global_mref_flying = ATOMIC_INIT(0);
EXPORT_SYMBOL_GPL(global_mref_flying);

void exit_logst(struct log_status *logst)
{
	int count = 0;
	log_flush(logst);
	while (atomic_read(&logst->mref_flying) > 0) {
		if (!count++)
			MARS_DBG("waiting for IO terminating...");
		brick_msleep(500);
	}
	if (logst->read_mref) {
		MARS_DBG("putting read_mref\n");
		GENERIC_INPUT_CALL_VOID(logst->input, mref_put, logst->read_mref);
		logst->read_mref = NULL;
	}
	if (logst->log_mref) {
		MARS_DBG("putting log_mref\n");
		GENERIC_INPUT_CALL_VOID(logst->input, mref_put, logst->log_mref);
		logst->log_mref = NULL;
	}
}
EXPORT_SYMBOL_GPL(exit_logst);

void init_logst(struct log_status *logst, struct mars_input *input, loff_t start_pos, loff_t end_pos)
{
	exit_logst(logst);

	memset(logst, 0, sizeof(struct log_status));

	logst->input = input;
	logst->brick = input->brick;
	logst->start_pos = start_pos;
	logst->log_pos = start_pos;
	logst->end_pos = end_pos;
	init_waitqueue_head(&logst->event);
}
EXPORT_SYMBOL_GPL(init_logst);

#define MARS_LOG_CB_MAX 32

struct log_cb_info {
	struct mref_object *mref;
	struct log_status *logst;
	struct semaphore mutex;
	atomic_t refcount;
	int nr_cb;
	void (*endios[MARS_LOG_CB_MAX])(void *private, int error);
	void *privates[MARS_LOG_CB_MAX];
};

static
void put_log_cb_info(struct log_cb_info *cb_info)
{
	if (atomic_dec_and_test(&cb_info->refcount)) {
		brick_mem_free(cb_info);
	}
}

static
void _do_callbacks(struct log_cb_info *cb_info, int error)
{
	int i;
	down(&cb_info->mutex);
	for (i = 0; i < cb_info->nr_cb; i++) {
		void (*end_fn)(void *private, int error);
		end_fn = cb_info->endios[i];
		cb_info->endios[i] = NULL;
		if (end_fn) {
			end_fn(cb_info->privates[i], error);
		}
	}
	up(&cb_info->mutex);
}

static
void log_write_endio(struct generic_callback *cb)
{
	struct log_cb_info *cb_info = cb->cb_private;
	struct log_status *logst;

	LAST_CALLBACK(cb);
	CHECK_PTR(cb_info, err);

	if (cb_info->mref) {
		mars_trace(cb_info->mref, "log_endio");
		mars_log_trace(cb_info->mref);
	}

	logst = cb_info->logst;
	CHECK_PTR(logst, done);

	MARS_IO("nr_cb = %d\n", cb_info->nr_cb);

	_do_callbacks(cb_info, cb->cb_error);

 done:
	put_log_cb_info(cb_info);
	atomic_dec(&logst->mref_flying);
	atomic_dec(&global_mref_flying);
	if (logst->signal_event && logst->signal_flag)
		brick_wake_flagged(logst->signal_event,
				   *(logst->signal_flag));

	return;

err:
	MARS_FAT("internal pointer corruption\n");
}

static
int log_compress(struct log_status *logst, int len,
		 int *padded_len,
		 __u32 *result_flags)
{
	struct mref_object *mref = logst->log_mref;
	void *inplace_buf;
	void *compr_buf;
	int compr_len;
	int res;

	if (unlikely(!mref || !mref->ref_data || len <= 0))
		return 0;

	compr_len = len + compress_overhead;
	compr_buf = brick_mem_alloc(compr_len);
	inplace_buf = mref->ref_data + logst->payload_offset;

	res = mars_compress(inplace_buf, len,
			    compr_buf, compr_len,
			    enabled_log_compressions,
			    result_flags);

	/* pad the resulting length */
	if (res > 0) {
		int pad_len = ((res + (_LOG_PAD - 1)) / _LOG_PAD) * _LOG_PAD;

		/* Did compression pay off? */
		if (pad_len < len) {
			*padded_len = pad_len;
			used_log_compression = *result_flags;
			memcpy(inplace_buf, compr_buf, res);
		} else {
			*padded_len = len;
			res = 0;
		}
	}
	brick_mem_free(compr_buf);
	return res;
}

void log_flush(struct log_status *logst)
{
	struct mref_object *mref = logst->log_mref;
	struct log_cb_info *cb_info;
	int align_size;
	int gap;

	if (!mref || !logst->count)
		return;

	gap = 0;
	align_size = (logst->align_size / PAGE_SIZE) * PAGE_SIZE;
	if (align_size > 0) {
		// round up to next alignment border
		int align_offset = logst->offset & (align_size-1);
		if (align_offset > 0) {
			int restlen = mref->ref_len - logst->offset;
			gap = align_size - align_offset;
			if (unlikely(gap > restlen)) {
				gap = restlen;
			}
		}
	}
	if (gap > 0) {
		// don't leak information from kernelspace
		memset(mref->ref_data + logst->offset, 0, gap);
		logst->offset += gap;
	}
	mref->ref_len = logst->offset;
	memcpy(&logst->log_pos_stamp, &logst->tmp_pos_stamp, sizeof(logst->log_pos_stamp));

	cb_info = logst->private;
	logst->private = NULL;
	SETUP_CALLBACK(mref, log_write_endio, cb_info);
	cb_info->logst = logst;
	mref->ref_flags |= MREF_WRITE | MREF_MAY_WRITE;

	mars_trace(mref, "log_flush");

	atomic_inc(&logst->mref_flying);
	atomic_inc(&global_mref_flying);

	GENERIC_INPUT_CALL_VOID(logst->input, mref_io, mref);
	GENERIC_INPUT_CALL_VOID(logst->input, mref_put, mref);

	logst->log_pos += logst->offset;
	logst->offset = 0;
	logst->count = 0;
	logst->log_mref = NULL;

	put_log_cb_info(cb_info);
}
EXPORT_SYMBOL_GPL(log_flush);

void *log_reserve(struct log_status *logst, struct log_header *lh)
{
	struct log_cb_info *cb_info = logst->private;
	struct mref_object *mref;
	void *data;
	short total_len = lh->l_len + OVERHEAD;
	int offset;
	int status;

	if (unlikely(lh->l_len <= 0 || lh->l_len > logst->max_size)) {
		MARS_ERR("trying to write %d bytes, max allowed = %d\n", lh->l_len, logst->max_size);
		goto err;
	}

	MARS_IO("reserving %d bytes at %lld\n", lh->l_len, logst->log_pos);

	mref = logst->log_mref;
	if ((mref && total_len > mref->ref_len - logst->offset)
	   || !cb_info || cb_info->nr_cb >= MARS_LOG_CB_MAX) {
		log_flush(logst);
	}

	mref = logst->log_mref;
	if (!mref) {
		if (unlikely(logst->private)) {
			MARS_ERR("oops\n");
			brick_mem_free(logst->private);
		}
		logst->private = brick_zmem_alloc(sizeof(struct log_cb_info));
		if (unlikely(!logst->private)) {
			MARS_ERR("no memory\n");
			goto err;
		}
		cb_info = logst->private;
		sema_init(&cb_info->mutex, 1);
		atomic_set(&cb_info->refcount, 2);

		mref = mars_alloc_mref(logst->brick);
		if (unlikely(!mref)) {
			MARS_ERR("no mref\n");
			goto err;
		}
		cb_info->mref = mref;

		mref->ref_pos = logst->log_pos;
		mref->ref_len = logst->chunk_size ? logst->chunk_size : total_len;
		mref->ref_flags = MREF_MAY_WRITE;
		mref->ref_prio = logst->io_prio;

		for (;;) {
			status = GENERIC_INPUT_CALL(logst->input, mref_get, mref);
			if (likely(status >= 0)) {
				break;
			}
			if (status != -ENOMEM && status != -EAGAIN) {
				MARS_ERR("mref_get() failed, status = %d\n", status);
				goto err_free;
			}
			brick_msleep(100);
		}

		mars_trace(mref, "log_start");

		if (unlikely(mref->ref_len < total_len)) {
			MARS_ERR("ref_len = %d total_len = %d\n", mref->ref_len, total_len);
			goto put;
		}

		logst->offset = 0;
		logst->log_mref = mref;
	}

	offset = logst->offset;
	data = mref->ref_data;
	DATA_PUT(data, offset, START_MAGIC);
	DATA_PUT(data, offset, (char)FORMAT_VERSION);
	logst->validflag_offset = offset;
	DATA_PUT(data, offset, (char)0); // valid_flag
	logst->totallen_offset = offset;
	DATA_PUT(data, offset, total_len); // start of next header
	DATA_PUT(data, offset, lh->l_stamp.tv_sec);
	DATA_PUT(data, offset, lh->l_stamp.tv_nsec);
	DATA_PUT(data, offset, lh->l_pos);
	logst->reallen_offset = offset;
	DATA_PUT(data, offset, lh->l_len);
	logst->decompresslen_offset = offset;
	DATA_PUT(data, offset, (short)0); /* placeholder */
	DATA_PUT(data, offset, (int)0); // spare
	DATA_PUT(data, offset, lh->l_code);
	DATA_PUT(data, offset, (short)0); // spare

	// remember the last timestamp
	memcpy(&logst->tmp_pos_stamp, &lh->l_stamp, sizeof(logst->tmp_pos_stamp));

	logst->payload_offset = offset;
	logst->payload_len = lh->l_len;

	return data + offset;

put:
	GENERIC_INPUT_CALL_VOID(logst->input, mref_put, mref);
	logst->log_mref = NULL;
	return NULL;

err_free:
	mars_free_mref(mref);
	if (logst->private) {
		// TODO: if callbacks are already registered, call them here with some error code
		brick_mem_free(logst->private);
	}
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(log_reserve);

/* Unfortunately, the old logfile format had only 32 bit
 * (4 byte) checksums.
 * By converting the unused l_written to a checksum, we now
 * can use 16 bytes.
 * TODO: new backwards-compatible logfile format with even bigger
 * checksums (32 bytes).
 */
static
void fold_crc(void *src, void *dst)
{
	int i;

	memset(dst, 0, LOG_CHKSUM_SIZE);
	for (i = 0; i < MARS_DIGEST_SIZE; i += LOG_CHKSUM_SIZE) {
		*(__u64*)dst ^= *(__u64*)(src + i);
		*(__u64*)(dst + sizeof(__u64)) ^= *(__u64*)(src + i + sizeof(__u64));
	}
}

bool log_finalize(struct log_status *logst, int len, void (*endio)(void *private, int error), void *private)
{
	struct mref_object *mref = logst->log_mref;
	struct log_cb_info *cb_info = logst->private;
	void *data;
	int offset;
	int restlen;
	int decompr_len;
	int padded_len;
	int nr_cb;
	unsigned char crc[LOG_CHKSUM_SIZE] = {};
	__u32 old_crc = 0;
	__u32 check_flags;
	__u16 crc_flags;
	bool ok = false;

	CHECK_PTR(mref, err);

	if (unlikely(len > logst->payload_len)) {
		MARS_ERR("trying to write more than reserved (%d > %d)\n", len, logst->payload_len);
		goto err;
	}
	restlen = mref->ref_len - logst->offset;
	if (unlikely(len + END_OVERHEAD > restlen)) {
		MARS_ERR("trying to write more than available (%d > %d)\n", len, (int)(restlen - END_OVERHEAD));
		goto err;
	}
	if (unlikely(!cb_info || cb_info->nr_cb >= MARS_LOG_CB_MAX)) {
		MARS_ERR("too many endio() calls\n");
		goto err;
	}

	data = mref->ref_data;

	check_flags = 0;

	/* Run the CRC on the _original_ data, before compression */
	{
		unsigned char checksum[MARS_DIGEST_SIZE];

		check_flags |=
		  mars_digest(usable_digest_mask & ~disabled_log_digests,
			      &used_log_digest,
			      checksum,
			      data + logst->payload_offset, len);

		if (check_flags & MREF_CHKSUM_MD5_OLD)
			old_crc = *(__u32*)checksum;
		else
			fold_crc(checksum, crc);
	}

	/*
	 * Important: when somebody else would be later unable to decompress,
	 * it will then automatically result in a CRC mismatch.
	 */
	decompr_len = 0;
	padded_len = len;
	if (logst->do_compress) {
		__u32 new_check_flags = check_flags;
		int new_len = log_compress(logst, len,
					   &padded_len,
					   &new_check_flags);

		/* When compression did not pay off, treat as uncompressed */
		if (new_len > 0) {
			check_flags = new_check_flags;
			/* exchange the lengths */
			decompr_len = len;
			len = new_len;
		}
	}

	/*
	 * We have only 16 flag bits in the traditional
	 * logfile format, which is in production over
	 * years. To remain compatible, we strip off
	 * non-checksum related bits.
	 */
	crc_flags = check_flags >> _MREF_CHKSUM_MD5_OLD;

	/* Correct the length in the header.
	 */
	offset = logst->decompresslen_offset;
	DATA_PUT(data, offset, (short)decompr_len);
	offset = logst->reallen_offset;
	DATA_PUT(data, offset, (short)len);
	offset = logst->totallen_offset;
	DATA_PUT(data, offset, (short)(padded_len + OVERHEAD));

	/* Write the trailer.
	 */
	offset = logst->payload_offset + padded_len;
	DATA_PUT(data, offset, END_MAGIC);
	DATA_PUT(data, offset, old_crc);
	DATA_PUT(data, offset, (char)1);  // valid_flag copy
	DATA_PUT(data, offset, (char)0);  // spare
	DATA_PUT(data, offset, crc_flags);
	DATA_PUT(data, offset, logst->seq_nr + 1);
	memcpy(data + offset, crc, LOG_CHKSUM_SIZE);
	offset += LOG_CHKSUM_SIZE;

	if (unlikely(offset > mref->ref_len)) {
		MARS_FAT("length calculation was wrong: %d > %d\n", offset, mref->ref_len);
		goto err;
	}
	logst->offset = offset;

	/* This must come last. In case of incomplete
	 * or even overlapping disk transfers, this indicates
	 * the completeness / integrity of the payload at
	 * the time of starting the transfer.
	 */
	offset = logst->validflag_offset;
	barrier();
	DATA_PUT(data, offset, (char)1);

	nr_cb = cb_info->nr_cb++;
	cb_info->endios[nr_cb] = endio;
	cb_info->privates[nr_cb] = private;

	// report success
	logst->seq_nr++;
	logst->count++;
	ok = true;

err:
	return ok;
}
EXPORT_SYMBOL_GPL(log_finalize);

static
void log_read_endio(struct generic_callback *cb)
{
	struct log_status *logst = cb->cb_private;

	LAST_CALLBACK(cb);
	CHECK_PTR(logst, err);
	logst->posix_error_code = cb->cb_error;
	logst->got = true;
	brick_wake_smp(&logst->event);
	return;

err:
	MARS_FAT("internal pointer corruption\n");
}

int log_read(struct log_status *logst,
	     struct log_header *lh,
	     void **payload, int *payload_len,
	     void **dealloc)
{
	struct mref_object *mref;
	int old_offset;
	int status;

	*dealloc = NULL;

restart:
	status = 0;
	mref = logst->read_mref;
	if (!mref || logst->do_free) {
		loff_t this_len;
		if (mref) {
			GENERIC_INPUT_CALL_VOID(logst->input, mref_put, mref);
			logst->read_mref = NULL;
			logst->log_pos += logst->offset;
			logst->offset = 0;
		}

		this_len = logst->end_pos - logst->log_pos;
		if (this_len > logst->chunk_size) {
			this_len = logst->chunk_size;
		} else if (unlikely(this_len <= 0)) {
			MARS_ERR("tried bad IO len %lld, start_pos = %lld log_pos = %lld end_pos = %lld\n", this_len, logst->start_pos, logst->log_pos, logst->end_pos);
			status = -EOVERFLOW;
			goto done;
		}

		mref = mars_alloc_mref(logst->brick);
		if (unlikely(!mref)) {
			MARS_ERR("no mref\n");
			goto done;
		}
		mref->ref_pos = logst->log_pos;
		mref->ref_len = this_len;
		mref->ref_prio = logst->io_prio;

		status = GENERIC_INPUT_CALL(logst->input, mref_get, mref);
		if (unlikely(status < 0)) {
			if (status != -ENODATA) {
				MARS_ERR("mref_get() failed, status = %d\n", status);
			}
			goto done_free;
		}
		if (unlikely(mref->ref_len <= OVERHEAD)) { // EOF
			status = 0;
			goto done_put;
		}

		SETUP_CALLBACK(mref, log_read_endio, logst);

		logst->offset = 0;
		logst->got = false;
		logst->do_free = false;

		GENERIC_INPUT_CALL_VOID(logst->input, mref_io, mref);

		brick_wait_smp(logst->event,
			       logst->got,
			       60 * HZ);
		status = -ETIME;
		if (!logst->got)
			goto done_put;
		status = logst->posix_error_code;
		if (status < 0)
			goto done_put;
		if (mref->ref_len < this_len) {
			/* Short read. May happen when logfiles are
			 * truncated underneath.
			 */
			logst->end_pos = logst->log_pos + mref->ref_len;
		}
		logst->read_mref = mref;
	}

	status = log_scan(mref->ref_data + logst->offset,
			  mref->ref_len - logst->offset,
			  mref->ref_pos,
			  logst->offset,
			  lh,
			  payload,
			  payload_len,
			  dealloc,
			  &logst->seq_nr,
			  &logst->mars_error_code,
			  &logst->byte_code);

	if (unlikely(status == 0)) {
		MARS_ERR("bad logfile scan\n");
		status = -EINVAL;
		if (!logst->mars_error_code)
			logst->mars_error_code = -MARS_ERR_NOSCAN;
		goto done_put;
	}
	if (unlikely(status < 0)) {
		goto done_put;
	}

	// memoize success
	logst->offset += status;
	if (logst->offset + (logst->max_size + OVERHEAD) * 2 >= mref->ref_len) {
		logst->do_free = true;
	}

done:
	if (status == -ENODATA) {
		status = 0; // indicates EOF
	}
	return status;

done_put:
	old_offset = logst->offset;
	if (mref) {
		GENERIC_INPUT_CALL_VOID(logst->input, mref_put, mref);
		logst->read_mref = NULL;
		logst->log_pos += logst->offset;
		logst->offset = 0;
	}
	if (status == -EAGAIN && old_offset > 0) {
		if (*dealloc) {
			brick_mem_free(*dealloc);
		}
		/* safeguard any suspected coherence problems */
		smp_mb();
		goto restart;
	}
	goto done;

done_free:
	if (mref) {
		mars_free_mref(mref);
	}
	logst->read_mref = NULL;
	goto done;

}

static
int _check_crc(struct log_header *lh,
	       void *crc,
	       void *crc_buf,
	       int crc_len,
	       __u32 check_flags,
	       int *mars_error_code)
{
	__u32 invalid_check_flags;
	bool is_invalid = false;
	bool did_simple_retry = false;
	int did_iterative_retry = 0;
	int bit = 0;
	int res;

 retry:
	res = -EBADMSG;
	if (check_flags & (MREF_CHKSUM_ANY - MREF_CHKSUM_MD5_OLD)) {
		unsigned char checksum[MARS_DIGEST_SIZE];
		unsigned char check_crc[LOG_CHKSUM_SIZE];

		mars_digest(check_flags,
			    &used_log_digest,
			    checksum,
			    crc_buf, crc_len);

		fold_crc(checksum, check_crc);
		if (!memcmp(crc, check_crc, LOG_CHKSUM_SIZE))
			res = 0;
	} else if (lh->l_crc_old) {
		unsigned char checksum[MARS_DIGEST_SIZE];
		__u32 old_crc;

		mars_digest(check_flags,
			    &used_log_digest,
			    checksum,
			    crc_buf, crc_len);

		old_crc = *(int*)checksum;
		if (old_crc == lh->l_crc_old)
			res = 0;
	} else if (!did_iterative_retry) {
		invalid_check_flags = check_flags;
		is_invalid = true;
	}
	/* simple retry method */
	if (unlikely(res && !did_simple_retry)) {
		did_simple_retry = true;
		MARS_WRN("RETRY crc check flags=0x%x crc_len=%d\n",
			 check_flags, crc_len);
		check_flags |=
			(usable_digest_mask & MREF_CHKSUM_ANY);
		cond_resched();
		/* safeguard any suspected coherence problems */
		smp_mb();
		goto retry;
	}
	/* when simple retry failed: try the painful iterative method */
	if (unlikely(res)) {
		/* We are desperate. We want to recover as much data
		 * as possible. Performance does no longer matter.
		 * Try to _wildly_ _guess_ what check_flags might by usable.
		 */
		if (!did_iterative_retry) {
			bit = find_first_bit((void *)&usable_digest_mask,
					     sizeof(usable_digest_mask));
		} else if (bit >= _MREF_COMPRESS_LAST) {
			goto failed;
		} else {
			int next_bit =
				find_next_bit((void *)&usable_digest_mask,
					      sizeof(usable_digest_mask),
					      bit + 1);
			if (next_bit <= bit)
				goto failed;
			bit = next_bit;
		}
		if (bit >= 32)
			goto failed;
		check_flags = (1 << bit);
		if (!(check_flags & usable_digest_mask))
			goto failed;
		did_iterative_retry++;
		cond_resched();
		/* safeguard any suspected coherence problems */
		smp_mb();
		goto retry;
	failed:
		MARS_WRN("ITERATIVE RETRY %d failed\n",
			 did_iterative_retry);
	}
	if (is_invalid) {
		if (!*mars_error_code)
			*mars_error_code = -MARS_ERR_CRC_FLAGS;
		MARS_ERR("Found invalid crc flags=0x%x retried=%d+%d\n",
			 invalid_check_flags,
			 did_simple_retry, did_iterative_retry);
	} else if (res < 0 && !*mars_error_code)
		*mars_error_code = -MARS_ERR_CRC_MISMATCH;

	return res;
}

static
int classify_bad_magic(unsigned long long this_magic,
		       unsigned char *found_byte_code,
		       int *mars_error_code)
{
	unsigned long long shifter;
	unsigned char pattern;
	unsigned char byte;
	int j;

	/* Variant 1:
	 * Zero is assumed to be recoverable.
	 */
	if (!this_magic)
		return -ERESTART;

	/* Variant 2:
	 * Repeated bytewise patterns are assumed
	 * to point at
	 *  (a) uninitialized (or defective) disk data.
	 *  (b) problems in RAID hardware, drivers, DMA, etc.
	 *  (c) CONFIG_DEBUG_PAGEALLOC or similar
	 *      kernel-level sisters (also MARS-specific
	 *      ones like CONFIG_MARS_DEBUG_MEM and
	 *      sisters).
	 */
	shifter = this_magic;
	pattern = (unsigned char)shifter;
	for (j = 1; j < sizeof(shifter); j++) {
		shifter >>= 8;
		byte = shifter;
		if (byte != pattern)
			goto no_repeat;
	}
	*found_byte_code = byte;
	if (!*mars_error_code)
		*mars_error_code = -MARS_ERR_MAGIC_REPEATED;
	return -EBADMSG;

 no_repeat:
	/* Last resort:
	 * not enough knowledge what might have happened before.
	 */
	if (!*mars_error_code)
		*mars_error_code = -MARS_ERR_MAGIC_BAD;
	return -EBADRQC;
}

#define RECORD_ERR(code)			\
	if (!*mars_error_code)			\
		*mars_error_code = (code)

int log_scan(void *buf,
	     int len,
	     loff_t file_pos,
	     int file_offset,
	     struct log_header *lh,
	     void **payload, int *payload_len,
	     void **dealloc,
	     unsigned int *seq_nr,
	     int *mars_error_code,
	     int *byte_code)
{
	bool dirty = false;
	unsigned char start_byte_code = 0;
	int offset;
	int i;

	*payload = NULL;
	*payload_len = 0;

	for (i = 0; i < len && i <= len - OVERHEAD; i += sizeof(long)) {
		unsigned char crc[LOG_CHKSUM_SIZE];
		unsigned long long start_magic;
		char format_version;
		char valid_flag;
		short total_len;
		unsigned long long end_magic;
		char valid_copy;
		__u32 check_flags;
		int restlen = 0;
		int crc_len;
		int decompr_len;
		int found_offset;
		int crc_status;
		int advance;
		void *new_buf = NULL;
		void *crc_buf;


		offset = i;
		if (unlikely(i > 0)) {
			MARS_ERR(SCAN_TXT "detected a hole / bad data >= %d\n",
				 SCAN_PAR, i);
			RECORD_ERR(-MARS_ERR_SCAN_HOLE);
			return -EBADMSG;
		}

		DATA_GET(buf, offset, start_magic);
		if (unlikely(start_magic != START_MAGIC)) {
			/* Skip any zeros without notice.
			 * This may be used for future extensions, like
			 * padding at certain places of logfiles.
			 */
			if (start_magic != 0) {
				dirty = true;
				classify_bad_magic(start_magic,
						   &start_byte_code,
						   mars_error_code);
				if (start_byte_code && !*byte_code) {
					*byte_code = start_byte_code;
					MARS_WRN(SCAN_TXT "found repeated byte pattern 0x%02x",
						 SCAN_PAR,
						 start_byte_code);
				}
			}
			continue;
		}

		restlen = len - i;
		if (unlikely(restlen < START_OVERHEAD)) {
			MARS_WRN(SCAN_TXT "magic found, but restlen is too small\n", SCAN_PAR);
			return -EAGAIN;
		}

		DATA_GET(buf, offset, format_version);
		if (unlikely(format_version != FORMAT_VERSION)) {
			MARS_ERR(SCAN_TXT "found unknown data format %d\n",
				 SCAN_PAR,
				 (int)format_version);
			RECORD_ERR(-MARS_ERR_SCAN_FORMAT);
			return -EBADMSG;
		}
		DATA_GET(buf, offset, valid_flag);
		if (unlikely(!valid_flag)) {
			MARS_WRN(SCAN_TXT "data is explicitly marked invalid (was there a short write?)\n",
				 SCAN_PAR);
			RECORD_ERR(-MARS_ERR_SCAN_INVAL);
			continue;
		}
		DATA_GET(buf, offset, total_len);
		if (unlikely(!total_len)) {
			MARS_WRN(SCAN_TXT "advance is zero\n",
				 SCAN_PAR);
			RECORD_ERR(-MARS_ERR_SCAN_ZERO);
			return -ERESTART;
		}
		if (unlikely(total_len < 0)) {
			MARS_WRN(SCAN_TXT "advance %d is wrong\n",
				 SCAN_PAR, total_len);
			RECORD_ERR(-MARS_ERR_SCAN_NEGATIVE);
			return -EBADMSG;
		}
		if (unlikely(total_len > restlen)) {
			MARS_WRN(SCAN_TXT "total_len = %d but available data restlen = %d. Was the logfile truncated?\n",
				 SCAN_PAR,
				 total_len, restlen);
			RECORD_ERR(-MARS_ERR_SCAN_BADLEN);
			return -EAGAIN;
		}

		memset(lh, 0, sizeof(struct log_header));

		DATA_GET(buf, offset, lh->l_stamp.tv_sec);
		DATA_GET(buf, offset, lh->l_stamp.tv_nsec);
		DATA_GET(buf, offset, lh->l_pos);
		DATA_GET(buf, offset, lh->l_len);
		DATA_GET(buf, offset, lh->l_decompress_len);
		offset += 4; // skip spare
		DATA_GET(buf, offset, lh->l_code);
		offset += 2; // skip spare

		found_offset = offset;
		advance = total_len - OVERHEAD;
		if (unlikely(advance <= 0)) {
			MARS_WRN(SCAN_TXT "advance %d is too small\n",
				 SCAN_PAR, advance);
			RECORD_ERR(-MARS_ERR_SCAN_ADVANCE);
			return -ERESTART;
		}
		offset += advance;

		restlen = len - offset;
		if (unlikely(restlen < END_OVERHEAD)) {
			MARS_WRN(SCAN_TXT "restlen %d is too small\n", SCAN_PAR, restlen);
			RECORD_ERR(-MARS_ERR_SCAN_RESTLEN);
			return -EAGAIN;
		}

		DATA_GET(buf, offset, end_magic);
		if (unlikely(end_magic != END_MAGIC)) {
			unsigned char end_byte_code = 0;
			int err;

			MARS_WRN(SCAN_TXT "bad end_magic 0x%llx, is the logfile truncated?\n",
				 SCAN_PAR,
				 end_magic);
			err = classify_bad_magic(end_magic,
						 &end_byte_code,
						 mars_error_code);
			if (end_byte_code && !*byte_code) {
				*byte_code = end_byte_code;
				MARS_WRN(SCAN_TXT "found repeated byte pattern 0x%02x",
					 SCAN_PAR,
					 end_byte_code);
			}
			return err;
		}
		DATA_GET(buf, offset, lh->l_crc_old);
		DATA_GET(buf, offset, valid_copy);

		if (unlikely(valid_copy != 1)) {
			MARS_WRN(SCAN_TXT "found data marked as uncompleted / invalid, len = %d, valid_flag = %d\n",
				 SCAN_PAR,
				 lh->l_len, (int)valid_copy);
			RECORD_ERR(-MARS_ERR_SCAN_INCOMPL);
			return -EBADMSG;
		}

		// skip spares
		offset += 1;

		DATA_GET(buf, offset, lh->l_crc_flags);
		DATA_GET(buf, offset, lh->l_seq_nr);
		memcpy(crc, buf + offset, LOG_CHKSUM_SIZE);
		offset += LOG_CHKSUM_SIZE;

		if (unlikely(lh->l_seq_nr > *seq_nr + 1 && lh->l_seq_nr && *seq_nr)) {
			MARS_ERR(SCAN_TXT "record sequence number %u mismatch, expected was %u\n",
				 SCAN_PAR,
				 lh->l_seq_nr, *seq_nr + 1);
			RECORD_ERR(-MARS_ERR_SCAN_SEQ_FW);
			return -EBADMSG;
		} else if (unlikely(lh->l_seq_nr != *seq_nr + 1 && lh->l_seq_nr && *seq_nr)) {
			MARS_WRN(SCAN_TXT "record sequence number %u mismatch, expected was %u\n",
				 SCAN_PAR,
				 lh->l_seq_nr, *seq_nr + 1);
			/* Theoretically, a backskip of sequence number
			 * can be tolerated, if it is really true.
			 * We may use this in future, e.g. for propagation
			 * of updated records.
			 * It may also happen in some future record patterns.
			 */
			RECORD_ERR(-MARS_ERR_SCAN_SEQ_BW);
		}
		*seq_nr = lh->l_seq_nr;

		/*
		 * We have only 16 flag bits in the traditional
		 * logfile format, which is in production over
		 * years. To remain compatible, we strip off
		 * non-checksum related bits.
		 */
		check_flags =
			(((__u32)lh->l_crc_flags) << _MREF_CHKSUM_MD5_OLD) &
			(available_digest_mask | available_compression_mask);

		/* compatibility with old logfiles during upgrade */
		if (!check_flags)
			check_flags = MREF_CHKSUM_MD5_OLD;

		decompr_len = lh->l_decompress_len;
		crc_len = lh->l_len;
		if (decompr_len > 0 &&
		    unlikely(decompr_len > MARS_MAX_COMPR_SIZE ||
			     decompr_len <= crc_len ||
			     (decompr_len % 512) != 0)) {
			MARS_ERR(SCAN_TXT "implausible decompr_len: %d ~~ %d\n",
				 SCAN_PAR, decompr_len, crc_len);
			RECORD_ERR(-MARS_ERR_DECOMPR_BADLEN);
			return -EBADMSG;
		}
		if (unlikely(crc_len > MARS_MAX_COMPR_SIZE)) {
			MARS_ERR(SCAN_TXT "implausible crc_len: %d > %ld\n",
				 SCAN_PAR, crc_len, MARS_MAX_COMPR_SIZE);
			RECORD_ERR(-MARS_ERR_DECOMPR_TOOBIG);
			return -EBADMSG;
		}
		crc_buf = buf + found_offset;
		if ((check_flags & MREF_COMPRESS_ANY) &&
		    decompr_len > 0) {
			new_buf =
			  mars_decompress(crc_buf, crc_len,
					  NULL, decompr_len,
					  check_flags);
			if (likely(new_buf)) {
				*dealloc = new_buf;
				crc_buf = new_buf;
				crc_len = decompr_len;
			} else {
				MARS_ERR(SCAN_TXT "decompression 0x%x failure len=%d/%d\n",
					 SCAN_PAR,  check_flags,
					 crc_len, decompr_len);
				RECORD_ERR(-MARS_ERR_DECOMPR_FAIL);
				return -EBADMSG;
			}
		}

		crc_status =
			_check_crc(lh,
				   crc,
				   crc_buf,
				   crc_len,
				   check_flags,
				   mars_error_code);
		if (crc_status) {
			MARS_ERR(SCAN_TXT
				 "data checksumming mismatch, flags=0x%x len=%d/%d err=%d\n",
				 SCAN_PAR,
				 check_flags,
				 lh->l_len, crc_len,
				 crc_status);
			return -EBADMSG;
		}

		// last check
		if (unlikely(total_len != offset - i)) {
			MARS_ERR(SCAN_TXT "internal size mismatch: %d != %d\n", SCAN_PAR, total_len, offset - i);
			RECORD_ERR(-MARS_ERR_SCAN_SIZE);
			return -EBADMSG;
		}

		// Success...
		*payload = crc_buf;
		*payload_len = crc_len;

		// don't cry when nullbytes have been skipped
		if (i > 0 && dirty) {
			MARS_WRN(SCAN_TXT "skipped %d dirty bytes to find valid data\n", SCAN_PAR, i);
			if (start_byte_code && !*byte_code) {
				*byte_code = start_byte_code;
				MARS_WRN("found repeated byte pattern 0x%02x",
					 start_byte_code);
			}
		}

		return offset;
	}

	MARS_ERR("could not find any useful data within len=%d bytes\n", len);
	RECORD_ERR(-MARS_ERR_SCAN_GARBAGE);
	return -EAGAIN;
}

////////////////// module init stuff /////////////////////////

int __init init_log_format(void)
{
	MARS_INF("init_log_format()\n");
	return 0;
}

void exit_log_format(void)
{
	MARS_INF("exit_log_format()\n");
}
