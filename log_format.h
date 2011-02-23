// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Definitions for logfile format.
 *
 * This is meant for sharing between different transaction logger variants,
 * and/or for sharing with userspace tools (e.g. logfile analyzers).
 * TODO: factor out kernelspace issues.
 */

#ifndef LOG_FORMAT_H
#define LOG_FORMAT_H

#include "mars.h"

/* The following structure is memory-only.
 * Transfers to disk are indirectly via the
 * format conversion functions below.
 * The advantage is that even newer disk formats can be parsed
 * by old code (of course, not all information / features will be
 * available then).
 */
struct log_header {
	struct timespec l_stamp;
	loff_t l_pos;
	int    l_len;
	int    l_code;
};

/* Bookkeeping status between calls
 */
struct log_status {
	struct mars_input *input;
	struct mars_output hidden_output;
	struct generic_object_layout ref_object_layout;

	struct mars_info info;
	loff_t log_pos;
	int validflag_offset;
	int reallen_offset;
	int payload_offset;
	int payload_len;
	struct mref_object *log_mref;
};

#define FORMAT_VERSION   1 // version of disk format, currently there is no other one

#define CODE_UNKNOWN     0
#define CODE_WRITE_NEW   1
#define CODE_WRITE_OLD   2

#define START_MAGIC  0xa8f7e908d9177957ll
#define END_MAGIC    0x74941fb74ab5726dll

#define OVERHEAD						\
	(							\
		sizeof(START_MAGIC) +				\
		sizeof(char) * 2 +				\
		sizeof(short) +					\
		sizeof(int) +					\
		sizeof(struct log_header) +                     \
		sizeof(END_MAGIC) +				\
		sizeof(char) * 2 +				\
		sizeof(short) +					\
		sizeof(int) +					\
		sizeof(struct timespec) +			\
		0						\
	)

// TODO: make this bytesex-aware.
#define DATA_PUT(data,offset,val)				\
	do {							\
		*((typeof(val)*)(data+offset)) = val;		\
		offset += sizeof(val);				\
	} while (0)

#define DATA_GET(data,offset,val)				\
	do {							\
		val = *((typeof(val)*)(data+offset));		\
		offset += sizeof(val);				\
	} while (0)

static inline
void log_skip(struct log_status *logst)
{
	int bits;
	if (!logst->info.transfer_size) {
		int status = GENERIC_INPUT_CALL(logst->input, mars_get_info, &logst->info);
		if (status < 0) {
			MARS_FAT("cannot get transfer log info (code=%d)\n", status);
		}
	}
	bits = logst->info.transfer_order + PAGE_SHIFT;
	logst->log_pos = ((logst->log_pos >> bits) + 1) << bits;
}

static inline
void *log_reserve(struct log_status *logst, struct log_header *l)
{
	struct mref_object *mref;
	void *data;
	int total_len;
	int status;
	int offset;

	MARS_DBG("reserving %d bytes at %lld\n", l->l_len, logst->log_pos);

	if (unlikely(logst->log_mref)) {
		MARS_ERR("mref already existing\n");
		goto err;
	}

	mref = mars_alloc_mref(&logst->hidden_output, &logst->ref_object_layout);
	if (unlikely(!mref))
		goto err;

	mref->ref_pos = logst->log_pos;
	total_len = l->l_len + OVERHEAD;
	mref->ref_len = total_len;
	mref->ref_may_write = WRITE;

	status = GENERIC_INPUT_CALL(logst->input, mref_get, mref);
	if (unlikely(status < 0)) {
		goto err_free;
	}
	if (unlikely(mref->ref_len < total_len)) {
		goto put;
	}

	logst->log_mref = mref;
	data = mref->ref_data;
	offset = 0;
	DATA_PUT(data, offset, START_MAGIC);
	DATA_PUT(data, offset, (char)FORMAT_VERSION);
	logst->validflag_offset = offset;
	DATA_PUT(data, offset, (char)0); // valid_flag
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, total_len); // start of next header
	DATA_PUT(data, offset, l->l_stamp.tv_sec);
	DATA_PUT(data, offset, l->l_stamp.tv_nsec);
	DATA_PUT(data, offset, l->l_pos);
	logst->reallen_offset = offset;
	DATA_PUT(data, offset, l->l_len);
	DATA_PUT(data, offset, l->l_code);

	logst->payload_offset = offset;
	logst->payload_len = l->l_len;

	return data + offset;

put:
	GENERIC_INPUT_CALL(logst->input, mref_put, mref);
	return NULL;

err_free:
	mars_free_mref(mref);
err:
	return NULL;
}

static inline
bool log_finalize(struct log_status *logst, int len, void (*endio)(struct generic_callback *cb), void *private)
{
	struct mref_object *mref = logst->log_mref;
	struct generic_callback *cb;
	struct timespec now;
	void *data;
	int offset;
	bool ok = false;

	CHECK_PTR(mref, err);

	logst->log_mref = NULL;
	if (unlikely(len > logst->payload_len)) {
		MARS_ERR("trying to write more than reserved (%d > %d)\n", len, logst->payload_len);
		goto put;
	}

	data = mref->ref_data;

	/* Correct the length in the header.
	 */
	offset = logst->reallen_offset;
	DATA_PUT(data, offset, len);

	/* Write the trailer.
	 */
	offset = logst->payload_offset + len;
	DATA_PUT(data, offset, END_MAGIC);
	DATA_PUT(data, offset, (char)1);  // valid_flag copy
	DATA_PUT(data, offset, (char)0);  // spare
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, (int)0);   // spare
	get_lamport(&now);    // when the log entry was ready.
	DATA_PUT(data, offset, now.tv_sec);  
	DATA_PUT(data, offset, now.tv_nsec);

	logst->log_pos += offset;

	/* This must come last. In case of incomplete
	 * or even operlapping disk transfers, this indicates
	 * the completeness / integrity of the payload at
	 * the time of starting the transfer.
	 */
	offset = logst->validflag_offset;
	DATA_PUT(data, offset, (char)1);

	cb = &mref->_ref_cb;
	cb->cb_fn = endio;
	cb->cb_error = 0;
	cb->cb_prev = NULL;
	cb->cb_private = private;
	mref->ref_cb = cb;
	mref->ref_rw = 1;

	GENERIC_INPUT_CALL(logst->input, mref_io, mref);

	ok = true;
put:
	GENERIC_INPUT_CALL(logst->input, mref_put, mref);

err:
	return ok;
}


#endif
