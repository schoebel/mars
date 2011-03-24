// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>

#include "log_format.h"

void init_logst(struct log_status *logst, struct mars_input *input, struct mars_output *output, loff_t start_pos)
{
	memset(logst, sizeof(*logst), 0);
	logst->input = input;
	logst->output = output;
	logst->log_pos = start_pos;
	init_waitqueue_head(&logst->event);
}
EXPORT_SYMBOL_GPL(init_logst);

#define MARS_LOG_CB_MAX 16

struct log_cb_info {
	int nr_endio;
	void (*endios[MARS_LOG_CB_MAX])(void *private, int error);
	void *privates[MARS_LOG_CB_MAX];
};

static
void log_endio(struct generic_callback *cb)
{
	struct log_cb_info *cb_info = cb->cb_private;
	int i;

	CHECK_PTR(cb_info, err);

	for (i = 0; i < cb_info->nr_endio; i++) {
		cb_info->endios[i](cb_info->privates[i], cb->cb_error);
	}
	kfree(cb_info);
	return;

err:
	MARS_FAT("internal pointer corruption\n");
}

void log_flush(struct log_status *logst)
{
	struct mref_object *mref = logst->log_mref;
	struct generic_callback *cb;
	int gap;

	if (!mref)
		return;

	gap = 0;
	if (logst->align_size > 0) {
		// round up to next alignment border
		int align_offset = logst->offset & (logst->align_size-1);
		if (align_offset > 0) {
			gap = logst->align_size - align_offset;
			if (gap > logst->restlen) {
				gap = logst->restlen;
			}
		}
	}
	if (gap > 0) {
		// don't leak information from kernelspace
		memset(mref->ref_data + logst->offset, 0, gap);
		logst->offset += gap;
	}
	mref->ref_len = logst->offset;
	logst->log_pos += logst->offset;

	cb = &mref->_ref_cb;
	cb->cb_fn = log_endio;
	cb->cb_private = logst->private;
	logst->private = NULL;
	cb->cb_error = 0;
	cb->cb_prev = NULL;
	mref->ref_cb = cb;
	mref->ref_rw = 1;

	GENERIC_INPUT_CALL(logst->input, mref_io, mref);
	GENERIC_INPUT_CALL(logst->input, mref_put, mref);

	logst->offset = 0;
	logst->log_mref = NULL;
}
EXPORT_SYMBOL_GPL(log_flush);

void *log_reserve(struct log_status *logst, struct log_header *lh)
{
	struct log_cb_info *cb_info = logst->private;
	struct mref_object *mref;
	void *data;
	int total_len = lh->l_len + OVERHEAD;
	int offset;
	int status;

	MARS_DBG("reserving %d bytes at %lld\n", lh->l_len, logst->log_pos);

	if (total_len > logst->restlen || !cb_info || cb_info->nr_endio >= MARS_LOG_CB_MAX) {
		log_flush(logst);
	}

	mref = logst->log_mref;
	if (!mref) {
		int chunk_offset;
		int chunk_rest;
		if (unlikely(logst->private)) {
			MARS_ERR("oops\n");
			kfree(logst->private);
		}
		logst->private = kzalloc(sizeof(struct log_cb_info), GFP_MARS);
		if (unlikely(!logst->private)) {
			MARS_ERR("no memory\n");
			goto err;
		}

		mref = mars_alloc_mref(logst->output, &logst->ref_object_layout);
		if (unlikely(!mref)) {
			MARS_ERR("no mref\n");
			goto err;
		}
		
		mref->ref_pos = logst->log_pos;
		chunk_offset = logst->log_pos & (loff_t)(logst->chunk_size - 1);
		chunk_rest = logst->chunk_size - chunk_offset;
		if (chunk_rest < total_len) {
			mref->ref_pos += chunk_rest;
			chunk_rest = logst->chunk_size;
		}
		mref->ref_len = chunk_rest;
		if (mref->ref_len < total_len) {
			MARS_INF("not good: ref_len = %d total_len = %d\n", mref->ref_len, total_len);
			mref->ref_len = total_len;
		}
		mref->ref_may_write = WRITE;
#if 0
		mref->ref_prio = MARS_PRIO_LOW;
#endif

		status = GENERIC_INPUT_CALL(logst->input, mref_get, mref);
		if (unlikely(status < 0)) {
			MARS_ERR("mref_get() failed, status = %d\n", status);
			goto err_free;
		}
		if (unlikely(mref->ref_len < total_len)) {
			MARS_ERR("ref_len = %d total_len = %d\n", mref->ref_len, total_len);
			goto put;
		}

		logst->restlen = mref->ref_len;
		logst->offset = 0;
		logst->log_mref = mref;
	}

	offset = logst->offset;
	data = mref->ref_data;
	DATA_PUT(data, offset, START_MAGIC);
	DATA_PUT(data, offset, (char)FORMAT_VERSION);
	logst->validflag_offset = offset;
	DATA_PUT(data, offset, (char)0); // valid_flag
	DATA_PUT(data, offset, (short)0); // spare
	DATA_PUT(data, offset, total_len); // start of next header
	DATA_PUT(data, offset, lh->l_stamp.tv_sec);
	DATA_PUT(data, offset, lh->l_stamp.tv_nsec);
	DATA_PUT(data, offset, lh->l_pos);
	logst->reallen_offset = offset;
	DATA_PUT(data, offset, lh->l_len);
	DATA_PUT(data, offset, lh->l_code);

	logst->payload_offset = offset;
	logst->payload_len = lh->l_len;
	logst->offset = offset;

	return data + offset;

put:
	GENERIC_INPUT_CALL(logst->input, mref_put, mref);
	return NULL;

err_free:
	mars_free_mref(mref);
	if (logst->private) {
		kfree(logst->private);
		logst->private = NULL;
	}
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(log_reserve);

bool log_finalize(struct log_status *logst, int len, void (*endio)(void *private, int error), void *private)
{
	struct mref_object *mref = logst->log_mref;
	struct log_cb_info *cb_info = logst->private;
	struct timespec now;
	void *data;
	int offset;
	int nr_endio;
	bool ok = false;

	CHECK_PTR(mref, err);

	if (unlikely(len > logst->restlen)) {
		MARS_ERR("trying to write more than reserved (%d > %d)\n", len, logst->restlen);
		goto err;
	}
	if (unlikely(!cb_info || cb_info->nr_endio >= MARS_LOG_CB_MAX)) {
		MARS_ERR("too many endio() calls\n");
		goto err;
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

	logst->offset = offset;
	logst->restlen = mref->ref_len - offset;

	/* This must come last. In case of incomplete
	 * or even operlapping disk transfers, this indicates
	 * the completeness / integrity of the payload at
	 * the time of starting the transfer.
	 */
	offset = logst->validflag_offset;
	DATA_PUT(data, offset, (char)1);

	nr_endio = cb_info->nr_endio++;
	cb_info->endios[nr_endio] = endio;
	cb_info->privates[nr_endio] = private;

	ok = true;

err:
	return ok;
}
EXPORT_SYMBOL_GPL(log_finalize);


static
void read_endio(struct generic_callback *cb)
{
	struct log_status *logst = cb->cb_private;

	CHECK_PTR(logst, err);
	logst->error_code = cb->cb_error;
	logst->got = true;
	wake_up_interruptible(&logst->event);
	return;

err:
	MARS_FAT("internal pointer corruption\n");
}


int log_read(struct log_status *logst, struct log_header *lh, void **payload)
{
	struct mref_object *mref = logst->read_mref;
	int i;
	int status = 0;
	if (!mref) {
		struct generic_callback *cb;
		int chunk_offset;
		int chunk_rest;
		mref = mars_alloc_mref(logst->output, &logst->ref_object_layout);
		if (unlikely(!mref)) {
			MARS_ERR("no mref\n");
			goto err;
		}
		mref->ref_pos = logst->log_pos;
		chunk_offset = logst->log_pos & (loff_t)(logst->chunk_size - 1);
		chunk_rest = logst->chunk_size - chunk_offset;
		mref->ref_len = chunk_rest;
#if 0
		mref->ref_prio = MARS_PRIO_LOW;
#endif
		status = GENERIC_INPUT_CALL(logst->input, mref_get, mref);
		if (unlikely(status < 0)) {
			MARS_ERR("mref_get() failed, status = %d\n", status);
			goto err_free;
		}


		cb = &mref->_ref_cb;
		cb->cb_fn = read_endio;
		cb->cb_private = logst;
		cb->cb_error = 0;
		cb->cb_prev = NULL;
		mref->ref_cb = cb;
		mref->ref_rw = 0;
		logst->offset = 0;
		logst->got = false;

		GENERIC_INPUT_CALL(logst->input, mref_io, mref);

		wait_event_interruptible_timeout(logst->event, logst->got, 60 * HZ);
		status = -EIO;
		if (!logst->got)
			goto err_free;
		status = logst->error_code;
		if (status < 0)
			goto err_free;
		logst->read_mref = mref;
	}

	for (i = logst->offset; i < mref->ref_len; ) {
		long long magic = 0;
		int startpos = i;
		DATA_GET(mref->ref_data, i, magic);
		if (magic == START_MAGIC) {
			int restlen = mref->ref_len - startpos;
			if (restlen < sizeof(struct log_header)) {
				MARS_ERR("magic found at pos %d, restlen = %d\n", startpos, restlen);
			}
			memcpy(lh, mref->ref_data + startpos, sizeof(struct log_header));
			//...
			break;
		}
	}

	return status;

err_free:
	if (mref) {
		GENERIC_INPUT_CALL(logst->input, mref_put, mref);
	}
err:
	return status;
}
EXPORT_SYMBOL_GPL(log_read);


////////////////// module init stuff /////////////////////////

static int __init init_log_format(void)
{
	MARS_INF("init_log_format()\n");
	return 0;
}

static void __exit exit_log_format(void)
{
	MARS_INF("exit_log_format()\n");
}

MODULE_DESCRIPTION("MARS log_format infrastucture");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_log_format);
module_exit(exit_log_format);
