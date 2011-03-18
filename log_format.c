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

void log_flush(struct log_status *logst, int min_rest)
{
	struct mref_object *mref = logst->log_mref;
	struct generic_callback *cb;
	int gap;

	if (!mref)
		return;

	if (logst->restlen > 0) { // don't leak information from kernelspace
		memset(mref->ref_data + logst->offset, 0, logst->restlen);
	}
	
	gap = 0;
	if (logst->align_size > 0) {
		int align_offset = logst->offset & (logst->align_size-1);
		if (align_offset > 0) {
			gap = logst->align_size - align_offset;
		}
	}
	if (logst->restlen < min_rest + gap + OVERHEAD) {
		// finish this chunk completely
		logst->offset += logst->restlen;
	} else {
		// round up to next alignment border
		logst->offset += gap;
	}
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
		log_flush(logst, lh->l_len);
	}

	mref = logst->log_mref;
	if (!mref) {
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
		mref->ref_len = logst->chunk_size - (logst->log_pos & (loff_t)(logst->chunk_size - 1));
		if (mref->ref_len < total_len) {
			MARS_INF("not good: ref_len = %d total_len = %d\n", mref->ref_len, total_len);
			mref->ref_len = total_len;
		}
		mref->ref_may_write = WRITE;
#if 1
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

#if 1
	if (logst->restlen < PAGE_SIZE + OVERHEAD) {
		log_flush(logst, PAGE_SIZE);
	}
#endif

err:
	return ok;
}
EXPORT_SYMBOL_GPL(log_finalize);


int log_read_prepare(struct log_status *logst, struct log_header *lh)
{
	return 0;
}
EXPORT_SYMBOL_GPL(log_read_prepare);

void log_read(struct log_status *logst, void *buffer)
{
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
