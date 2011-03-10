// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>

#include "log_format.h"

void init_logst(struct log_status *logst, struct mars_input *input, struct mars_output *output)
{
	memset(logst, sizeof(*logst), 0);
	logst->input = input;
	logst->output = output;
}
EXPORT_SYMBOL_GPL(init_logst);

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
EXPORT_SYMBOL_GPL(log_skip);

void *log_reserve(struct log_status *logst, struct log_header *lh)
{
	struct mref_object *mref;
	void *data;
	int total_len;
	int status;
	int offset;

	MARS_DBG("reserving %d bytes at %lld\n", lh->l_len, logst->log_pos);

	if (unlikely(logst->log_mref)) {
		MARS_ERR("mref already existing\n");
		goto err;
	}

	mref = mars_alloc_mref(logst->output, &logst->ref_object_layout);
	if (unlikely(!mref))
		goto err;

	mref->ref_pos = logst->log_pos;
	total_len = lh->l_len + OVERHEAD;
	mref->ref_len = total_len;
	mref->ref_may_write = WRITE;
#if 1
	mref->ref_prio = MARS_PRIO_LOW;
#endif

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
	DATA_PUT(data, offset, lh->l_stamp.tv_sec);
	DATA_PUT(data, offset, lh->l_stamp.tv_nsec);
	DATA_PUT(data, offset, lh->l_pos);
	logst->reallen_offset = offset;
	DATA_PUT(data, offset, lh->l_len);
	DATA_PUT(data, offset, lh->l_code);

	logst->payload_offset = offset;
	logst->payload_len = lh->l_len;

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
EXPORT_SYMBOL_GPL(log_finalize);

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
