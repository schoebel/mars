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
	struct mref_object *mref;
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

	if (cb_info->mref) {
		mars_trace(cb_info->mref, "log_endio");
		mars_log_trace(cb_info->mref);
	}

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

	mars_trace(mref, "log_flush");

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
	short total_len = lh->l_len + OVERHEAD;
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
		cb_info = logst->private;

		mref = mars_alloc_mref(logst->output, &logst->ref_object_layout);
		if (unlikely(!mref)) {
			MARS_ERR("no mref\n");
			goto err;
		}
		cb_info->mref = mref;

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

		mars_trace(mref, "log_start");

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
	DATA_PUT(data, offset, total_len); // start of next header
	DATA_PUT(data, offset, lh->l_stamp.tv_sec);
	DATA_PUT(data, offset, lh->l_stamp.tv_nsec);
	DATA_PUT(data, offset, lh->l_pos);
	logst->reallen_offset = offset;
	DATA_PUT(data, offset, lh->l_len);
	DATA_PUT(data, offset, lh->l_extra_len);
	DATA_PUT(data, offset, lh->l_code);
	DATA_PUT(data, offset, lh->l_extra);

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
	DATA_PUT(data, offset, (int)0);   // crc
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
	 * or even overlapping disk transfers, this indicates
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
int log_scan(void *buf, int len, struct log_header *lh, void **payload, int *payload_len)
{
	int i;

	*payload_len = 0;

	for (i = 0; i < len; i += sizeof(long)) {
		long long start_magic;
		char format_version;
		char valid_flag;
		short total_len;
		long long end_magic;
		char valid_copy;

		int restlen;
		int offset = i;

		DATA_GET(buf, offset, start_magic);
		if (start_magic != START_MAGIC) {
			continue;
		}

		restlen = len - i;
		if (restlen < START_OVERHEAD) {
			MARS_WRN("magic found at offset %d, but restlen %d is too small\n", i, restlen);
			return -EBADMSG;
		}

		DATA_GET(buf, offset, format_version);
		if (format_version != FORMAT_VERSION) {
			MARS_WRN("found unknown data format %d at offset %d\n", (int)format_version, i);
			continue;
		}
		DATA_GET(buf, offset, valid_flag);
		if (!valid_flag) {
			MARS_WRN("data at offset %d is marked invalid (was there a short write?)\n", i);
			continue;
		}
		DATA_GET(buf, offset, total_len);
		if (total_len > restlen) {
			MARS_WRN("data at offset %d is too long (len = %d larger than boundary %d)\n", i, total_len, restlen);
			continue;
		}

		memset(lh, 0, sizeof(struct log_header));

		DATA_GET(buf, offset, lh->l_stamp.tv_sec);
		DATA_GET(buf, offset, lh->l_stamp.tv_nsec);
		DATA_GET(buf, offset, lh->l_pos);
		DATA_GET(buf, offset, lh->l_len);
		DATA_GET(buf, offset, lh->l_extra_len);
		DATA_GET(buf, offset, lh->l_code);
		DATA_GET(buf, offset, lh->l_extra);

		*payload = buf + offset;
		*payload_len = lh->l_len;
		offset += lh->l_len;

		restlen = len - offset;
		if (restlen < END_OVERHEAD) {
			MARS_WRN("magic found at offset %d, but restlen %d is too small\n", i, restlen);
			continue;
		}

		DATA_GET(buf, offset, end_magic);
		if (end_magic != END_MAGIC) {
			MARS_WRN("bad end_magic 0x%llx\n", end_magic);
			continue;
		}
		DATA_GET(buf, offset, valid_copy);
		if (valid_copy != 1) {
			MARS_WRN("found uncompleted / invalid data at %d len = %d (valid_flag = %d)\n", i, lh->l_len, (int)valid_copy);
			continue;
		}
		DATA_GET(buf, offset, lh->l_crc);
		// skip spares
		offset += 3 + 4;
		DATA_GET(buf, offset, lh->l_written.tv_sec);
		DATA_GET(buf, offset, lh->l_written.tv_nsec);

		// last check
		if (total_len != offset - i) {
			MARS_WRN("size mismatch at offset %d: %d != %d\n", i, total_len, offset - i);
			// just warn, but no consequences: better use the data, it has been checked by lots of magics
		}

		if (i > 0) {
			MARS_WRN("skipped %d bytes to find valid data\n", i);
		}
		return offset - i;
	}
	return -EAGAIN;
}

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


int log_read(struct log_status *logst, struct log_header *lh, void **payload, int *payload_len)
{
	struct mref_object *mref = logst->read_mref;
	int status = 0;
	if (!mref) {
		struct generic_callback *cb;
		int chunk_offset;
		int chunk_rest;
		mref = mars_alloc_mref(logst->output, &logst->ref_object_layout);
		if (unlikely(!mref)) {
			MARS_ERR("no mref\n");
			goto done;
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
			goto done_free;
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
			goto done_free;
		status = logst->error_code;
		if (status < 0)
			goto done_free;
		logst->read_mref = mref;
	}

	status = log_scan(mref->ref_data + logst->offset, mref->ref_len - logst->offset, lh, payload, payload_len);
	if (status < 0) {
		goto done_free;
	}

	logst->offset += status;
	if (logst->offset < mref->ref_len) {
		goto done;
	}

done_free:
	if (mref) {
		if (status >= 0) {
			logst->log_pos += logst->offset;
		}
		GENERIC_INPUT_CALL(logst->input, mref_put, mref);
		logst->read_mref = NULL;
	}
done:
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
