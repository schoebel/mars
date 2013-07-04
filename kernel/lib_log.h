// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Definitions for logfile format.
 *
 * This is meant for sharing between different transaction logger variants,
 * and/or for sharing with userspace tools (e.g. logfile analyzers).
 * TODO: factor out some remaining kernelspace issues.
 */

#ifndef LIB_LOG_H
#define LIB_LOG_H

#ifdef __KERNEL__
#include "mars.h"

extern atomic_t global_mref_flying;
#endif

/* The following structure is memory-only.
 * Transfers to disk are indirectly via the
 * format conversion functions below.
 * The advantage is that even newer disk formats can be parsed
 * by old code (of course, not all information / features will be
 * available then).
 */
#define log_header log_header_v1

struct log_header_v1 {
	struct timespec l_stamp;
	struct timespec l_written;
	loff_t l_pos;
	short  l_len;
	short  l_code;
	unsigned int l_seq_nr;
	int    l_crc;
};

#define FORMAT_VERSION   1 // version of disk format, currently there is no other one

#define CODE_UNKNOWN     0
#define CODE_WRITE_NEW   1
#define CODE_WRITE_OLD   2

#define START_MAGIC  0xa8f7e908d9177957ll
#define END_MAGIC    0x74941fb74ab5726dll

#define START_OVERHEAD						\
	(							\
		sizeof(START_MAGIC) +				\
		sizeof(char) +					\
		sizeof(char) +					\
		sizeof(short) +					\
		sizeof(struct timespec) +			\
		sizeof(loff_t) +				\
		sizeof(int) +					\
		sizeof(int) +					\
		sizeof(short) +					\
		sizeof(short) +					\
		0						\
	)

#define END_OVERHEAD						\
	(							\
		sizeof(END_MAGIC) +				\
		sizeof(int) +					\
		sizeof(char) +					\
		3 + 4 /*spare*/ +				\
		sizeof(struct timespec) +			\
		0						\
	)

#define OVERHEAD (START_OVERHEAD + END_OVERHEAD)

// TODO: make this bytesex-aware.
#define DATA_PUT(data,offset,val)				\
	do {							\
		*((typeof(val)*)((data)+offset)) = val;		\
		offset += sizeof(val);				\
	} while (0)

#define DATA_GET(data,offset,val)				\
	do {							\
		val = *((typeof(val)*)((data)+offset));		\
		offset += sizeof(val);				\
	} while (0)

#define SCAN_TXT "at file_pos = %lld file_offset = %d scan_offset = %d (%lld) test_offset = %d (%lld) restlen = %d: "
#define SCAN_PAR file_pos, file_offset, offset, file_pos + file_offset + offset, i, file_pos + file_offset + i, restlen

static inline
int log_scan(void *buf, int len, loff_t file_pos, int file_offset, bool sloppy, struct log_header *lh, void **payload, int *payload_len, unsigned int *seq_nr)
{
	bool dirty = false;
	int offset;
	int i;

	*payload = NULL;
	*payload_len = 0;

	for (i = 0; i < len && i <= len - OVERHEAD; i += sizeof(long)) {
		long long start_magic;
		char format_version;
		char valid_flag;
		short total_len;
		long long end_magic;
		char valid_copy;

		int restlen = 0;
		int found_offset;

		offset = i;
		if (unlikely(i > 0 && !sloppy)) {
			MARS_ERR(SCAN_TXT "detected a hole / bad data\n", SCAN_PAR);
			return -EBADMSG;
		}

		DATA_GET(buf, offset, start_magic);
		if (unlikely(start_magic != START_MAGIC)) {
			if (start_magic != 0)
				dirty = true;
			continue;
		}

		restlen = len - i;
		if (unlikely(restlen < START_OVERHEAD)) {
			MARS_WRN(SCAN_TXT "magic found, but restlen is too small\n", SCAN_PAR);
			return -EAGAIN;
		}

		DATA_GET(buf, offset, format_version);
		if (unlikely(format_version != FORMAT_VERSION)) {
			MARS_ERR(SCAN_TXT "found unknown data format %d\n", SCAN_PAR, (int)format_version);
			return -EBADMSG;
		}
		DATA_GET(buf, offset, valid_flag);
		if (unlikely(!valid_flag)) {
			MARS_WRN(SCAN_TXT "data is explicitly marked invalid (was there a short write?)\n", SCAN_PAR);
			continue;
		}
		DATA_GET(buf, offset, total_len);
		if (unlikely(total_len > restlen)) {
			MARS_WRN(SCAN_TXT "total_len = %d but available data restlen = %d. Was the logfile truncated?\n", SCAN_PAR, total_len, restlen);
			return -EAGAIN;
		}

		memset(lh, 0, sizeof(struct log_header));

		DATA_GET(buf, offset, lh->l_stamp.tv_sec);
		DATA_GET(buf, offset, lh->l_stamp.tv_nsec);
		DATA_GET(buf, offset, lh->l_pos);
		DATA_GET(buf, offset, lh->l_len);
		offset += 2; // skip spare
		offset += 4; // skip spare
		DATA_GET(buf, offset, lh->l_code);
		offset += 2; // skip spare

		found_offset = offset;
		offset += lh->l_len;

		restlen = len - offset;
		if (unlikely(restlen < END_OVERHEAD)) {
			MARS_WRN(SCAN_TXT "restlen %d is too small\n", SCAN_PAR, restlen);
			return -EAGAIN;
		}

		DATA_GET(buf, offset, end_magic);
		if (unlikely(end_magic != END_MAGIC)) {
			MARS_WRN(SCAN_TXT "bad end_magic 0x%llx, is the logfile truncated?\n", SCAN_PAR, end_magic);
			return -EBADMSG;
		}
		DATA_GET(buf, offset, lh->l_crc);
		DATA_GET(buf, offset, valid_copy);

		if (unlikely(valid_copy != 1)) {
			MARS_WRN(SCAN_TXT "found data marked as uncompleted / invalid, len = %d, valid_flag = %d\n", SCAN_PAR, lh->l_len, (int)valid_copy);
			return -EBADMSG;
		}

		// skip spares
		offset += 3;

		DATA_GET(buf, offset, lh->l_seq_nr);
		DATA_GET(buf, offset, lh->l_written.tv_sec);
		DATA_GET(buf, offset, lh->l_written.tv_nsec);

		if (unlikely(lh->l_seq_nr != *seq_nr + 1 && lh->l_seq_nr && *seq_nr)) {
			MARS_ERR(SCAN_TXT "record sequence number %u mismatch, expected was %u\n", SCAN_PAR, lh->l_seq_nr, *seq_nr + 1);
			return -EBADMSG;
		}
		*seq_nr = lh->l_seq_nr;

		if (lh->l_crc) {
			unsigned char checksum[mars_digest_size];
			mars_digest(checksum, buf + found_offset, lh->l_len);
			if (unlikely(*(int*)checksum != lh->l_crc)) {
				MARS_ERR(SCAN_TXT "data checksumming mismatch, length = %d\n", SCAN_PAR, lh->l_len);
				return -EBADMSG;
			}
		}

		// last check
		if (unlikely(total_len != offset - i)) {
			MARS_ERR(SCAN_TXT "internal size mismatch: %d != %d\n", SCAN_PAR, total_len, offset - i);
			return -EBADMSG;
		}

		// Success...
		*payload = buf + found_offset;
		*payload_len = lh->l_len;

		// don't cry when nullbytes have been skipped
		if (i > 0 && dirty) {
			MARS_WRN(SCAN_TXT "skipped %d dirty bytes to find valid data\n", SCAN_PAR, i);
		}

		return offset;
	}

	MARS_ERR("could not find any useful data within len=%d bytes\n", len);
	return -EAGAIN;
}

////////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__

/* Bookkeeping status between calls
 */
struct log_status {
	// interfacing
	wait_queue_head_t *signal_event;
	// tunables
	int align_size;   // alignment between requests
	int chunk_size;   // must be at least 8K (better 64k)
	int max_size;     // max payload length
	int io_prio;
	bool do_crc;
	// informational
	atomic_t mref_flying;
	int count;
	loff_t log_pos;
	struct timespec log_pos_stamp;
	// internal
	struct timespec tmp_pos_stamp;
	struct mars_input *input;
	struct mars_brick *brick;
	struct mars_info info;
	int offset;
	int validflag_offset;
	int reallen_offset;
	int payload_offset;
	int payload_len;
	unsigned int seq_nr;
	struct mref_object *log_mref;
	struct mref_object *read_mref;
	wait_queue_head_t event;
	int error_code;
	bool got;
	bool do_free;
	void *private;
};

void init_logst(struct log_status *logst, struct mars_input *input, loff_t start_pos);
void exit_logst(struct log_status *logst);

void log_flush(struct log_status *logst);

void *log_reserve(struct log_status *logst, struct log_header *lh);

bool log_finalize(struct log_status *logst, int len, void (*endio)(void *private, int error), void *private);

int log_read(struct log_status *logst, bool sloppy, struct log_header *lh, void **payload, int *payload_len);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_log_format(void);
extern void exit_log_format(void);

#endif
#endif
