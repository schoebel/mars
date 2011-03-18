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
#define log_header log_header_v1

struct log_header_v1 {
	struct timespec l_stamp;
	loff_t l_pos;
	int    l_len;
	int    l_code;
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

////////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__

/* Bookkeeping status between calls
 */
struct log_status {
	// tunables
	int align_size;   // alignment between requests
	int chunk_size;   // must be at least 8K (better 64k)
	// informational
	loff_t log_pos;
	// internal
	struct mars_input *input;
	struct mars_output *output;
	struct generic_object_layout ref_object_layout;
	struct mars_info info;
	int restlen;
	int offset;
	int validflag_offset;
	int reallen_offset;
	int payload_offset;
	int payload_len;
	struct mref_object *log_mref;
	void *private;
};

void init_logst(struct log_status *logst, struct mars_input *input, struct mars_output *output, loff_t start_pos);

void log_flush(struct log_status *logst, int min_rest);

void *log_reserve(struct log_status *logst, struct log_header *lh);

bool log_finalize(struct log_status *logst, int len, void (*endio)(void *private, int error), void *private);

int log_read_prepare(struct log_status *logst, struct log_header *lh);
void log_read(struct log_status *logst, void *buffer);

#endif
#endif
