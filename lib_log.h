// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

/* Definitions for logfile format.
 *
 * This is meant for sharing between different transaction logger variants,
 * and/or for sharing with userspace tools (e.g. logfile analyzers).
 * TODO: factor out some remaining kernelspace issues.
 */

#ifndef LIB_LOG_H
#define LIB_LOG_H

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
	struct timespec l_written;
	loff_t l_pos;
	int    l_len;
	int    l_extra_len;
	short  l_code;
	short  l_extra;
	int    l_crc; // NYI
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

////////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__

/* Bookkeeping status between calls
 */
struct log_status {
	// tunables
	int align_size;   // alignment between requests
	int chunk_size;   // must be at least 8K (better 64k)
	int io_prio;
	// informational
	atomic_t mref_flying;
	int count;
	loff_t log_pos;
	// internal
	struct mars_input *input;
	struct mars_brick *brick;
	struct mars_info info;
	int offset;
	int validflag_offset;
	int reallen_offset;
	int payload_offset;
	int payload_len;
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

bool log_finalize(struct log_status *logst, int len, void (*preio)(void *private), void (*endio)(void *private, int error), void *private);

int log_read(struct log_status *logst, struct log_header *lh, void **payload, int *payload_len);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_log_format(void);
extern void exit_log_format(void);

#endif
#endif
