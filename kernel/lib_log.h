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


/* Definitions for logfile format.
 *
 * This is meant for sharing between different transaction logger variants,
 * and/or for sharing with userspace tools (e.g. logfile analyzers).
 * TODO: factor out some remaining kernelspace issues.
 */

#ifndef LIB_LOG_H
#define LIB_LOG_H

#include "mars_errno.h"

#ifdef __KERNEL__
#include "mars.h"

extern __u32 enabled_log_compressions;

extern __u32 used_log_compression;

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
	struct lamport_time l_stamp;
	loff_t l_pos;
	short  l_len;
	short  l_decompress_len;
	short  l_code;
	unsigned int l_seq_nr;
	__u32  l_crc_old;
	__u16  l_crc_flags;
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
		sizeof(struct lamport_time) +			\
		sizeof(loff_t) +				\
		sizeof(int) +					\
		sizeof(int) +					\
		sizeof(short) +					\
		sizeof(short) +					\
		0						\
	)

#define LOG_CHKSUM_SIZE (sizeof(__u64) * 2)

#define END_OVERHEAD						\
	(							\
		sizeof(END_MAGIC) +				\
		sizeof(int) +					\
		sizeof(char) +					\
		3 + 4 /*spare*/ +				\
		LOG_CHKSUM_SIZE +				\
		0						\
	)

#define OVERHEAD (START_OVERHEAD + END_OVERHEAD)

/* alignment of log positions to 64bit */
#define _LOG_PAD_BITS 3
#define _LOG_PAD (1 << _LOG_PAD_BITS)

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

extern int log_scan(void *buf,
		    int len,
		    loff_t file_pos,
		    int file_offset,
		    bool sloppy,
		    struct log_header *lh,
		    void **payload, int *payload_len,
		    void **dealloc,
		    unsigned int *seq_nr,
		    int *mars_error_code,
		    int *byte_code);

////////////////////////////////////////////////////////////////////////////

#ifdef __KERNEL__

/* Bookkeeping status between calls
 */
struct log_status {
	// interfacing
	wait_queue_head_t *signal_event;
	int               *signal_flag;
	// tunables
	loff_t start_pos;
	loff_t end_pos;
	int align_size;   // alignment between requests
	int chunk_size;   // must be at least 8K (better 64k)
	int max_size;     // max payload length
	int io_prio;
	bool do_compress;
	// informational
	atomic_t mref_flying;
	int count;
	loff_t log_pos;
	struct lamport_time log_pos_stamp;
	// internal
	struct lamport_time tmp_pos_stamp;
	struct mars_input *input;
	struct mars_brick *brick;
	struct mars_info info;
	int offset;
	int validflag_offset;
	int totallen_offset;
	int reallen_offset;
	int decompresslen_offset;
	int payload_offset;
	int payload_len;
	unsigned int seq_nr;
	struct mref_object *log_mref;
	struct mref_object *read_mref;
	wait_queue_head_t event;
	int posix_error_code;
	int mars_error_code;
	int byte_code;
	bool got;
	bool do_free;
	void *private;
};

void init_logst(struct log_status *logst, struct mars_input *input, loff_t start_pos, loff_t end_pos);
void exit_logst(struct log_status *logst);

void log_flush(struct log_status *logst);

void *log_reserve(struct log_status *logst, struct log_header *lh);

bool log_finalize(struct log_status *logst, int len, void (*endio)(void *private, int error), void *private);

int log_read(struct log_status *logst,
	     bool sloppy,
	     struct log_header *lh,
	     void **payload, int *payload_len,
	     void **dealloc);

/////////////////////////////////////////////////////////////////////////

// init

extern int init_log_format(void);
extern void exit_log_format(void);

#endif
#endif
