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

#ifndef MARS_CKSUM_H
#define MARS_CKSUM_H

#define CKSUM_PAGE_SIZE PAGE_SIZE

struct cksum_record_v1 {
	struct timespec cs_stamp;
	unsigned char cs_cksum[16];
};

struct cksum_mref_aspect {
	GENERIC_ASPECT(mref);
	struct cksum_brick *brick;
	struct generic_callback *master_cb;
	struct generic_callback inter_cb;
	struct cksum_record_v1 cs;
	atomic_t cb_count;
	int cb_error;
	int orig_rw;
	int delayed_dec;
	bool is_right_sized;
};

struct cksum_brick {
	MARS_BRICK(cksum);
	/* parameters */
	bool report_errors;
	bool block_on_errors;
	/* statistics */
	atomic_t total_reads;
	atomic_t total_writes;
	atomic_t total_small_reads;
	atomic_t total_small_writes;
	atomic_t total_success;
	atomic_t total_errors;
};

/* common part of 2 input types */
struct _cksum_input {
	MARS_INPUT(cksum);
};

/* 1st input type, referencing the original data */
struct cksum_input_orig {
	struct _cksum_input inp;
};

/* 2nd input type, referencing the corresponding checksum data */
struct cksum_input_cksum {
	struct _cksum_input inp;
};

struct cksum_output {
	MARS_OUTPUT(cksum);
};

MARS_TYPES(cksum);

#endif
