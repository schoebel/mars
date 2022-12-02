/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2010-2022 Thomas Schoebel-Theuer
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

#ifndef MARS_LIB_QIO_RW_H
#define MARS_LIB_QIO_RW_H

#include "brick.h"
#include "lamport.h"

#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/pagemap.h>

/* Minor abstraction to/from the kernel IO interface.
 * (a) hopefully this interface will remain stable until MARS
 *     can go upstream. Only the implementation in lib_qio_rw.c
 *     should need to cope with kernel versions.
 * (b) keep the door open for alternative kernel adaptors, maybe even
 *     more direct access to the page cache, or some future developments.
 *
 * Architectural differences to kernel_{read,write}():
 * (1) The interface is as similar as possible, for long-term
 *     code maintenance.
 * (2) Submission should work as non-blocking as possible ;)
 * (3) *_wait() operations are supposed to block any (separate)
 *     kernel threads.
 * Any information transfer between submission and (internal)
 * completion path(s) goes via *private, which should always
 * start with prefix "struct qio_rw_...", but may append further
 * external items.
 */

enum qio_rw_phase {
	QIO_RW_NOTSTARTED,
	QIO_RW_RD_STARTED,
	QIO_RW_WR_STARTED,
	QIO_RW_WAITING,
	QIO_RW_COMPLETED,
};

struct qio_rw {
	union {
		struct {
			/* from general kernel infrastructure */
			struct kiocb kiocb;
			struct iov_iter from_to;
			/* from io_uring */
			/* currently unused: struct io_async_rw rw; */
			/* private */
			ssize_t submission_ret;
			ssize_t completion_ret;
			enum qio_rw_phase qio_phase;
		};
	};
};

struct qio_rw_operations {
	ssize_t (*qio_read_start)(struct file *file,
				  void *buf, size_t count,
				  loff_t *pos,
				  void *private,
				  bool nowait);
	ssize_t (*qio_write_start)(struct file *file,
				   void *buf, size_t count,
				   loff_t *pos,
				   void *private,
				   bool wait_for_sync);
	ssize_t (*qio_rw_wait)(struct file *file,
			       bool is_write,
			       bool needs_write_sync,
			       void *private);
};

extern const struct qio_rw_operations qio_rw_operations;

extern void init_qio_rw(struct qio_rw *qio_rw);
extern void exit_qio_rw(struct qio_rw *qio_rw);

#endif
