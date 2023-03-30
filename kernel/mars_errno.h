/*
 * MARS Long Distance Replication Software
 *
 * This file is part of MARS project: http://schoebel.github.io/mars/
 *
 * Copyright (C) 2022 Thomas Schoebel-Theuer
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
#ifndef MARS_ERRNO_H
#define MARS_ERRNO_H


/* MARS needs to report many issues to scripts and to humans.
 * Many problems are not covered by POSIX and other errno definitions.
 *
 * IMPORTANT: keep the following namespaces unique within itself.
 * Keep MARS-specific namespace parts distinct from POSIX and others:
 *   (a) Integer (primary key)
 *   (b) C preprocessor macro names
 *   (c) Cleartext intended for humans.
 * Also, make any entry a 1:1:1 correspondence.
 *
 * While (a) and (b) are only defined here, the full
 * relationship (a) <=> (b) <=> (c) should reside in marsadm.
 */

#include <uapi/asm-generic/errno-base.h>
#include <uapi/asm-generic/errno.h>

/* logfile scanning problems */
#define MARS_ERR_NOSCAN		10000	/* Logfile scan was not possible */
#define MARS_ERR_SCAN_TIMEOUT	10001	/* Logfile scan timsouted */
#define MARS_ERR_SCAN_HOLE	10002	/* Detected a hole in logfile */
#define MARS_ERR_SCAN_FORMAT	10003	/* Unknown record format in logfile */
#define MARS_ERR_SCAN_INVAL	10003	/* Record marked as invalid */
#define MARS_ERR_SCAN_ZERO	10004	/* Zero-length record encountered */
#define MARS_ERR_SCAN_NEGATIVE	10005	/* Negative record length */
#define MARS_ERR_SCAN_BADLEN	10006	/* Mismatch in record length */
#define MARS_ERR_SCAN_ADVANCE	10007	/* Positional advance too small */
#define MARS_ERR_SCAN_RESTLEN	10008	/* Record restlen not sufficient */
#define MARS_ERR_SCAN_INCOMPL	10009	/* Record explicitly marked as incomplete */
#define MARS_ERR_SCAN_SEQ_FW	10010	/* Illegal record sequence skip forward */
#define MARS_ERR_SCAN_SEQ_BW	10011	/* Record sequence skip backwards */
#define MARS_ERR_SCAN_SIZE	10012	/* Internal size mismatch */
#define MARS_ERR_SCAN_MAGIC	10013	/* Unrecognized record */

#define MARS_ERR_MAGIC_BAD	10020	/* Bad magic  */
#define MARS_ERR_MAGIC_REPEATED	10021	/* Bad magic has repeated pattern */
#define MARS_ERR_SCAN_GARBAGE	10029	/* Scanning found garbage */

/* CRC errors */
#define MARS_ERR_CRC_FLAGS	10100	/* Bad CRC flags found */
#define MARS_ERR_CRC_MISMATCH	10101	/* CRC mismatch found */

/* Compression errors */
#define MARS_ERR_DECOMPR_FAIL	10150	/* Decompression failure */
#define MARS_ERR_DECOMPR_TOOBIG	10151	/* Cannot handle decompression length */
#define MARS_ERR_DECOMPR_BADLEN	10152	/* Implausible decompression length */



#endif
