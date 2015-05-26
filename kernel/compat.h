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

#ifndef _MARS_COMPAT
#define _MARS_COMPAT

#include <linux/major.h>

/* TRANSITIONAL compatibility to BOTH the old prepatch
 * and the new wrappers around vfs_*().
 */
#ifdef MARS_MAJOR
#define HAS_MARS_PREPATCH
#else
#define MARS_MAJOR (DRBD_MAJOR + 1)
#endif

#ifdef HAS_MARS_PREPATCH

#include <linux/syscalls.h>

#else /* HAS_MARS_PREPATCH */

#include <linux/compiler.h>

extern int _compat_symlink(
	const char __user *oldname,
	const char __user *newname);

extern int _compat_mkdir(
	const char __user *pathname,
	int mode);

#endif /* HAS_MARS_PREPATCH */

#endif /* _MARS_COMPAT */
