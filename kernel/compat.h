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

#include <linux/syscalls.h>
#include <linux/major.h>

/* Detect 5c0ba4e0762e6dabd14a5c276652e2defec38de7
 * and f2b91d8d385d2cef3a1e3b3846f2dde4a6720c43
 * via 2b44c4db2e2f1765d35163a861d301038e0c8a75
 */
#ifdef PF_SUSPEND_TASK
#define MARS_HAS_ITERATE_DIR
#if !defined(f_dentry)
#define __HAS_NEW_FILLDIR_T
#endif
/* else use old vfs_readdir() */
#endif

#ifdef RENAME_NOREPLACE
#define __HAS_RENAME2
#endif

/* TRANSITIONAL compatibility to the old/new prepatch
 * and the new wrappers around vfs_*().
 */
#ifdef MARS_MAJOR
#if !defined(MARS_HAS_PREPATCH_V3)
/*
 * Obey 819671ff849b07b9831b91de879ddc5da4b333d4 as much as possible,
 * detected via 57b56ac6fecb05c3192586e4892572dd13d972de
 */
#ifdef SB_I_UNTRUSTED_MOUNTER
#define MARS_HAS_PREPATCH_V2
#else
/* old prepatch (to disappear), using deprecated sys_*() calls */
#define MARS_HAS_PREPATCH
#endif
#endif /* !defined(MARS_HAS_PREPATCH_V3) */
#else /* MARS_MAJOR */
#define MARS_MAJOR (DRBD_MAJOR + 1)
#endif /* MARS_MAJOR */

#if defined(MARS_HAS_PREPATCH_V2) || defined(MARS_HAS_PREPATCH)

#else /* MARS_HAS_PREPATCH */

#include <linux/compiler.h>
#include <linux/time.h>
#include "lamport.h"

/* The __oldcompat_*() functions were originally needed for OLD out-of-tree
 * versions of MARS for adapdation to OLD kernel versions.
 * After some v4.xxx kernels, the out-of-tree compile did not
 * really work anymore.
 * Even some combinations of in-tree mars.ko with some (Frankenstein) kernels
 * were requiring this code.
 *
 * This crap should VANISH in the long term, by integration of MARS
 * into the upstream kernel.
 *
 * Since kernel v5.10 and later, it should be possible to compile (and run!)
 * even an out-of-tree mars.ko without the following compat_*()
 * historics.
 */
#define MARS_NEEDS_OLDCOMPAT_FUNCTIONS

extern int __oldcompat_symlink(
	const char __user *oldname,
	const char __user *newname,
	struct lamport_time *mtime);

extern int __oldcompat_mkdir(
	const char __user *pathname,
	int mode);

extern int __oldcompat_rename(
	const char __user *oldname,
	const char __user *newname);

extern int __oldcompat_unlink(
	const char __user *pathname);

#endif /* MARS_HAS_PREPATCH */

/* Various compatibility checks for upstream kernels.
 * This is a hell.
 */

/* For bio block layer compatibility */
#include <linux/blk_types.h>
#include <linux/bio.h>

#ifdef __bvec_iter_bvec
#define MARS_HAS_BVEC_ITER
#endif

/* Detect upstream commits
 * dc3b17cc8bf21307c7e076e7c778d5db756f7871
 * d03f6cdc1fc422accb734c7c07a661a0018d8631
 * b1d2dc5659b41741f5a29b2ade76ffb4e5bb13d8
 * via fd2d332677c687ca90c12a47d6c377c547100b56
 */
#include <linux/blkdev.h>
#ifdef BLK_QC_T_INTERNAL
#define MARS_HAS_BDI_GET
#endif
#ifdef MARS_HAS_BDI_GET
#include <linux/backing-dev.h>
#endif

/* Adapt to 3d745ea5b095a3985129e162900b7e6c22518a9d
 * detected via 9243c6f3e012a92dd900d97ef45efaf8a8edc448
 * and see its comment.
 */
#if !defined(GENHD_FL_MEDIA_CHANGE_NOTIFY) ||	\
  defined(IOCB_WAITQ)
#define MARS_NEW_BLK_ALLOC_QUEUE
#endif

/* Detect upstream commits
 * 2a842acab109f40f0d7d10b38e9ca88390628996
 * 4e4cbee93d56137ebff722be022cae5f70ef84fb
 * & neighbour commits.
 */
#ifdef BLK_STS_OK
#define MARS_HAS_BI_STATUS
#else
/* adaptation to 4246a0b63bd8f56a1469b12eafeb875b1041a451 and 8ae126660fddbeebb9251a174e6fa45b6ad8f932 */
#ifndef bio_io_error
#define MARS_HAS_BI_ERROR
#else
#define MARS_HAS_MERGE_BVEC
#endif
#endif

/* Adapt to 74d46992e0d9dee7f1f376de0d56d31614c8a17a
 */
#ifdef bio_set_dev
#define MARS_HAS_SET_DEV
#endif

/* adapt to 4e1b2d52a80d79296a5d899d73249748dea71a53 and many others */
#ifdef bio_op
#define MARS_HAS_NEW_BIO_OP
#endif

#ifdef bio_end_sector
#define MARS_HAS_VOID_RELEASE
#endif

#ifdef __bvec_iter_bvec
#define MARS_HAS_BVEC_ITER
#endif

/* 54efd50bfd873e2dbf784e0b21a8027ba4299a3e and 8ae126660fddbeebb9251a174e6fa45b6ad8f932,
 * detected via 4246a0b63bd8f56a1469b12eafeb875b1041a451
 */
#ifndef BIO_UPTODATE
#define NEED_BIO_SPLIT
#endif
/* Adapt to modification of blk_queue_split() in
 * af67c31fba3b879b241536a48df703a2eee18ebf
 * detected via f4560ffe8cec1361b1021d81aca6a4173f8e7c87
 */
#ifdef QUEUE_FLAG_QUIESCED
#define MARS_HAS_BIO_SPLIT2
#endif

/* adapt to 4e1b2d52a80d79296a5d899d73249748dea71a53 and many others */
#ifdef bio_op
#define MARS_HAS_NEW_BIO_OP
#endif

/* adapt to 8d2bbd4c8236e9e38e6b36ac9e2c54fdcfe5b335
 * obyeing 2b24e6f63ac9e817630424c6d8f008256348dfc4,
 * the latter detected via 932f4a630a695212bdc7379b05f9bd0dafc5d968
 */
#if defined(BIO_THROTTLED) || defined(FOLL_LONGTERM)
#define MARS_HAS_BIO_THROTTLED
#endif

/* adapt to 0d945c1f966b2bcb67bb12be749da0a7fb00201b
 * detected via 8f4236d9008b0973a8281256ccfde6913cdec6cb
 */
#ifdef QUEUE_FLAG_BYPASS
#define MARS_HAS_OLD_QUEUE_LOCK
#endif

/* IO accounting */

/* adapt to 394ffa503bc40e32d7f54a9b817264e81ce131b4
 * detected via b25de9d6da49b1a8760a89672283128aa8c7
 */
#ifndef BIO_EOPNOTSUPP
#define MARS_HAS_GENERIC_BLK_ACCOUNTING
#elif defined(part_stat_lock)
#define MARS_HAS_OLD_BLK_ACCOUNTING
#endif
/* adapt to d62e26b3ffd28f16ddae85a1babd0303a1a6dfb6
 * detected via e743eb1ecd5564b5ae0a4a76c1566f748a358839
 */
#ifndef QUEUE_FLAG_SYNCFULL
#define MARS_HAS_NEW_GENERIC_BLK_ACCOUNTING
#endif

/* vfs stuff */

/* Adapt to
 * eb031849d52e61d24ba54e9d27553189ff328174 and siblings
 * bdd1d2d3d251c65b74ac4493e08db18971c09240
 * e13ec939e96b13e664bb6cee361cc976a0ee621a
 * detected via e462ec50cb5fad19f6003a3d8087f4a0945dd2b1
 */
#ifdef SB_RDONLY
#define MARS_HAS_KERNEL_READ
#endif

/* Adapt to fd4a0edf2a3d781c6ae07d2810776ce22302ee1c
 * detected via 76fca90e9f3abc82114d9d02d8e14e0324a18ca2
 */
#ifdef IOP_DEFAULT_READLINK
#define MARS_HAS_VFS_READLINK
#endif

/* for mm stuff, should disappear */

/* adapt to 68e21be2916b359fd8afb536c1911dc014cfd03e
 * detected via dea38c74cb9205341f52b8d8ae18f61247a43ea8
 */
#ifndef CALC_LOAD
#include <linux/sched/mm.h>
#endif

/* for networking */
#include <net/sock.h>

#ifndef TCP_MAX_REORDERING
#define __HAS_IOV_ITER
#endif

/* see eeb1bd5c40edb0e2fd925c8535e2fdebdbc5cef2 */
#ifdef sk_net_refcnt
#define __HAS_STRUCT_NET
#endif

/* adapt to a9beb86ae6e55bd92f38453c8623de60b8e5a308
 */
#ifdef SO_SNDTIMEO_NEW
#define MARS_HAS_SO_SNDTIMEO_NEW
#endif

/* for crypto stuff */
#include <linux/crypto.h>

/*
 * Forced by 896545098777564212b9e91af4c973f094649aa7
 * Detected by 7b5a080b3c46f0cac71c0d0262634c6517d4ee4f
 */
#ifdef CRYPTO_ALG_TYPE_SHASH
#define MARS_HAS_NEW_CRYPTO
#endif

#if defined(CONFIG_CRC32C) || defined(CONFIG_CRYPTO_CRC32C) || defined(CONFIG_CRYPTO_CRC32C_MODULE)
#define HAS_CRC32C
#endif

#if defined(CONFIG_CRC32) || defined(CONFIG_CRYPTO_CRC32) || defined(CONFIG_CRYPTO_CRC32_MODULE)
#define HAS_CRC32
#endif

#if defined(CONFIG_CRYPTO_SHA1) || defined(CONFIG_CRYPTO_SHA1_MODULE)
#define HAS_SHA1
#endif

/* adapt to 877b5691f27a1aec0d9b53095a323e45c30069e2
 * detected via 113b7dfd827175977ea71cc4a29c1ac24acb9fce
 */
#ifdef LRU_ALL_FILE
#define MARS_HAS_SHASH_DESC_FLAGS
#endif

/* compression stuff */

#if (defined(CONFIG_LZO_COMPRESS) || defined(CONFIG_LZO_COMPRESS_MODULE)) && \
  (defined(CONFIG_LZO_DECOMPRESS) || defined(CONFIG_LZO_DECOMPRESS_MODULE))
#include <linux/lzo.h>
#define HAS_LZO
#endif

#if (defined(CONFIG_LZ4_COMPRESS) || defined(CONFIG_LZ4_COMPRESS_MODULE)) && \
  (defined(CONFIG_LZ4_DECOMPRESS) || defined(CONFIG_LZ4_DECOMPRESS_MODULE))
#include <linux/lz4.h>
#define HAS_LZ4
/* adapt to 4e1a33b105ddf201f66dcc44490c6086a25eca0b
 */
#ifdef LZ4_ACCELERATION_DEFAULT
#define HAS_FAST_LZ4
#endif
#endif

#if defined(CONFIG_ZLIB_INFLATE) && defined(CONFIG_ZLIB_DEFLATE)
#include <linux/zlib.h>
#define HAS_ZLIB
#endif

/* general compat */

/* new code prefers READ_ONCE in place of ACCESS_ONCE */
#ifndef READ_ONCE
#define READ_ONCE ACCESS_ONCE
#endif
#ifndef WRITE_ONCE
/* quirk */
#define WRITE_ONCE(dst,src) ACCESS_ONCE(dst) = (src)
#endif

#endif /* _MARS_COMPAT */
