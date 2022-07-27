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


//#define BRICK_DEBUGGING
#define MARS_DEBUGGING
//#define IO_DEBUGGING
#define STAT_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/utsname.h>
#include <linux/crc32c.h>

#include "strategy.h"

#include "../lib_mapfree.h"
#include "../mars_client.h"

#include "../compat.h"
#include <linux/namei.h>
#include <linux/kthread.h>
#include <linux/statfs.h>

#define SKIP_BIO false

//      remove_this
#include <linux/wait.h>
#include <linux/version.h>

#ifndef DCACHE_MISS_TYPE /* define accessors compatible to b18825a7c8e37a7cf6abb97a12a6ad71af160de7 */
#define d_is_negative(dentry)     ((dentry)->d_inode == NULL)
#define d_backing_inode(dentry)   ((dentry)->d_inode)
#endif

//      end_remove_this
/////////////////////////////////////////////////////////////////////

// meta descriptions

const struct meta mars_kstat_meta[] = {
	META_INI(ino, struct kstat, FIELD_INT),
	META_INI(mode, struct kstat, FIELD_INT),
	META_INI(size, struct kstat, FIELD_INT),
	META_INI_SUB(atime, struct kstat, mars_lamport_time_meta),
	META_INI_SUB(mtime, struct kstat, mars_lamport_time_meta),
	META_INI_SUB(ctime, struct kstat, mars_lamport_time_meta),
	META_INI(blksize, struct kstat, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_kstat_meta);

const struct meta mars_dent_meta[] = {
	META_INI(d_name,    struct mars_dent, FIELD_STRING),
	META_INI(d_rest,    struct mars_dent, FIELD_STRING),
	META_INI(d_path,    struct mars_dent, FIELD_STRING),
	META_INI(d_type,    struct mars_dent, FIELD_INT),
	META_INI(d_class,   struct mars_dent, FIELD_INT),
	META_INI(d_serial,  struct mars_dent, FIELD_INT),
	META_INI(d_corr_A,  struct mars_dent, FIELD_INT),
	META_INI(d_corr_B,  struct mars_dent, FIELD_INT),
	META_INI(d_proto,   struct mars_dent, FIELD_INT),
	META_INI(d_unordered, struct mars_dent, FIELD_INT),
	META_INI_SUB(new_stat,struct mars_dent, mars_kstat_meta),
	META_INI_SUB(old_stat,struct mars_dent, mars_kstat_meta),
	META_INI(new_link,    struct mars_dent, FIELD_STRING),
	META_INI(old_link,    struct mars_dent, FIELD_STRING),
	META_INI(d_args,    struct mars_dent, FIELD_STRING),
	META_INI(d_argv[0], struct mars_dent, FIELD_STRING),
	META_INI(d_argv[1], struct mars_dent, FIELD_STRING),
	META_INI(d_argv[2], struct mars_dent, FIELD_STRING),
	META_INI(d_argv[3], struct mars_dent, FIELD_STRING),
	{}
};
EXPORT_SYMBOL_GPL(mars_dent_meta);

//      remove_this
#ifndef MARS_HAS_PREPATCH
/////////////////////////////////////////////////////////////////////

/* The _compat_*() functions are needed for the out-of-tree version
 * of MARS for adapdation to different kernel version.
 */

#ifdef SB_FREEZE_LEVELS
/* since kernel 3.6 */
/* see a8104a9fcdeb82e22d7acd55fca20746581067d3 */
/* locking order changes in c30dabfe5d10c5fd70d882e5afb8f59f2942b194, we need to adapt */
#define __NEW_PATH_CREATE
#endif

#include <linux/fscache-cache.h>
#ifndef FSCACHE_OP_DEAD
/* since kernel 3.8 */
/* see b9d6ba94b875192ef5e2dab92d72beea33b83c3d */
#define  __HAS_RETRY_ESTALE
#endif

/* 5955102c9984fa081b2d570cfac75c97eecf8f3b
 */
#ifndef FLOCK_VERIFY_READ /* detect kernel 4.5-rc1 via acc15575e */
#define HAS_INODE_LOCK_WRAPPERS
#endif

/* Hack because of 8bcb77fabd7cbabcad49f58750be8683febee92b
 */
static int __path_parent(const char *name, struct path *path, unsigned flags)
{
#ifdef user_path
	return kern_path(name, flags | LOOKUP_PARENT | LOOKUP_DIRECTORY | LOOKUP_FOLLOW, path);
#else
	char *tmp;
	int len;
	int error;

	len = strlen(name);
	while (len > 0 && name[len] != '/')
		len--;
	if (unlikely(!len))
		return -EINVAL;

	tmp = brick_string_alloc(len + 1);
	strncpy(tmp, name, len);
	tmp[len] = '\0';

	error = kern_path(tmp, flags | LOOKUP_DIRECTORY | LOOKUP_FOLLOW, path);

	brick_string_free(tmp);
	return error;
#endif
}

/* code is blindly stolen from symlinkat()
 * and later adapted to various kernels
 */
int _compat_symlink(const char __user *oldname,
		    const char __user *newname,
		    struct lamport_time *mtime)
{
	const int newdfd = AT_FDCWD;
	int error;
	char *from;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;

	from = (char *)oldname;

#ifdef __HAS_RETRY_ESTALE
retry:
#endif
	dentry = user_path_create(newdfd, newname, &path, lookup_flags);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_putname;

#ifndef __NEW_PATH_CREATE
	error = mnt_want_write(path.mnt);
	if (error)
		goto out_dput;
#endif
	error = vfs_symlink(path.dentry->d_inode, dentry, from);
	if (error >= 0 && mtime) {
		struct iattr iattr = {
			.ia_valid = ATTR_MTIME | ATTR_MTIME_SET | ATTR_TIMES_SET,
			.ia_mtime.tv_sec = mtime->tv_sec,
			.ia_mtime.tv_nsec = mtime->tv_nsec,
		};

#ifdef HAS_INODE_LOCK_WRAPPERS
		inode_lock(dentry->d_inode);
#else
		mutex_lock(&dentry->d_inode->i_mutex);
#endif
#ifdef FL_DELEG
		error = notify_change(dentry, &iattr, NULL);
#else
		error = notify_change(dentry, &iattr);
#endif
#ifdef HAS_INODE_LOCK_WRAPPERS
		inode_unlock(dentry->d_inode);
#else
		mutex_unlock(&dentry->d_inode->i_mutex);
#endif
	}
#ifdef __NEW_PATH_CREATE
	done_path_create(&path, dentry);
#else
	mnt_drop_write(path.mnt);
out_dput:
	dput(dentry);
	mutex_unlock(&path.dentry->d_inode->i_mutex);
	path_put(&path);
#endif
#ifdef __HAS_RETRY_ESTALE
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
#endif
out_putname:
	return error;
}

/* code is stolen from mkdirat()
 */
int _compat_mkdir(const char __user *pathname,
		  int mode)
{
	const int dfd = AT_FDCWD;
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

#ifdef __HAS_RETRY_ESTALE
retry:
#endif
	dentry = user_path_create(dfd, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
#ifndef __NEW_PATH_CREATE
	error = mnt_want_write(path.mnt);
	if (error)
		goto out_dput;
#endif
	error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
#ifdef __NEW_PATH_CREATE
	done_path_create(&path, dentry);
#else
	mnt_drop_write(path.mnt);
out_dput:
	dput(dentry);
	mutex_unlock(&path.dentry->d_inode->i_mutex);
	path_put(&path);
#endif
#ifdef __HAS_RETRY_ESTALE
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
#endif
	return error;
}

/* This has some restrictions:
 *  - oldname and newname must reside in the same directory
 *  - standard case, no mountpoints inbetween
 *  - no security checks (we are anyway called from kernel code)
 */
int _compat_rename(const char *oldname,
		   const char *newname)
{
	struct path oldpath;
	struct path newpath;
	struct dentry *old_dir;
	struct dentry *new_dir;
	struct dentry *old_dentry;
	struct dentry *new_dentry;
	struct dentry *trap;
	const char *old_one;
	const char *new_one;
	const char *tmp;
	unsigned int lookup_flags = 0;
#ifdef __HAS_RETRY_ESTALE
	bool should_retry = false;
#endif
	int error;

#ifdef __HAS_RETRY_ESTALE
retry:
#endif
	error = __path_parent(oldname, &oldpath, lookup_flags);
	if (unlikely(error))
		goto exit;
	old_dir = oldpath.dentry;

	error = __path_parent(newname, &newpath, lookup_flags);
	if (unlikely(error))
		goto exit1;
	new_dir = newpath.dentry;

	old_one = oldname;
	for (;;) {
		for (tmp = old_one; *tmp && *tmp != '/'; tmp++)
			/* empty */;
		if (!*tmp)
			break;
		old_one = tmp + 1;
	}

	new_one = newname;
	for (;;) {
		for (tmp = new_one; *tmp && *tmp != '/'; tmp++)
			/* empty */;
		if (!*tmp)
			break;
		new_one = tmp + 1;
	}

#ifdef __NEW_PATH_CREATE
	error = mnt_want_write(oldpath.mnt);
	if (unlikely(error))
		goto exit2;
#endif
	trap = lock_rename(new_dir, old_dir);

	old_dentry = lookup_one_len(old_one, old_dir, strlen(old_one));
	error = PTR_ERR(old_dentry);
	if (unlikely(IS_ERR(old_dentry)))
		goto out_unlock_rename;
	error = -ENOENT;
	if (unlikely(d_is_negative(old_dentry)))
		goto out_dput_old;
	error = -EINVAL;
	if (unlikely(old_dentry == trap))
		goto out_dput_old;

	new_dentry = lookup_one_len(new_one, new_dir, strlen(new_one));
	error = PTR_ERR(new_dentry);
	if (unlikely(IS_ERR(new_dentry)))
		goto out_dput_old;
	error = -ENOTEMPTY;
	if (unlikely(new_dentry == trap))
		goto out_dput_new;

#ifndef __NEW_PATH_CREATE
	error = mnt_want_write(oldpath.mnt);
	if (unlikely(error))
		goto out_dput_new;
#endif

#ifdef __HAS_RENAME2
	error = vfs_rename(old_dir->d_inode, old_dentry,
			   new_dir->d_inode, new_dentry, NULL, 0);
#elif defined(FL_DELEG)
	error = vfs_rename(old_dir->d_inode, old_dentry,
			   new_dir->d_inode, new_dentry, NULL);
#else
	error = vfs_rename(old_dir->d_inode, old_dentry,
			   new_dir->d_inode, new_dentry);
#endif

#ifndef __NEW_PATH_CREATE
	mnt_drop_write(oldpath.mnt);
#endif

out_dput_new:
	dput(new_dentry);

out_dput_old:
	dput(old_dentry);

out_unlock_rename:
	unlock_rename(new_dir, old_dir);
#ifdef __NEW_PATH_CREATE
	mnt_drop_write(oldpath.mnt);
exit2:
#endif
#ifdef __HAS_RETRY_ESTALE
	if (retry_estale(error, lookup_flags))
		should_retry = true;
#endif
	path_put(&newpath);
exit1:
	path_put(&oldpath);
#ifdef __HAS_RETRY_ESTALE
	if (should_retry) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
#endif
exit:
	return error;
}

/* This has some restrictions:
 *  - standard case, no mountpoints inbetween
 *  - no security checks (we are anyway called from kernel code)
 */
int _compat_unlink(const char *pathname)
{
	struct path path;
	struct dentry *parent;
	struct dentry *dentry;
	struct inode *inode = NULL;
	const char *one;
	const char *tmp;
	int error;
	unsigned int lookup_flags = 0;

#ifdef __HAS_RETRY_ESTALE
retry:
#endif
	error = __path_parent(pathname, &path, lookup_flags);
	if (unlikely(error))
		goto exit;

	parent = path.dentry;
	if (unlikely(d_is_negative(parent)))
		goto exit1;

	one = pathname;
	for (;;) {
		for (tmp = one; *tmp && *tmp != '/'; tmp++)
			/* empty */;
		if (!*tmp)
			break;
		one = tmp + 1;
	}

#ifdef __NEW_PATH_CREATE
	error = mnt_want_write(path.mnt);
	if (error)
		goto exit1;
#endif
#ifdef HAS_INODE_LOCK_WRAPPERS
	inode_lock_nested(parent->d_inode, I_MUTEX_PARENT);
#else
	mutex_lock_nested(&parent->d_inode->i_mutex, I_MUTEX_PARENT);
#endif

	dentry = lookup_one_len(one, parent, strlen(one));
	error = PTR_ERR(dentry);
	if (unlikely(IS_ERR(dentry)))
		goto exit2;
	error = -ENOENT;
	if (unlikely(d_is_negative(dentry)))
		goto exit3;

	inode = dentry->d_inode;
	ihold(inode);

#ifndef __NEW_PATH_CREATE
	error = mnt_want_write(path.mnt);
	if (error)
		goto exit3;
#endif

#ifdef FL_DELEG
	error = vfs_unlink(parent->d_inode, dentry, NULL);
#else
	error = vfs_unlink(parent->d_inode, dentry);
#endif

#ifndef __NEW_PATH_CREATE
	mnt_drop_write(path.mnt);
#endif
exit3:
	dput(dentry);
exit2:
#ifdef HAS_INODE_LOCK_WRAPPERS
	inode_unlock(parent->d_inode);
#else
	mutex_unlock(&parent->d_inode->i_mutex);
#endif
	if (inode)
		iput(inode);
#ifdef __NEW_PATH_CREATE
	mnt_drop_write(path.mnt);
#endif
exit1:
	path_put(&path);
exit:
#ifdef __HAS_RETRY_ESTALE
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		inode = NULL;
		goto retry;
	}
#endif
	return error;
}

#endif
//      end_remove_this
/////////////////////////////////////////////////////////////////////

// some helpers

static inline
int _length_paranoia(int len, int line)
{
	if (unlikely(len < 0)) {
		MARS_ERR("implausible string length %d (line=%d)\n", len, line);
		len = PAGE_SIZE - 2;
	} else if (unlikely(len > PAGE_SIZE - 2)) {
		MARS_WRN("string length %d will be truncated to %d (line=%d)\n",
			 len, (int)PAGE_SIZE - 2, line);
		len = PAGE_SIZE - 2;
	}
	return len;
}

bool mars_is_mountpoint(const char *pathname)
{
	struct path path = {};
	mm_segment_t oldfs;
	int status;
	bool res = false;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	status = user_path_at(AT_FDCWD, pathname, 0, &path);
	if (unlikely(status < 0)) {
		MARS_WRN("pathname '%s' does not exist, status = %d\n",
			 pathname, status);
		goto done_fs;
	}
	if (unlikely(!path.dentry)) {
		MARS_WRN("path '%s' has invalid dentry\n", pathname);
		goto done_put;
	}
	if (unlikely(!follow_up(&path))) {
		MARS_WRN("path '%s' has no vfsmnt\n", pathname);
		goto done_put;
	}
	/* the second one may fail when we already are at the root mount */
	if (!follow_up(&path)) {
		goto done_put;
	}
	res = d_mountpoint(path.dentry);

done_put:
	path_put(&path);

done_fs:
	set_fs(oldfs);
	return res;
}

int mars_stat(const char *path, struct kstat *stat, bool use_lstat)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	if (use_lstat) {
		status = vfs_lstat((char*)path, stat);
	} else {
		status = vfs_stat((char*)path, stat);
	}
	set_fs(oldfs);

	if (likely(status >= 0)) {
		set_lamport(&stat->mtime);
	}

	return status;
}
EXPORT_SYMBOL_GPL(mars_stat);

void mars_sync(void)
{
	struct file *f;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	f = filp_open("/mars", O_DIRECTORY | O_RDONLY, 0);
	set_fs(oldfs);
	if (unlikely(IS_ERR(f)))
		return;

	if (likely(f->f_mapping)) {
		struct inode *inode = f->f_mapping->host;

		if (likely(inode && inode->i_sb)) {
			struct super_block *sb = inode->i_sb;
			down_read(&sb->s_umount);
			sync_filesystem(sb);
			shrink_dcache_sb(sb);
			up_read(&sb->s_umount);
		}
	}

	filp_close(f, NULL);
}

int mars_mkdir(const char *path)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
#ifdef MARS_HAS_PREPATCH
	status = sys_mkdir(path, 0700);
#else
	status = _compat_mkdir(path, 0700);
#endif
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_mkdir);

int mars_rmdir(const char *path)
{
#ifdef MARS_HAS_PREPATCH
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	status = sys_rmdir(path);
	set_fs(oldfs);

	return status;
#else
	return -ENOSYS;
#endif
}
EXPORT_SYMBOL_GPL(mars_rmdir);

int mars_unlink(const char *path)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
#ifdef MARS_HAS_PREPATCH
	status = sys_unlink(path);
#else
	status = _compat_unlink(path);
#endif
	set_fs(oldfs);

	return status;
}

static
int mars_symlink(const char *oldpath, const char *newpath,
		 const struct lamport_time *stamp,
		 bool ordered)
{
	char *tmp = backskip_replace(newpath, '/', true, "/.tmp-"); 
	mm_segment_t oldfs;
	struct kstat stat = {};
	struct lamport_time times[2];
	int status;
	
	if (stamp)
		memcpy(&times[0], stamp, sizeof(times[0]));
	else
		get_lamport(NULL, &times[0]);
	
#ifdef CONFIG_MARS_DEBUG
	while (mars_hang_mode & 4)
		brick_msleep(100);
#endif

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	status = vfs_lstat((char*)newpath, &stat);

	/* When ordered, obey the Lamport condition.
	 */
	if (ordered && status >= 0 && stamp &&
	    lamport_time_compare(&stat.mtime, stamp) > 0) {
		struct lamport_time real_now;

		/* Illegal old link stamps are disobeyed, when
		 * they are too far in the future.
		 * Although this leads to a backskip violating
		 * the Lamport condition, it is a beneficial
		 * exceptional error correction.
		 * Such errors have been observed at ShaHoLin
		 * after fatal hardware crashes, where MARS
		 * was run for a _short_ time with an illegal
		 * CMOS hardware clock value, until ntpd
		 * corrected the system clock, fortunately.
		 */
		get_real_lamport(&real_now);
		status = 1;
		if (likely(stat.mtime.tv_sec <
			   real_now.tv_sec + max_lamport_future))
			goto done_fs;
		/* Continue, overriding the illegal old
		 * link stamp by exceptionally disobeying
		 * the Lamport condition.
		 */
	}

	/* Some filesystems have only full second resolution.
	 * Thus it may happen that the new timestamp is not
	 * truly moving forward when called twice shortly.
	 * This is a _workaround_, to be replaced by a better
	 * method somewhen.
	 */
	if (status >= 0 &&
	    !stamp &&
	    !stat.mtime.tv_nsec &&
	    times[0].tv_sec == stat.mtime.tv_sec) {
		MARS_DBG("workaround timestamp tv_sec=%lld\n",
			 (s64)stat.mtime.tv_sec);
		times[0].tv_sec = stat.mtime.tv_sec + 1;
		/* Setting tv_nsec to 1 prevents from unnecessarily reentering
		 * this workaround again if accidentally the original tv_nsec
		 * had been 0 or if the workaround had been triggered.
		 */
		times[0].tv_nsec = 1;
	}

#ifdef MARS_HAS_PREPATCH
	(void)sys_unlink(tmp);
	status = sys_symlink(oldpath, tmp);
	if (status >= 0) {
		sys_lchown(tmp, 0, 0);
		memcpy(&times[1], &times[0], sizeof(struct lamport_time));
		status = do_utimes(AT_FDCWD, tmp, times, AT_SYMLINK_NOFOLLOW);
	}
#else
	(void)_compat_unlink(tmp);
	status = _compat_symlink(oldpath, tmp, &times[0]);
#endif

	if (status >= 0) {
		set_lamport(&times[0]);
		status = mars_rename(tmp, newpath);
	}
 done_fs:
	set_fs(oldfs);
	brick_string_free(tmp);
	return status;
}

/* adapt to ce6595a28a15c874aee374757dcd08f537d7b24d
 * detected via 84a2bd39405ffd5fa6d6d77e408c5b9210da98de
 */
#ifdef LOOKUP_ROOT_GRABBED
#define user_lpath(name,path)					\
	user_path_at_empty(AT_FDCWD, (name), 0, (path), NULL)
#endif

char *mars_readlink(const char *newpath, struct lamport_time *stamp)
{
	char *res = NULL;
	struct path path = {};
	mm_segment_t oldfs;
	struct inode *inode;
	int len;
	int status;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	status = user_lpath(newpath, &path);
	if (unlikely(status < 0)) {
		MARS_DBG("link '%s' does not exist, status = %d\n", newpath, status);
		goto done_fs;
	}
	if (unlikely(!path.dentry)) {
		MARS_WRN("path '%s' has invalid dentry\n", newpath);
		goto done_put;
	}

#ifdef MARS_HAS_VFS_READLINK
	inode = d_inode(path.dentry);
#else
	inode = path.dentry->d_inode;
#endif
	if (unlikely(!inode)) {
		MARS_ERR("link '%s' has invalid inode\n", newpath);
		status = -EINVAL;
		goto done_put;
	}
	if (S_ISDIR(inode->i_mode)) {
		/* fail silently: this can happen during
		 * deletions of directories
		 */
		status = -EINVAL;
		goto done_put;
	}
	if (!S_ISLNK(inode->i_mode)) {
		MARS_WRN("'%s' is no symlink\n", newpath);
		status = -EINVAL;
		goto done_put;
	}

	len = i_size_read(inode);
	if (unlikely(len <= 0 || len > PAGE_SIZE)) {
		MARS_ERR("link '%s' invalid length = %d\n", newpath, len);
		status = -EINVAL;
		goto done_put;
	}
	res = brick_string_alloc(len + 2);

#ifdef MARS_HAS_VFS_READLINK
	status = vfs_readlink(path.dentry, res, len + 1);
#else
	status = inode->i_op->readlink(path.dentry, res, len + 1);
#endif
	if (unlikely(status < 0)) {
		MARS_ERR("cannot read link '%s', status = %d\n", newpath, status);
	} else if (stamp) {
		set_get_lamport(&inode->i_mtime, NULL, stamp);
	} else {
		set_lamport(&inode->i_mtime);
	}

done_put:
	path_put(&path);
	
done_fs:
	set_fs(oldfs);
	if (unlikely(status < 0)) {
		if (unlikely(!res)) {
			res = brick_string_alloc(1);
		}
		res[0] = '\0';
	}
	return res;
}
EXPORT_SYMBOL_GPL(mars_readlink);

int mars_rename(const char *oldpath, const char *newpath)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
#ifdef MARS_HAS_PREPATCH
	status = sys_rename(oldpath, newpath);
#else
	status = _compat_rename(oldpath, newpath);
#endif
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_rename);

int mars_chmod(const char *path, mode_t mode)
{
#ifdef MARS_HAS_PREPATCH
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	status = sys_chmod(path, mode);
	set_fs(oldfs);

	return status;
#else
	return -ENOSYS;
#endif
}
EXPORT_SYMBOL_GPL(mars_chmod);

loff_t _compute_space(struct kstatfs *kstatfs, loff_t raw_val)
{
	u64 fsize = kstatfs->f_frsize;


	if (fsize <= 0)
		fsize = kstatfs->f_bsize;

	MARS_DBG("fsize = %llu raw_val = %lld\n", fsize, raw_val);

	/* Implausible value:
	 * Guess, use safe side from old Unix...
	 */
	if (fsize <= 0)
		fsize = 512;

	// prevent intermediate integer overflows
	if (fsize <= 1024)
		return raw_val / (1024 / fsize);

	return raw_val * (fsize / 1024);
}

void mars_remaining_space(const char *fspath, loff_t *total, loff_t *remaining)
{
	struct path path = {};
	struct kstatfs kstatfs = {};
	mm_segment_t oldfs;
	int res;

	*total = *remaining = 0;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	res = user_path_at(AT_FDCWD, fspath, 0, &path);

	set_fs(oldfs);

	if (unlikely(res < 0)) {
		MARS_ERR("cannot get fspath '%s', err = %d\n\n", fspath, res);
		goto err;
	}
	if (unlikely(!path.dentry)) {
		MARS_ERR("bad dentry for fspath '%s'\n", fspath);
		res = -ENXIO;
		goto done;
	}

#ifdef ST_RDONLY
	res = vfs_statfs(&path, &kstatfs);
#else
	res = vfs_statfs(path.dentry, &kstatfs);
#endif
	if (unlikely(res < 0)) {
		goto done;
	}

	*total = _compute_space(&kstatfs, kstatfs.f_blocks);
	*remaining = _compute_space(&kstatfs, kstatfs.f_bavail);
	
done:
	path_put(&path);
err: ;
}
EXPORT_SYMBOL_GPL(mars_remaining_space);

/*************************************************************/

/* Timestamp Ordering */

/* Description of the OLD odering method:
 */
/* Timestamp ordering (e.g. via Lamport Clock) is easy when
 * the object exists.
 * When unlink() comes into play, it becomes more complex:
 * where to store the timestamp of the object when it is
 * currently deleted?
 * This is necessary to allow permutations between _all_ operations
 * on the object, including unlink().
 * Idea: use a substitute object ".deleted-$object".
 */

int compat_deletions = 1;

static DEFINE_MUTEX(ordered_lock);

static
int compat_ordered_unlink(const char *path,
			  const struct lamport_time *stamp,
			  int serial, int mode)
{
	struct kstat stat;
	char serial_str[32];
	struct lamport_time now;
	const char *marker_path;
	int marker_status;
	int status = 0;

	snprintf(serial_str, sizeof(serial_str), "%d,%d", serial, mode);
	if (!stamp) {
		get_lamport(NULL, &now);
		stamp = &now;
	}

	mutex_lock(&ordered_lock);

	marker_path = backskip_replace(path, '/', true, "/.deleted-");
	marker_status = mars_stat(marker_path, &stat, true);
	if (marker_status < 0 ||
	    lamport_time_compare(stamp, &stat.mtime) >= 0) {
		MARS_DBG("creating / updating marker '%s' mtime=%lld.%09ld\n",
			 marker_path,
			 (s64)stamp->tv_sec, stamp->tv_nsec);
		status = mars_symlink(serial_str, marker_path, stamp, false);
	}
	if (marker_status < 0 ||
	    lamport_time_compare(stamp, &stat.mtime) >= 0) {
		status = mars_unlink(path);
	}

	mutex_unlock(&ordered_lock);
	brick_string_free(marker_path);
	return status;
}

static
int compat_ordered_symlink(const char *oldpath,
			   const char *newpath,
			   const struct lamport_time *stamp)
{
	struct kstat stat;
	struct lamport_time now;
	const char *marker_path;
	int status = 1;

	if (!stamp) {
		get_lamport(NULL, &now);
		stamp = &now;
	}

	mutex_lock(&ordered_lock);

	marker_path = backskip_replace(newpath, '/', true, "/.deleted-");

	if (mars_stat(marker_path, &stat, true) >= 0 &&
	    lamport_time_compare(&stat.mtime, stamp) > 0) {
		goto done;
	}
	if (mars_stat(newpath, &stat, true) >= 0 &&
	    lamport_time_compare(&stat.mtime, stamp) > 0) {
		goto done;
	}

	(void)mars_unlink(marker_path);
	status = mars_symlink(oldpath, newpath, stamp, false);

 done:
	mutex_unlock(&ordered_lock);
	brick_string_free(marker_path);
	return status;
}

/* NEW timestamp ordering method.
 * Timestamp ordering (e.g. via Lamport Clock) is easy when
 * the object exists.
 * When unlink() comes into play, it becomes more complex:
 * where to store the timestamp of the object when it is
 * deleted?
 * The new method simply uses a special value MARS_DELETED_STR
 * as a marker for symlinks.
 * In order to prevent long-term accumulation of suchalike
 * "zombie" symlinks, some cleanup via unlink() is necessary.
 * We offload cleanup to "marsadm cron".
 */

char *ordered_readlink(const char *path, struct lamport_time *stamp)
{
	char *res = mars_readlink(path, stamp);

	if (!strcmp(res, MARS_DELETED_STR)) {
		*res = '\0';
	}
	return res;
}

int ordered_unlink(const char *path,
		   const struct lamport_time *stamp,
		   int serial, int mode)
{
	if (compat_deletions)
		return compat_ordered_unlink(path, stamp, serial, mode);

	return ordered_symlink(MARS_DELETED_STR, path, stamp);
}

int ordered_symlink(const char *oldpath,
		    const char *newpath,
		    const struct lamport_time *stamp)
{
	char *dir_path = NULL;
	int dir_len;
	int nr_retry = 0;
	int status;

 retry:
	if (compat_deletions)
		status = compat_ordered_symlink(oldpath, newpath, stamp);
	else
		status = mars_symlink(oldpath, newpath, stamp, true);

	/* Automatically create any missing path dirs */
	while (unlikely(status < 0)) {
		int old_len;
		int check;

		if (!dir_path) {
			dir_path = brick_strdup(newpath);
			dir_len = strlen(dir_path);
		}
		old_len = dir_len;
		while (dir_len > 0 && dir_path[dir_len] != '/')
			dir_len--;
		dir_path[dir_len] = '\0';
		if (dir_len <= 0 || dir_len >= old_len)
			break;
		check = mars_mkdir(dir_path);
		if (check >= 0) {
			brick_string_free(dir_path);
			dir_path = NULL;
			if (nr_retry++ < 3)
				goto retry;
			break;
		}
	}
	brick_string_free(dir_path);
	return status;
}

//////////////////////////////////////////////////////////////

// thread binding

void bind_to_dent(struct mars_dent *dent, struct say_channel **ch)
{
	if (!dent) {
		if (*ch) {
			remove_binding_from(*ch, current);
			*ch = NULL;
		}
		return;
	}
	// Memoize the channel. This is executed only once for each dent.
	if (unlikely(!dent->d_say_channel)) {
		struct mars_dent *test = dent->d_parent;

		for (;;) {
			if (!test) {
				dent->d_say_channel = default_channel;
				break;
			}
			CHECK_PTR(test, fatal);
			if (test->d_use_channel && test->d_path) {
				dent->d_say_channel = make_channel(test->d_path,
								   true);
				break;
			}
			test = test->d_parent;
		}
	}
	if (dent->d_say_channel != *ch) {
		if (*ch)
			remove_binding_from(*ch, current);
		*ch = dent->d_say_channel;
		if (*ch)
			bind_to_channel(*ch, current);
	}
 fatal: ;
}
EXPORT_SYMBOL_GPL(bind_to_dent);

//////////////////////////////////////////////////////////////

// infrastructure

struct mars_global *mars_global = NULL;
EXPORT_SYMBOL_GPL(mars_global);

void _init_mars_global(struct mars_global *global)
{
	int i;

	memset(global, 0, sizeof(struct mars_global));
	INIT_LIST_HEAD(&global->dent_anchor);
	INIT_LIST_HEAD(&global->brick_anchor);
	global->global_power.button = true;
	init_waitqueue_head(&global->main_event);
	for (i = 0; i < MARS_GLOBAL_HASH_BASE; i++) {
		struct list_head *table = brick_mem_alloc(PAGE_SIZE);
		int j;

		global->dent_hash_table[i] = table;
		for (j = 0; j < MARS_GLOBAL_HASH_TABLE; j++)
			INIT_LIST_HEAD(&table[j]);
	}
}

void exit_mars_global(struct mars_global *global)
{
	int i;

#ifdef CONFIG_MARS_DEBUG
	CHECK_HEAD_EMPTY(&global->dent_anchor);
	CHECK_HEAD_EMPTY(&global->brick_anchor);
#endif
	for (i = 0; i < MARS_GLOBAL_HASH_BASE; i++) {
		struct list_head *table = global->dent_hash_table[i];
#ifdef CONFIG_MARS_DEBUG
		int j;

		for (j = 0; j < MARS_GLOBAL_HASH_TABLE; j++)
			CHECK_HEAD_EMPTY(&table[j]);
#endif
		brick_mem_free(table);
	}

}

void __mars_trigger(int mode)
{
	struct mars_global *global = mars_global;

	if (global) {
		global->trigger_mode |= mode;
		global->main_trigger = true;
		wake_up_interruptible_all(&global->main_event);
	}
}

static
int mars_check_inputs(struct mars_brick *brick)
{
	int max_inputs;
	int nr_bad = 0;
	int i;

	if (likely(brick->type)) {
		max_inputs = brick->type->max_inputs;
	} else {
		MARS_ERR("uninitialized brick '%s' '%s'\n",
			 brick->brick_name,
			 brick->brick_path);
		return -1;
	}
	for (i = 0; i < max_inputs; i++) {
		struct mars_input *input = brick->inputs[i];
		struct mars_output *prev_output;
		struct mars_brick *prev_brick;

		if (!input)
			continue;
		prev_output = input->connect;
		if (!prev_output)
			continue;
		prev_brick = prev_output->brick;
		CHECK_PTR(prev_brick, done);
		if (prev_brick->power.button && prev_brick->power.led_on)
			continue;
		MARS_ERR("PREDECESSOR %d/%d prev_brick '%s' '%s' type='%s' led_off=%d led_on=%d power=%d\n",
			 i, max_inputs,
			 prev_brick->brick_name, prev_brick->brick_path,
			 prev_brick->type ? prev_brick->type->type_name : "(unknown)",
			 prev_brick->power.led_off, prev_brick->power.led_on, 
			 prev_brick->power.button);

	done:
		nr_bad++;
	}
	if (nr_bad) {
		MARS_ERR("CANNOT SWITCH ON: brick '%s' '%s' type='%s' has %d turned-off / bad predecessors\n",
			 brick->brick_name, brick->brick_path,
			 brick->type ? brick->type->type_name : "(unknown)",
			 nr_bad);
	}
	return nr_bad;
}

static
bool mars_check_outputs(struct mars_brick *brick)
{
	int i;
	for (i = 0; i < brick->type->max_outputs; i++) {
		struct mars_output *output = brick->outputs[i];
		if (!output || !output->nr_connected)
			continue;
		return true;
	}
	return false;
}

int mars_power_button(struct mars_brick *brick, bool val, bool force_off)
{
	int status = 0;
	bool oldval = brick->power.button;

	if (force_off && !val)
		brick->power.force_off = true;

	if (brick->power.force_off)
		val = false;

	if (val != oldval) {
		// check whether switching is possible
		status = -EINVAL;
		if (val) { // check all inputs
			int bad = mars_check_inputs(brick);

			if (unlikely(bad)) {
				goto done;
			}
		} else { // check all outputs
			if (unlikely(mars_check_outputs(brick))) {
				/* For now, we have a strong rule:
				 * Switching off is only allowed when no successor brick
				 * exists at all. This could be relaxed to checking
				 * whether all successor bricks are actually switched off.
				 * Probabĺy it is a good idea to retain the stronger rule
				 * as long as nobody needs the relaxed one.
				 */
				MARS_ERR("CANNOT SWITCH OFF: brick '%s' '%s' type='%s' has a successor\n",
					 brick->brick_name, brick->brick_path,
					 brick->type ? brick->type->type_name : "(unknown)");
				goto done;
			}
		}

		MARS_DBG("brick '%s' '%s' type='%s' power button %d -> %d\n",
			 brick->brick_name, brick->brick_path,
			 brick->type->type_name,
			 oldval, val);

		set_button(&brick->power, val, false);
	}

	if (unlikely(!brick->ops)) {
		MARS_ERR("brick '%s' '%s' has no brick_switch() method\n", brick->brick_name, brick->brick_path);
		status = -EINVAL;
		goto done;
	}

	/* Always call the switch function, even if nothing changes.
	 * The implementations must be idempotent.
	 * They may exploit the regular calls for some maintenance operations
	 * (e.g. changing disk capacity etc).
	 */
	status = brick->ops->brick_switch(brick);

	if (val != oldval || status < 0) {
		mars_trigger();
	}

 done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_power_button);

/////////////////////////////////////////////////////////////////////

// strategy layer


struct mars_cookie {
	struct mars_global *global;
	mars_dent_checker_fn checker;
	char *path;
	struct mars_dent *check_parent;
	struct mars_dent *parent;
	struct list_head tmp_anchor;
	int allocsize;
	int depth;
	bool some_ordered;
	bool hit;
};

static
int get_inode(char *newpath, struct mars_dent *dent, bool get_deleted)
{
	mm_segment_t oldfs;
	int status;
	struct kstat tmp = {};

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	status = vfs_lstat(newpath, &tmp);
	if (status < 0) {
		MARS_WRN("cannot stat '%s', status = %d\n", newpath, status);
		goto done;
	}

	/* Correct illegal timestamps */
	if (unlikely(protect_lamport_time(&tmp.mtime)) &&
	    S_ISLNK(dent->new_stat.mode)) {
		char *val = mars_readlink(newpath, NULL);
		if (val) {
			mars_symlink(val, newpath, &tmp.mtime, false);
			brick_string_free(val);
		}
	}

	memcpy(&dent->old_stat, &dent->new_stat, sizeof(dent->old_stat)); 
	memcpy(&dent->new_stat, &tmp, sizeof(dent->new_stat));

	if (S_ISLNK(dent->new_stat.mode)) {
		struct path path = {};
		int len = dent->new_stat.size;
                struct inode *inode;
		char *link;
		
		if (unlikely(len <= 0)) {
			MARS_ERR("symlink '%s' bad len = %d\n", newpath, len);
			status = -EINVAL;
			goto done;
		}
		len = _length_paranoia(len, __LINE__);

		status = user_path_at(AT_FDCWD, newpath, 0, &path);
		if (unlikely(status < 0)) {
			MARS_WRN("cannot read link '%s'\n", newpath);
			goto done;
		}
		if (unlikely(!path.dentry)) {
			MARS_WRN("path '%s' has invalid dentry\n", newpath);
			goto done;
		}

#ifdef MARS_HAS_VFS_READLINK
		inode = d_inode(path.dentry);
#else
                inode = path.dentry->d_inode;
#endif
		if (unlikely(!inode || !S_ISLNK(inode->i_mode))) {
			MARS_ERR("link '%s' has invalid inode\n", newpath);
			status = -EINVAL;
			goto done_put;
		}

		link = brick_string_alloc(len + 2);
		MARS_IO("len = %d\n", len);
#ifdef MARS_HAS_VFS_READLINK
		status = vfs_readlink(path.dentry, link, len + 1);
#else
		status = inode->i_op->readlink(path.dentry, link, len + 1);
#endif
		link[len] = '\0';
		if (status < 0 ||
		    (dent->new_link && !strcmp(dent->new_link, link))) {
			brick_string_free(link);
		} else {
			MARS_IO("symlink '%s' -> '%s' (%s) status = %d\n", newpath, link, dent->new_link ? dent->new_link : "", status);
			brick_string_free(dent->old_link);
			dent->old_link = dent->new_link;
			dent->new_link = link;
		}
		/* Treat deleted dents as non-existing.
		 * Killing will be done later via ->killme.
		 */
		if (!get_deleted &&
		    status >= 0 &&
		    dent->new_link &&
		    !strcmp(dent->new_link, MARS_DELETED_STR)) {
			status = -ENOENT;
		}
	done_put:
		path_put(&path);
	} else if (S_ISREG(dent->new_stat.mode) && dent->d_name && !strncmp(dent->d_name, "log-", 4)) {
		loff_t min;

		dent->d_corr_A = 0;
		dent->d_corr_B = 0;
		min = mf_get_any_dirty(newpath, DIRTY_COMPLETING);
		if (min < dent->new_stat.size) {
			MARS_DBG("file '%s' A size=%lld min=%lld\n", newpath, dent->new_stat.size, min);
			dent->d_corr_A = min;
		}
		min = mf_get_any_dirty(newpath, DIRTY_FINISHED);
		if (min < dent->new_stat.size) {
			MARS_DBG("file '%s' B size=%lld min=%lld\n", newpath, dent->new_stat.size, min);
			dent->d_corr_B = min;
		}
	}

	if (dent->new_link)
		MARS_IO("symlink '%s'\n", dent->new_link);

 done:
	set_fs(oldfs);
	return status;
}

unsigned int dent_hash(const char *str, int len)
{
	u32 raw_hash = crc32c(0, str, len);
	u32 mask = (u32)-1;
	unsigned int hash = 0;

	/* catch all possible bits */
	while (mask) {
		hash ^= raw_hash;
		raw_hash /= MARS_GLOBAL_HASH;
		mask /= MARS_GLOBAL_HASH;
	}
	hash %= MARS_GLOBAL_HASH;

	return hash;
}

static
int dent_compare(struct mars_dent *a, struct mars_dent *b)
{
	if (a->d_class < b->d_class) {
		return -1;
	}
	if (a->d_class > b->d_class) {
		return +1;
	}
	if (a->d_serial < b->d_serial) {
		return -1;
	}
	if (a->d_serial > b->d_serial) {
		return +1;
	}
	return strcmp(a->d_path, b->d_path);
}

//      remove_this
#ifdef MARS_HAS_ITERATE_DIR
//      end_remove_this
struct mars_dir_context {
	struct dir_context ctx;
	struct mars_cookie *cookie;
};
//      remove_this
#endif
//      end_remove_this

/* Skip any names / directories used for backup etc */
#define SKIP_ENTRY(str)				\
	{ str, strlen(str) }

struct skip_info {
	const char *name;
	int len;
};

const struct skip_info skips[] = {
	SKIP_ENTRY("backup"),
	SKIP_ENTRY("cache"),
	SKIP_ENTRY("local"),
	SKIP_ENTRY("probe"),
	{ NULL, 0 }
};

/* Caution: this is called as a callback from iterate_dir() and friends.
 * Don't deadlock by producing any filesystem output within this!
 */
#ifdef __HAS_NEW_FILLDIR_T
int mars_filler(struct dir_context *__buf, const char *name, int namlen, loff_t offset,
		u64 ino, unsigned int d_type)
#else
static
int mars_filler(void *__buf, const char *name, int namlen, loff_t offset,
		u64 ino, unsigned int d_type)
#endif
{
//      remove_this
#ifdef MARS_HAS_ITERATE_DIR
	struct mars_dir_context *buf = (void *)__buf;
	struct mars_cookie *cookie = buf->cookie;
#else
	struct mars_cookie *cookie = __buf;
#endif
//      end_remove_this
	struct mars_dent *dent;
	char *newpath;
	unsigned int hash;
	int prefix = 0;
	int pathlen;
	int class;
	int serial = 0;
#if 0
	int i;
#endif
	bool use_channel = false;

	cookie->hit = true;
	cookie->global->nr_readitem++;

	if (!name || !*name || name[0] == '.') {
		return 0;
	}

	class = cookie->checker(cookie->check_parent,
				name, namlen,
				d_type,
				&prefix,
				&serial,
				&use_channel);

	/* For some_ordered network transfers, always
	 * accept symlinks.
	 */
	if (class < 0 &&
	    (!cookie->some_ordered ||
	     d_type != DT_LNK))
		return 0;

	pathlen = strlen(cookie->path);
	newpath = brick_string_alloc(pathlen + namlen + 2);
	memcpy(newpath, cookie->path, pathlen);
	newpath[pathlen++] = '/';
	memcpy(newpath + pathlen, name, namlen);
	pathlen += namlen;
	newpath[pathlen] = '\0';

	hash = dent_hash(newpath, pathlen);

	dent = brick_zmem_alloc(cookie->allocsize);

	dent->d_class = class;
	dent->d_serial = serial;
	dent->d_path = newpath;
	newpath = NULL;

	dent->d_hash = hash;
	dent->d_name = brick_string_alloc(namlen + 1);
	memcpy(dent->d_name, name, namlen);
	dent->d_name[namlen] = '\0';
	dent->d_rest = brick_strdup(dent->d_name + prefix);

	INIT_LIST_HEAD(&dent->dent_link);
	INIT_LIST_HEAD(&dent->dent_hash_link);
	INIT_LIST_HEAD(&dent->brick_list);

	list_add(&dent->dent_link, &cookie->tmp_anchor);

	dent->d_type = d_type;
	dent->d_class = class;
	dent->d_serial = serial;
	dent->d_killme = false;
	dent->d_use_channel = use_channel;
	dent->d_depth = cookie->depth;

	return 0;
}

static
void _reconnect_dent(struct mars_dent *parent, struct mars_dent *dent)
{
	CHECK_PTR(dent, fatal);
	if (dent->d_parent == parent)
		return;

	if (dent->d_parent) {
		CHECK_PTR(dent->d_parent, fatal);
		dent->d_parent->d_child_count--;
	}
	dent->d_parent = parent;
	if (parent) {
		CHECK_PTR(parent, fatal);
		parent->d_child_count++;
	}
 fatal: ;
}

static
void _mars_order(struct mars_cookie *cookie, struct mars_dent *dent)
{
	struct mars_global *global = cookie->global;
	struct list_head *sorted_anchor;
	struct list_head *sorted_prev;
	struct list_head *hash_anchor;
	struct list_head *hash_try;
	struct list_head *hash_prev;
	struct list_head *tmp;

	CHECK_PTR(dent, fatal);
	/* Fuzzy hashing algorithm.
	 * Although based on external hashing, it produces an additional
	 * sorted list and allows for neighbour search.
	 + A description and an evaluation can be found at the
	 * University of Stattgart, Institut fuer Informatik
	 * (sorry, much is in German, produced in the 1990s)
	 */
	sorted_anchor = &global->dent_anchor;
	CHECK_PTR(sorted_anchor, fatal);
	hash_anchor = DENT_HASH_ANCHOR(global, dent->d_hash);
	CHECK_PTR(hash_anchor, fatal);

	sorted_prev = sorted_anchor;
	tmp = sorted_anchor->next;

	for (hash_try = hash_anchor->next; hash_try != hash_anchor; hash_try = hash_try->next) {
		struct mars_dent *hash_test = container_of(hash_try, struct mars_dent, dent_hash_link);
		int cmp;

		CHECK_PTR(hash_test, fatal);

		if (hash_test->d_unordered)
			break;
#ifdef CONFIG_MARS_DEBUG
		if (unlikely(hash_test->d_hash != dent->d_hash)) {
			MARS_ERR("bad target hash index %d\n", hash_test->d_hash);
			break;
		}
#endif

		cmp = dent_compare(hash_test, dent);
		if (!cmp) {
			mars_free_dent(global, dent);
			dent = hash_test;
			goto found;
		}
		if (cmp >= 0)
			break;

		tmp = &hash_test->dent_link;
		sorted_prev = tmp->prev;
		CHECK_PTR(sorted_prev, fatal);
	}

	while (tmp != sorted_anchor) {
		struct mars_dent *test = container_of(tmp, struct mars_dent, dent_link);
		int cmp;

		CHECK_PTR(test, fatal);

		if (test->d_unordered)
			break;

		cmp = dent_compare(test, dent);
		if (!cmp) {
			mars_free_dent(global, dent);
			dent = test;
			goto found;
		}
		// keep the list sorted. find the next smallest member.
		if (cmp > 0)
			break;

		for (;;) {
			struct list_head *hash_try;
			struct list_head *hash_try_anchor;
			unsigned int hash_try_index = test->d_hash;

#ifdef CONFIG_MARS_DEBUG
			if (unlikely(hash_try_index >= MARS_GLOBAL_HASH)) {
				MARS_ERR("bad hash index %d\n", hash_try_index);
				break;
			}
#endif

			hash_try_anchor =  DENT_HASH_ANCHOR(global, hash_try_index);
			CHECK_PTR(hash_try_anchor, fatal);
			hash_try = test->dent_hash_link.next;
			CHECK_PTR(hash_try, fatal);
			if (hash_try == hash_try_anchor ||
			    hash_try == tmp->next ||
			    hash_try == &test->dent_hash_link)
				break;

			test = container_of(hash_try,
					    struct mars_dent,
					    dent_hash_link);
			CHECK_PTR(test, fatal);
			if (test->d_unordered)
				break;
#ifdef CONFIG_MARS_DEBUG
			if (unlikely(test->d_hash != hash_try_index)) {
				MARS_ERR("bad target hash index %d\n", test->d_hash);
				break;
			}
#endif

			cmp = dent_compare(test, dent);
			if (!cmp) {
				mars_free_dent(global, dent);
				dent = test;
				goto found;
			}
			if (cmp >= 0)
				break;
			tmp = &test->dent_link;
			CHECK_PTR(tmp, fatal);
		}
		sorted_prev = tmp;
		tmp = tmp->next;
		CHECK_PTR(tmp, fatal);
	}

	/* not found: finish dent and insert into data stuctures */

	dent->d_unordered = false;
	list_add(&dent->dent_link, sorted_prev);

	hash_prev = hash_anchor;
	for (tmp = hash_anchor->next; tmp != hash_anchor; tmp = tmp->next) {
		struct mars_dent *test = container_of(tmp, struct mars_dent, dent_hash_link);
		int cmp;

		CHECK_PTR(test, fatal);
		cmp = dent_compare(test, dent);
		if (cmp >= 0)
			break;
		hash_prev = tmp;
	}
	list_add(&dent->dent_hash_link, hash_prev);

found:
	_reconnect_dent(cookie->parent, dent);
 fatal: ;
}

static inline
void _list_connect(struct list_head *a, struct list_head *b)
{
	a->next = b;
	b->prev = a;
}

static
void _mars_order_all(struct mars_cookie *cookie)
{
	LIST_HEAD(later_anchor);

	while (!list_empty(&cookie->tmp_anchor)) {
		struct list_head *tmp = cookie->tmp_anchor.next;
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		CHECK_PTR(dent, fatal);
		list_del_init(tmp);
		/* When some_ordered: only sort links spawning
		 * a .cl_forward action (with some unimportant exceptions).
		 * In addition, the alive and time links need to
		 * come last, for race avoidance.
		 * The rest needs not to be sorted, saving CPU.
		 */
		if (cookie->some_ordered &&
		    dent->d_class < 0 &&
		    !S_ISDIR(dent->new_stat.mode) &&
		    /* further sorted items */
		    strncmp(dent->d_name, "alive-", 6) &&
		    true) {
			get_inode(dent->d_path, dent, true);
			dent->d_unordered = true;
			cookie->global->nr_unordered++;
			/* time-* must be the very last items */
			if (strncmp(dent->d_name, "time-", 5))
				list_add(&dent->dent_link, &later_anchor);
			else
				list_add_tail(&dent->dent_link, &later_anchor);
			_reconnect_dent(NULL, dent);
			continue;
		}
		if (!cookie->some_ordered) {
			char *check;

			/* Do not add _new_ dents when deleted.
			 * Existing ones are treated in get_inode().
			 */
			check = mars_readlink(dent->d_path, NULL);
			if (check && !strcmp(check, MARS_DELETED_STR)) {
				brick_string_free(check);
				mars_free_dent(cookie->global, dent);
				continue;
			}
			brick_string_free(check);
		}
		cookie->global->nr_ordered++;
		get_inode(dent->d_path, dent, true);
		_mars_order(cookie, dent);
	}
	/* Append the whole unordered list.
	 * This is done on return from recursion, so searching
	 * remains possible.
	 */
	if (!list_empty(&later_anchor)) {
		struct list_head *a = cookie->global->dent_anchor.prev;
		struct list_head *b = later_anchor.next;
		struct list_head *c = later_anchor.prev;
		struct list_head *d = &cookie->global->dent_anchor;

		_list_connect(a, b);
		_list_connect(c, d);
	}
 fatal: ;
}

static int _mars_readdir(struct mars_cookie *cookie)
{
	struct file *f;
	struct address_space *mapping;
        mm_segment_t oldfs;
	loff_t dir_pos, old_dir_pos;
	int _loop_limit;
	int i;
	int status = 0;

	/* check for names to skip */
	for (i = 0; ; ) {
		const struct skip_info *check;

		check = &skips[i++];
		if (!check->name)
			break;
		if (!strncmp(cookie->path, check->name, check->len))
			goto done;
	}

	/* Performance optimization.
	 * Skip readdir() when not activated and no device-$host exists
	 */
	if (cookie->parent &&
	    cookie->parent->d_skip_fn) {
		cookie->parent->d_skip_fn(cookie->parent);
		if (cookie->parent->d_no_scan &&
		    !cookie->parent->d_running) {
			MARS_DBG("scan_skip '%s'\n", cookie->parent->d_path);
			goto done;
		}
	}

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        f = filp_open(cookie->path, O_DIRECTORY | O_RDONLY, 0);
        set_fs(oldfs);
	if (unlikely(IS_ERR(f))) {
		return PTR_ERR(f);
	}
	if ((mapping = f->f_mapping)) {
		mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));
	}

	cookie->global->nr_readdir++;

	_loop_limit = 1024 * 1024;
	dir_pos = f->f_pos;
	for (;;) {
//      remove_this
#ifdef MARS_HAS_ITERATE_DIR
		struct mars_dir_context buf = {
			.ctx.actor = mars_filler,
			.cookie = cookie,
		};

		cookie->hit = false;
		status = iterate_dir(f, &buf.ctx);
#else
		cookie->hit = false;
		status = vfs_readdir(f, mars_filler, cookie);
#endif
//      end_remove_this
		/* Check this first.
		 * We cannot continue upon inode lock contention.
		 */
		if (unlikely(status < 0)) {
			MARS_ERR("readdir() on path='%s' status=%d\n", cookie->path, status);
			/* Retry on the next invocation, but calm down any
			 * potential lock contention issues & sisters.
			 */
			brick_msleep(100);
			break;
		}
		/* Give up on EOF-like semantics */
		if (!cookie->hit)
			break;

		/* This should _never_ happen, but who knows what may
		 * actually happen on _defective_ file systems....
		 */
		if (unlikely(_loop_limit-- < 0)) {
			MARS_ERR("readdir() path='%s' ENDLESS LOOP, status=%d\n",
				 cookie->path, status);
			brick_msleep(100);
			break;
		}
		/* The old POSIX-like semantics was to run the loop
		 * until nothing was delivered anymore, which meant EOF.
		 * Since iterate_dir() is used in the kernel, the semantics
		 * of "hit" is/has somewhat changed (in detail), and maybe
		 * (less) subtly depending on the fs type.
		 * For maintainability over long periods, and over
		 * upstream kernel generations, we assume that EOF
		 * can be detected when nothing changes anymore
		 * at ->f_pos, and when ->f_pos is non-zero.
		 * Any filesystem ignoring ->f_pos is no longer
		 * supported via the old semantics, but assumed
		 * that a single iteration will _entirely_ work
		 * (until "classical" EOF).
		 * Consequence: in worst case, an unnecessary iteration
		 * _should_ run only twice.
		 * For maximum safety (e.g. flipping positions due to
		 * whatever reasons), _loop_limit acts as a safeguard.
		 * CHECK: can this be improved?
		 */
		old_dir_pos = dir_pos;
		dir_pos = f->f_pos;
		if (dir_pos == old_dir_pos || !dir_pos)
			break;

		brick_yield();
	}

	filp_close(f, NULL);

	_mars_order_all(cookie);

 done:
	return status;
}

static
bool dir_path_is_in(const char *path, const char *list)
{
	const char *pattern = path_make("|%s/", path);
	bool res;

	res = strstr(list, pattern) != NULL;
	brick_string_free(pattern);
	return res;
}

#define MARS_PREFIX_RESOURCE    "/mars/resource-"

static
bool has_subtree_prefix(const char *path)
{
	bool res;

	res = !strncmp(path,
		       MARS_PREFIX_RESOURCE,
		       sizeof(MARS_PREFIX_RESOURCE) - 1);
	return res;
}

static
const char *subtree_prefix(const char *path)
{
	char *copy = brick_strdup(path);
	char *tmp = copy;
	int count = 3;

	while (*tmp) {
		if (*tmp++ != '/')
			continue;
		if (--count > 0)
			continue;
		tmp[-1] = '\0';
		return copy;
	}
	brick_string_free(copy);
	return NULL;
}

static
int _op_scan(struct say_channel **say_channel,
	     struct mars_global *global,
	     const char *path_list,
	     int allocsize,
	     mars_dent_checker_fn checker,
	     int maxdepth,
	     bool use_subtree,
	     int version,
	     bool *found_dir,
	     bool has_dir_list,
	     bool some_ordered)
{
	struct list_head *tmp;
	int total_status = 0;

	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		int status;

		// treat any member only once during this invocation
		if (dent->d_version == version)
			continue;
		dent->d_version = version;

		if (say_channel)
			bind_to_dent(dent, say_channel);

		//MARS_IO("reading inode '%s'\n", dent->d_path);
		status = get_inode(dent->d_path, dent, some_ordered);
		total_status |= status;

		// mark gone dents for removal
		if (unlikely(status < 0) && list_empty(&dent->brick_list))
			dent->d_killme = true;

		/* Recurse into subdirectories.
		 * Insert either into the flat list, or create
		 * a new subtree.
		 */
		if (S_ISDIR(dent->new_stat.mode) &&
		    (maxdepth <= 0 ||
		     dent->d_depth <= maxdepth) &&
		    (!dent->d_no_scan ||
		     dent->d_running ||
		     dent->d_depth <= 1) &&
		    (!has_dir_list || 
		     dent->d_depth > 0 ||
		     dir_path_is_in(dent->d_path, path_list))) {
			struct mars_cookie sub_cookie = {
				.global = global,
				.checker = checker,
				.path = dent->d_path,
				.allocsize = allocsize,
				.check_parent = dent,
				.parent = some_ordered ? NULL : dent,
				.tmp_anchor = LIST_HEAD_INIT(sub_cookie.tmp_anchor),
				.depth = dent->d_depth + 1,
				.some_ordered = some_ordered,
			};

			if (say_channel && use_subtree && 
			    has_subtree_prefix(dent->d_path)) {
				if (!dent->d_subtree) {
					dent->d_subtree = alloc_mars_global();
				}
				sub_cookie.global = dent->d_subtree;
				sub_cookie.global->nr_readdir = 0;
				sub_cookie.global->nr_readitem = 0;
				sub_cookie.global->nr_ordered = 0;
				sub_cookie.global->nr_unordered = 0;
			}
			global->has_subtrees = true;
			*found_dir = true;
			status = _mars_readdir(&sub_cookie);
			total_status |= status;
			if (status < 0) {
				MARS_INF("forward: status %d on '%s'\n", status, dent->d_path);
			}
			if (dent->d_subtree)
				total_status |=
					_op_scan(NULL,
						 dent->d_subtree,
						 path_list,
						 allocsize, checker,
						 maxdepth, use_subtree,
						 version,
						 found_dir, has_dir_list,
						 false);
		}
	}
	return total_status;
}

static
int _op_forward(struct say_channel **say_channel,
		struct mars_global *global,
		mars_dent_worker_fn worker,
		void *buf,
		bool w_fl1, bool w_fl2)
{
	struct list_head *tmp;
	struct list_head *next;
	int total_status = 0;

	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.next, next = tmp->next; tmp != &global->dent_anchor; tmp = next, next = next->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		int status;

		if (dent->d_no_scan && !dent->d_running) {
			MARS_DBG("scan_skip '%s'\n", dent->d_path);
			continue;
		}

		up_read(&global->dent_mutex);

		brick_yield();

		if (say_channel)
			bind_to_dent(dent, say_channel);

		/* Caution: the order is important.
		 * First visit the parent, then descend into
		 * the subtree (when present).
		 */
		status = worker(buf, dent, w_fl1, w_fl2);
		total_status |= status;

		if (dent->d_subtree)
			total_status |=
				_op_forward(NULL,
					    dent->d_subtree,
					    worker, buf,
					    w_fl1, w_fl2);

		down_read(&global->dent_mutex);
	}
	up_read(&global->dent_mutex);
	return total_status;
}

static
int _op_backward(struct say_channel **say_channel,
		 struct mars_global *global,
		 mars_dent_worker_fn worker,
		 void *buf)
{
	struct list_head *tmp;
	struct list_head *next;
	int total_status = 0;

	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.prev, next = tmp->prev; tmp != &global->dent_anchor; tmp = next, next = next->prev) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		int status;

		if (dent->d_no_scan && !dent->d_running) {
			MARS_DBG("scan_skip '%s'\n", dent->d_path);
			continue;
		}

		up_read(&global->dent_mutex);

		brick_yield();

		if (say_channel)
			bind_to_dent(dent, say_channel);

		/* Caution: the order is important.
		 * When running backwards, we first need to
		 * descend into the subtree (when present)
		 * before visiting the parent.
		 */
		if (dent->d_subtree)
			total_status |=
				_op_backward(NULL,
					    dent->d_subtree,
					    worker, buf);

		status = worker(buf, dent, false, true);
		down_read(&global->dent_mutex);
		total_status |= status;
		if (status < 0) {
			MARS_INF("backwards: status %d on '%s'\n", status, dent->d_path);
		}
	}
	up_read(&global->dent_mutex);
	return total_status;
}

static
void _op_remove(struct say_channel **say_channel,
		struct mars_global *global)
{
	struct list_head *tmp;
	struct list_head *prev;

	down_write(&global->dent_mutex);
	for (tmp = global->dent_anchor.prev, prev = tmp->prev; tmp != &global->dent_anchor; tmp = prev, prev = prev->prev) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);

		if (dent->d_subtree)
			_op_remove(NULL, dent->d_subtree);

		if (!dent->d_killme)
			continue;
		if (dent->d_child_count)
			continue;
		if (atomic_read(&dent->d_count))
			continue;
		if (!list_empty(&dent->brick_list))
			continue;

		if (say_channel)
			bind_to_dent(dent, say_channel);

		MARS_DBG("killing dent '%s'\n", dent->d_path);
		list_del_init(&dent->dent_link);
		list_del_init(&dent->dent_hash_link);
		mars_free_dent(NULL, dent);
	}
	up_write(&global->dent_mutex);
}

/* Stripped-down version for peer metadata exchange
 */
int mars_get_dent_list(struct mars_global *global,
		   const char *path_list,
		   int allocsize,
		   mars_dent_checker_fn checker,
		   int maxdepth)
{
	static int version = 0;
	char *startname = brick_strdup(path_list);
	struct mars_cookie cookie = {
		.global = global,
		.checker = checker,
		.path = startname,
		.tmp_anchor = LIST_HEAD_INIT(cookie.tmp_anchor),
		.allocsize = allocsize,
		.depth = 0,
		.some_ordered = true,
	};
	struct say_channel *say_channel = NULL;
	char *ptr;
	int total_status;
	bool found_dir = false;
	bool has_dir_list = false;

	ptr = strchr(startname, '|');
	if (ptr) {
		*ptr = '\0';
		has_dir_list = true;
	}

	global->global_version = ++version;

	down_write(&global->dent_mutex);

	global->nr_readdir = 0;
	global->nr_readitem = 0;
	global->nr_ordered = 0;
	global->nr_unordered = 0;

	total_status = _mars_readdir(&cookie);

	total_status =
		_op_scan(&say_channel,
			 global,
			 path_list,
			 allocsize,
			 checker,
			 maxdepth,
			 false,
			 version,
			 &found_dir,
			 has_dir_list,
			 true);

	up_write(&global->dent_mutex);

	brick_string_free(startname);
	return total_status;
}

int mars_dent_work(struct mars_global *global,
		   char *path_list,
		   int allocsize,
		   mars_dent_checker_fn checker,
		   mars_dent_worker_fn worker,
		   void *buf,
		   int maxdepth,
		   bool use_subtree)
{
	static int version = 0;
	char *startname = brick_strdup(path_list);
	char *ptr;
	struct mars_cookie cookie = {
		.global = global,
		.checker = checker,
		.path = startname,
		.tmp_anchor = LIST_HEAD_INIT(cookie.tmp_anchor),
		.allocsize = allocsize,
		.depth = 0,
	};
	struct say_channel *say_channel = NULL;
	int rounds = 0;
	int total_status = 0;
	bool found_dir;
	bool has_dir_list = false;

	ptr = strchr(startname, '|');
	if (ptr) {
		*ptr = '\0';
		has_dir_list = true;
	}

	/* Initialize the flat dent list
	 */
	version++;
	global->global_version = version;
	total_status = _mars_readdir(&cookie);

	if (total_status || !worker) {
		goto done;
	}

	down_write(&global->dent_mutex);

	global->nr_readdir = 0;
	global->nr_readitem = 0;
	global->nr_ordered = 0;
	global->nr_unordered = 0;

restart:
	MARS_IO("at restart\n");
	found_dir = false;

	/* First, get all the inode information in a separate pass
	 * before starting work.
	 * The separate pass is necessary because some dents may
	 * forward-reference other dents, and it would be a pity if
	 * some inodes were not available or were outdated.
	 */
	total_status |=
		_op_scan(&say_channel,
			 global, path_list,
			 allocsize, checker,
			 maxdepth, use_subtree,
			 version,
			 &found_dir,
			 has_dir_list,
			 false);

	bind_to_dent(NULL, &say_channel);

	if (found_dir && ++rounds < 10) {
		brick_yield();
		goto restart;
	}

	up_write(&global->dent_mutex);

	/* Preparation pass.
	 * Here is a chance to mark some dents for removal
	 * (or other types of non-destructive operations)
	 */
	total_status |=
		_op_forward(&say_channel, global, worker, buf, true, false);

	bind_to_dent(NULL, &say_channel);

	/* Remove all dents marked for removal.
	 * Needs to be done in reverse order because later d_parent pointers may
	 * reference earlier list members.
	 */
	_op_remove(&say_channel, global);

	bind_to_dent(NULL, &say_channel);

	/* Forward pass.
	*/
	total_status |=
		_op_forward(&say_channel, global, worker, buf, false, false);

	/* Backward pass.
	*/
	total_status |=
		_op_backward(&say_channel, global, worker, buf);

	bind_to_dent(NULL, &say_channel);

done:
	brick_string_free(startname);
	MARS_IO("total_status = %d\n", total_status);
	return total_status;
}
EXPORT_SYMBOL_GPL(mars_dent_work);

static inline
struct mars_dent *_mars_find_dent(struct list_head *anchor, const char *path)
{
	struct mars_dent *res = NULL;
	struct list_head *tmp;

	for (tmp = anchor->next; tmp != anchor; tmp = tmp->next) {
		struct mars_dent *tmp_dent;

		tmp_dent = container_of(tmp, struct mars_dent, dent_hash_link);
		CHECK_PTR(tmp_dent, done);

		if (unlikely(!tmp_dent->d_path)) {
			MARS_ERR("dent %p has empty path\n", tmp_dent);
			continue;
		}
		if (!strcmp(tmp_dent->d_path, path)) {
			if (unlikely(tmp_dent->d_unordered))
				MARS_ERR("found unordered '%s'\n",
					 tmp_dent->d_path);
			res = tmp_dent;
			break;
		}
	}

 done:
	return res;
}

struct mars_dent *mars_find_dent(struct mars_global *global,
				 const char *path)
{
	struct list_head *hash_anchor;
	struct mars_dent *res = NULL;
	unsigned int hash;

	if (!global || !path)
		return NULL;

	if (global->has_subtrees && has_subtree_prefix(path)) {
		const char *prefix = subtree_prefix(path);

		if (prefix) {
			struct list_head *sub_hash_anchor;
			struct mars_dent *sub;
			unsigned int sub_hash;

			sub_hash = dent_hash(prefix, strlen(prefix));
			sub_hash_anchor = DENT_HASH_ANCHOR(global, sub_hash);
			down_read(&global->dent_mutex);
			sub = _mars_find_dent(sub_hash_anchor, prefix);
			if (sub && sub->d_subtree) {
				hash = dent_hash(path, strlen(path));
				hash_anchor = DENT_HASH_ANCHOR(sub->d_subtree, hash);
				down_read(&sub->d_subtree->dent_mutex);
				up_read(&global->dent_mutex);
				res = _mars_find_dent(hash_anchor, path);
				up_read(&sub->d_subtree->dent_mutex);
			} else {
				up_read(&global->dent_mutex);
				res = sub;
			}
			brick_string_free(prefix);
			return res;
		}
	}

	hash = dent_hash(path, strlen(path));
	hash_anchor = DENT_HASH_ANCHOR(global, hash);

	down_read(&global->dent_mutex);
	res = _mars_find_dent(hash_anchor, path);
	up_read(&global->dent_mutex);
	return res;
}

void mars_kill_dent(struct mars_global *global, struct mars_dent *dent)
{
	/* Only mark as killable.
	 * Removal from the lists is done at mars_free_dent_all().
	 */
	dent->d_killme = true;
	mars_kill_brick_all(global, &dent->brick_list, true);
}
EXPORT_SYMBOL_GPL(mars_kill_dent);

void mars_free_dent(struct mars_global *global, struct mars_dent *dent)
{
	int i;

	CHECK_PTR(dent, fatal);
	MARS_IO("%p path='%s'\n", dent, dent->d_path);
	mars_kill_dent(global, dent);

	CHECK_HEAD_EMPTY(&dent->dent_link);
	CHECK_HEAD_EMPTY(&dent->dent_hash_link);
	CHECK_HEAD_EMPTY(&dent->brick_list);

	if (dent->d_subtree) {
		mars_free_dent_all(dent->d_subtree);
		free_mars_global(dent->d_subtree);
	}

	if (dent->d_private) {
		if (dent->d_private_destruct) {
			dent->d_private_destruct(dent->d_private);
		}
		brick_mem_free(dent->d_private);
	}

	for (i = 0; i < MARS_ARGV_MAX; i++) {
		brick_string_free(dent->d_argv[i]);
	}
	brick_string_free(dent->d_args);
	brick_string_free(dent->d_name);
	brick_string_free(dent->d_rest);
	brick_string_free(dent->d_path);
	brick_string_free(dent->old_link);
	brick_string_free(dent->new_link);
	if (dent->d_parent) {
		CHECK_PTR(dent->d_parent, fatal);
		dent->d_parent->d_child_count--;
		dent->d_parent = NULL;
	}
	if (unlikely(dent->d_child_count)) {
		MARS_ERR("dent '%s' child_count=%d\n",
			 dent->d_path,
			 dent->d_child_count);
		goto fatal;
	}
	if (unlikely(atomic_read(&dent->d_count))) {
		MARS_ERR("dent '%s' d_count=%d\n",
			 dent->d_path,
			 atomic_read(&dent->d_count));
		goto fatal;
	}
	brick_mem_free(dent);
 fatal: ;
}
EXPORT_SYMBOL_GPL(mars_free_dent);

void mars_free_dent_all(struct mars_global *global)
{
	struct list_head *anchor = &global->dent_anchor;
	LIST_HEAD(tmp_list);

	/* Needs to be done in reverse order because later d_parent pointers may
	 * reference earlier list members.
	 */
	if (global) {
		down_write(&global->dent_mutex);
	}
	list_replace_init(anchor, &tmp_list);
	if (global)
		up_write(&global->dent_mutex);
	MARS_DBG("is_empty=%d\n", list_empty(&tmp_list));
	while (!list_empty(&tmp_list)) {
		struct mars_dent *dent;

		dent = container_of(tmp_list.prev, struct mars_dent, dent_link);
		CHECK_PTR(dent, fatal);
		list_del_init(&dent->dent_link);
		list_del_init(&dent->dent_hash_link);
		MARS_IO("freeing dent %p\n", dent);
		mars_free_dent(global, dent);
	}
 fatal: ;
}
EXPORT_SYMBOL_GPL(mars_free_dent_all);


/////////////////////////////////////////////////////////////////////

// low-level brick instantiation

int mars_connect(struct mars_input *a, struct mars_output *b)
{
	struct mars_brick *a_brick = a->brick;
	struct mars_global *a_global = a_brick->global;
	struct mars_brick *b_brick = b->brick;
	struct mars_global *b_global = b_brick->global;
	int status;

	if (a_global)
		down_write(&a_global->brick_mutex);
	if (b_global && b_global != a_global)
		down_write(&b_global->brick_mutex);

	status = generic_connect((void*)a, (void*)b);

	if (b_global && b_global != a_global)
		up_write(&b_global->brick_mutex);
	if (a_global)
		up_write(&a_global->brick_mutex);

	return status;
}

int mars_disconnect(struct mars_input *a)
{
	struct mars_brick *a_brick = a->brick;
	struct mars_global *a_global = a_brick->global;
	struct mars_output *b;
	int status = 0;

	if (a_global)
		down_write(&a_global->brick_mutex);

	b = a->connect;
	if (b) {
		struct mars_brick *b_brick = b->brick;
		struct mars_global *b_global = b_brick->global;

		if (b_global && b_global != a_global)
			down_write(&b_global->brick_mutex);

		status = generic_disconnect((void*)a);

		if (b_global && b_global != a_global)
			up_write(&b_global->brick_mutex);
	}

	if (a_global)
		up_write(&a_global->brick_mutex);

	return status;
}

struct mars_brick *mars_find_brick(struct mars_global *global, const void *brick_type, const char *path)
{
	struct list_head *tmp;

	if (!global || !path)
		return NULL;

	down_read(&global->brick_mutex);

	for (tmp = global->brick_anchor.next; tmp != &global->brick_anchor; tmp = tmp->next) {
		struct mars_brick *test = container_of(tmp, struct mars_brick, global_brick_link);
		if (!strcmp(test->brick_path, path)) {
			up_read(&global->brick_mutex);
			if (brick_type && test->type != brick_type) {
				MARS_ERR("bad brick type\n");
				return NULL;
			}
			return test;
		}
	}

	up_read(&global->brick_mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(mars_find_brick);

int mars_free_brick(struct mars_brick *brick)
{
	struct mars_global *global;
	int i;
	int count;
	int status;
	int sleeptime;
	int maxsleep;

	if (!brick) {
		MARS_ERR("bad brick parameter\n");
		status = -EINVAL;
		goto done;
	}

	if (!brick->power.force_off || !brick->power.led_off) {
		MARS_WRN("brick '%s' is not freeable\n", brick->brick_path);
		status = -ETXTBSY;
		goto done;
	}

	// first check whether the brick is in use somewhere
	for (i = 0; i < brick->type->max_outputs; i++) {
		struct mars_output *output = brick->outputs[i];
		if (output && output->nr_connected > 0) {
			MARS_WRN("brick '%s' not freeable, output %i is used\n", brick->brick_path, i);
			status = -EEXIST;
			goto done;
		}
	}

	// Should not happen, but workaround: wait until flying IO has vanished
	maxsleep = 20000;
	sleeptime = 1000;
	for (;;) {
		count = atomic_read(&brick->mref_object_layout.alloc_count);
		if (likely(!count)) {
			break;
		}
		if (maxsleep > 0) {
			MARS_WRN("memleak: brick '%s' has %d mrefs allocated (total = %d, maxsleep = %d)\n",
				 brick->brick_path, count,
				 atomic_read(&brick->mref_object_layout.total_alloc_count),
				 maxsleep);
		} else {
			MARS_ERR("MEMLEAK: brick '%s' has %d mrefs allocated (total = %d)\n", brick->brick_path, count, atomic_read(&brick->mref_object_layout.total_alloc_count));
#ifdef CONFIG_MARS_DEBUG
			dump_stack();
#endif
			break;
		}
		brick_msleep(sleeptime);
		maxsleep -= sleeptime;
	}

	MARS_DBG("===> freeing brick name = '%s' path = '%s'\n", brick->brick_name, brick->brick_path);

	global = brick->global;
	if (global) {
		down_write(&global->brick_mutex);
		list_del_init(&brick->global_brick_link);
		list_del_init(&brick->dent_brick_link);
		up_write(&global->brick_mutex);
	}

	for (i = 0; i < brick->type->max_inputs; i++) {
		struct mars_input *input = brick->inputs[i];
		if (input) {
			MARS_DBG("disconnecting input %i\n", i);
			mars_disconnect(input);
		}
	}

	MARS_DBG("deallocate name = '%s' path = '%s'\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
	brick_string_free(brick->brick_name);
	brick_string_free(brick->brick_path);

	status = generic_brick_exit_full((void*)brick);

	if (status >= 0) {
		brick_mem_free(brick);
		mars_trigger();
	} else {
		MARS_ERR("error freeing brick, status = %d\n", status);
	}

done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_free_brick);

struct mars_brick *mars_make_brick(struct mars_global *global, struct mars_dent *belongs, const void *_brick_type, const char *path, const char *_name)
{
	const char *name = brick_strdup(_name);
	const char *names[] = { name, NULL };
	const struct generic_brick_type *brick_type = _brick_type;
	const struct generic_input_type **input_types;
	const struct generic_output_type **output_types;
	struct mars_brick *res;
	int size;
	int i;
	int status;
	
	if (!name) {
		MARS_ERR("cannot allocate space for name\n");
		return NULL;
	}

	size = brick_type->brick_size +
		(brick_type->max_inputs + brick_type->max_outputs) * sizeof(void*);
	input_types = brick_type->default_input_types;
	for (i = 0; i < brick_type->max_inputs; i++) {
		const struct generic_input_type *type = *input_types++;
		if (unlikely(!type)) {
			MARS_ERR("input_type %d is missing\n", i);
			goto err_name;
		}
		if (unlikely(type->input_size <= 0)) {
			MARS_ERR("bad input_size at %d\n", i);
			goto err_name;
		}
		size += type->input_size;
	}
	output_types = brick_type->default_output_types;
	for (i = 0; i < brick_type->max_outputs; i++) {
		const struct generic_output_type *type = *output_types++;
		if (unlikely(!type)) {
			MARS_ERR("output_type %d is missing\n", i);
			goto err_name;
		}
		if (unlikely(type->output_size <= 0)) {
			MARS_ERR("bad output_size at %d\n", i);
			goto err_name;
		}
		size += type->output_size;
	}
	
	res = brick_zmem_alloc(size);
	if (!res) {
		MARS_ERR("cannot grab %d bytes for brick type '%s'\n", size, brick_type->type_name);
		goto err_name;
	}
	get_lamport(NULL, &res->create_stamp);
	res->global = global;
	INIT_LIST_HEAD(&res->dent_brick_link);
	res->brick_path = brick_strdup(path);
	if (!res->brick_path) {
		MARS_ERR("cannot grab memory for path '%s'\n", path);
		goto err_res;
	}

	status = generic_brick_init_full(res, size, brick_type, NULL, NULL, names);
	MARS_DBG("brick '%s' init '%s' '%s' (status=%d)\n", brick_type->type_name, path, name, status);
	if (status < 0) {
		MARS_ERR("cannot init brick %s\n", brick_type->type_name);
		goto err_path;
	}
	res->free = mars_free_brick;

	/* Immediately make it visible, regardless of internal state.
	 * Switching on / etc must be done separately.
	 */
	down_write(&global->brick_mutex);
	list_add(&res->global_brick_link, &global->brick_anchor);
	if (belongs) {
		list_add_tail(&res->dent_brick_link, &belongs->brick_list);
	}
	up_write(&global->brick_mutex);

	return res;

err_path:
	brick_string_free(res->brick_path);
err_res:
	brick_mem_free(res);
err_name:
	brick_string_free(name);
	return NULL;
}
EXPORT_SYMBOL_GPL(mars_make_brick);

int mars_kill_brick(struct mars_brick *brick)
{
	struct mars_global *global;
	int status = -EINVAL;

	CHECK_PTR(brick, done);
	global = brick->global;

	MARS_DBG("===> killing brick %s path = '%s' name = '%s'\n", brick->type ? SAFE_STR(brick->type->type_name) : "undef", SAFE_STR(brick->brick_path), SAFE_STR(brick->brick_name));

	if (unlikely(brick->nr_outputs > 0 && brick->outputs[0] && brick->outputs[0]->nr_connected)) {
		MARS_ERR("sorry, output is in use '%s'\n", SAFE_STR(brick->brick_path));
		goto done;
	}

	// start shutdown
	set_button_wait((void*)brick, false, true, 0);

	if (brick->power.led_off) {
		int max_inputs = 0;
		bool failed = false;
		int i;

		if (global) {
			down_write(&global->brick_mutex);
			list_del_init(&brick->global_brick_link);
			list_del_init(&brick->dent_brick_link);
			up_write(&global->brick_mutex);
		}

		if (likely(brick->type)) {
			max_inputs = brick->type->max_inputs;
		} else {
			MARS_ERR("uninitialized brick '%s' '%s'\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
		}

		MARS_DBG("---> freeing '%s' '%s'\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));

		if (brick->kill_ptr)
			*brick->kill_ptr = NULL;
		
		for (i = 0; i < max_inputs; i++) {
			struct mars_input *input = brick->inputs[i];
			if (!input)
				continue;
			status = mars_disconnect(input);
			if (unlikely(status < 0)) {
				failed = true;
				MARS_ERR("brick '%s' '%s' disconnect %d failed, status = %d\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path), i, status);
			}
		}
		if (failed)
			goto done;
		if (likely(brick->free)) {
			status = brick->free(brick);
			if (unlikely(status < 0)) {
				MARS_ERR("freeing '%s' '%s' failed, status = %d\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path), status);
				goto done;
			}
		} else {
			MARS_ERR("brick '%s' '%s' has no destructor\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
		}
		status = 0;
	} else {
		/* This may happen regularly when bricks are shut down in parallel */
		MARS_INF("brick '%s' '%s' is not off\n",
			 SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
		status = -EUCLEAN;
	}

done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_kill_brick);

int mars_kill_brick_all(struct mars_global *global, struct list_head *anchor, bool use_dent_link)
{
	int status = 0;
	if (!anchor || !anchor->next)
		goto done;
	if (global) {
		down_write(&global->brick_mutex);
	}
	while (!list_empty(anchor)) {
		struct list_head *tmp = anchor->next;
		struct mars_brick *brick;
		if (use_dent_link) {
			brick = container_of(tmp, struct mars_brick, dent_brick_link);
		} else {
			brick = container_of(tmp, struct mars_brick, global_brick_link);
		}
		list_del_init(tmp);
		if (global) {
			up_write(&global->brick_mutex);
		}
		status |= mars_kill_brick(brick);
		if (global) {
			down_write(&global->brick_mutex);
		}
	}
	if (global) {
		up_write(&global->brick_mutex);
	}
done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_kill_brick_all);

int mars_kill_brick_when_possible(struct mars_global *global,
				  const struct mars_brick_type *type_list[],
				  bool even_on)
{
	struct list_head *anchor = &global->brick_anchor;
	int return_status = 0;
	struct list_head *tmp;

restart:
	if (global) {
		down_write(&global->brick_mutex);
	}
	for (tmp = anchor->next; tmp != anchor; tmp = tmp->next) {
		struct mars_brick *brick;
		struct lamport_time now;
		int count;
		int status;

		brick = container_of(tmp, struct mars_brick, global_brick_link);

		// only kill marked bricks
		if (!brick->killme) {
			continue;
		}
		// only kill unconnected bricks
		if (brick->nr_outputs > 0 && brick->outputs[0] && brick->outputs[0]->nr_connected > 0) {
			continue;
		}
		if (!even_on && (brick->power.button || !brick->power.led_off)) {
			continue;
		}

		/* Only kill the right brick types
		 */
		if (type_list) {
			int index = 0;
			const struct mars_brick_type *this_type = type_list[index++];
			bool matches = false;

			while (this_type) {
				if (this_type == brick->type) {
					matches = true;
					break;
				}
				this_type = type_list[index++];
			}
			/* also kill any non-working bricks */
			if (!matches &&
			    (brick->power.button || !brick->power.led_off))
				continue;
		}

		// only kill bricks which have no resources allocated
		count = atomic_read(&brick->mref_object_layout.alloc_count);
		if (count > 0) {
			mars_trigger();
			continue;
		}

		/* only kill non-transient bricks */
		if (brick->power.button != brick->power.led_on ||
		    brick->power.button == brick->power.led_off) {
			if (!brick->kill_stamp.tv_sec) {
				get_real_lamport(&brick->kill_stamp);
				brick->kill_stamp.tv_sec += 10;
			}
		}
		/* Workaround FIXME:
		 * only kill bricks which have not been touched during the current mars_dent_work() round.
		 * some bricks like aio seem to have races between startup and termination of threads.
		 * disable this for stress-testing the allocation/deallocation logic.
		 * OTOH, frequently doing useless starts/stops is no good idea.
		 * CHECK: how to avoid too frequent switching by other means?
		 */
		if (!brick->kill_stamp.tv_sec) {
			get_real_lamport(&brick->kill_stamp);
			brick->kill_stamp.tv_sec += 3;
		}
		get_real_lamport(&now);
		if (lamport_time_compare(&now, &brick->kill_stamp) <= 0 &&
		    global &&
		    global->global_power.button) {
			mars_trigger();
			continue;
		}
		if (brick->kill_round++ < 1) {
			mars_trigger();
			continue;
		}

		/* start shutdown */
		mars_power_button(brick, false, true);

		/* wait until actually off */
		if (!brick->power.led_off) {
			mars_trigger();
			continue;
		}

		if (global) {
			up_write(&global->brick_mutex);
		}

		MARS_DBG("KILLING '%s' '%s'\n",
			 brick->brick_path, brick->brick_name);
		status = mars_kill_brick(brick);

		if (status >= 0)
			return_status++;

		/* The list may have changed during the open lock
		 * in unpredictable ways.
		 */
		goto restart;
	}
	if (global) {
		up_write(&global->brick_mutex);
	}
	return return_status;
}
EXPORT_SYMBOL_GPL(mars_kill_brick_when_possible);


/////////////////////////////////////////////////////////////////////

// mid-level brick instantiation (identity is based on path strings)

char *_vpath_make(int line, const char *fmt, va_list *args)
{
	va_list copy_args;
	char dummy[2];
	int len;
	char *res;

	memcpy(&copy_args, args, sizeof(copy_args));
	len = vsnprintf(dummy, sizeof(dummy), fmt, copy_args);
	len = _length_paranoia(len, line);
	res = _brick_string_alloc(len + 2, line);

	vsnprintf(res, len + 1, fmt, *args);

	return res;
}
EXPORT_SYMBOL_GPL(_vpath_make);

char *_path_make(int line, const char *fmt, ...)
{
	va_list args;
	char *res;
	va_start(args, fmt);
	res = _vpath_make(line, fmt, &args);
	va_end(args);
	return res;
}
EXPORT_SYMBOL_GPL(_path_make);

char *_backskip_replace(int line, const char *path, char delim, bool insert, const char *fmt, ...)
{
	int path_len = strlen(path);
	int fmt_len;
	int total_len;
	char *res;
	va_list args;
	int pos = path_len;
	int plus;
	char dummy[2];

	va_start(args, fmt);
	fmt_len = vsnprintf(dummy, sizeof(dummy), fmt, args);
	va_end(args);
	fmt_len = _length_paranoia(fmt_len, line);

	total_len = fmt_len + path_len;
	total_len = _length_paranoia(total_len, line);

	res = _brick_string_alloc(total_len + 2, line);

	while (pos > 0 && path[pos] != '/') {
		pos--;
	}
	if (delim != '/') {
		while (pos < path_len && path[pos] != delim) {
			pos++;
		}
	}
	memcpy(res, path, pos);

	va_start(args, fmt);
	plus = vscnprintf(res + pos, total_len - pos, fmt, args);
	va_end(args);

	if (insert) {
		strncpy(res + pos + plus, path + pos + 1, total_len - pos - plus);
	}
	return res;
}
EXPORT_SYMBOL_GPL(_backskip_replace);

struct mars_brick *path_find_brick(struct mars_global *global, const void *brick_type, const char *fmt, ...)
{
	va_list args;
	char *fullpath;
	struct mars_brick *res;

	va_start(args, fmt);
	fullpath = vpath_make(fmt, &args);
	va_end(args);

	if (!fullpath) {
		return NULL;
	}
	res = mars_find_brick(global, brick_type, fullpath);
	brick_string_free(fullpath);
	MARS_IO("search for '%s' found = %p\n", fullpath, res);
	return res;
}
EXPORT_SYMBOL_GPL(path_find_brick);

const struct generic_brick_type *_client_brick_type = NULL;
EXPORT_SYMBOL_GPL(_client_brick_type);
const struct generic_brick_type *_bio_brick_type = NULL;
EXPORT_SYMBOL_GPL(_bio_brick_type);
const struct generic_brick_type *_aio_brick_type = NULL;
EXPORT_SYMBOL_GPL(_aio_brick_type);
const struct generic_brick_type *_sio_brick_type = NULL;
EXPORT_SYMBOL_GPL(_sio_brick_type);

#define MAX_PREV_COUNT 8

struct mars_brick *make_brick_all(
	struct mars_global *global,
	struct mars_dent *belongs,
	int (*setup_fn)(struct mars_brick *brick, void *private),
	void *private,
	const char *new_name,
	const struct generic_brick_type *new_brick_type,
	const struct generic_brick_type *prev_brick_type[],
	int switch_override, // -1 = off, 0 = leave in current state, +1 = create when necessary, +2 = create + switch on
	const char *new_fmt,
	const char *prev_fmt[],
	int prev_count,
	...
	)
{
	va_list args;
	const char *new_path;
	char *_new_path = NULL;
	struct mars_brick *brick = NULL;
	char *paths[MAX_PREV_COUNT];
	struct mars_brick *prev[MAX_PREV_COUNT];
	bool switch_state;
	int i;
	int status;

	if (prev_count >= MAX_PREV_COUNT) {
		MARS_ERR("internal: prev_count=%d too high!\n",
			 prev_count);
		goto err;
	}

	// treat variable arguments
	va_start(args, prev_count);
	if (new_fmt) {
		new_path = _new_path = vpath_make(new_fmt, &args);
	} else {
		new_path = new_name;
	}
	for (i = 0; i < prev_count; i++) {
		paths[i] = vpath_make(prev_fmt[i], &args);
	}
	va_end(args);

	if (!new_path) {
		MARS_ERR("could not create new path\n");
		goto err;
	}

	// get old switch state
	brick = mars_find_brick(global, NULL, new_path);
	switch_state = false;
	if (brick) {
		switch_state = brick->power.button;
	}
	// override?
	if (switch_override > 1)
		switch_state = true;
	else if (switch_override < 0)
		switch_state = false;
	// even higher override
	if (global && !global->global_power.button) {
		switch_state = false;
	}

	// brick already existing?
	if (brick) {
		// just switch the power state
		MARS_DBG("found existing brick '%s'\n", new_path);
		// highest general override
		if (!switch_state &&
		    brick->power.button &&
		    mars_check_outputs(brick)) {
			MARS_DBG("KEEP '%s' override 0 -> 1\n", new_path);
			switch_state = true;
		}
		goto do_switch;
	}

	// brick not existing => check whether to create it
	if (switch_override < 1) { // don't create
		MARS_DBG("no need for brick '%s'\n", new_path);
		goto done;
	}
	MARS_DBG("make new brick '%s'\n", new_path);
	if (!new_name)
		new_name = new_path;

	MARS_DBG("----> new brick type = '%s' path = '%s' name = '%s'\n", new_brick_type->type_name, new_path, new_name);

	// get all predecessor bricks
	for (i = 0; i < prev_count; i++) {
		char *path = paths[i];

		if (!path) {
			MARS_ERR("could not build path %d\n", i);
			goto err;
		}

		prev[i] = mars_find_brick(global, NULL, path);

		if (!prev[i]) {
			MARS_WRN("prev brick '%s' does not exist\n", path);
			goto err;
		}
		MARS_DBG("------> predecessor %d path = '%s'\n", i, path);
		if (!prev[i]->power.led_on) {
			MARS_DBG("predecessor power is not on\n");
			if (!brick || !brick->power.button)
				switch_state = false;
		}
	}

	// some generic brick replacements (better performance / network functionality)
	brick = NULL;
	if ((new_brick_type == _bio_brick_type || new_brick_type == _aio_brick_type)
	   && _client_brick_type != NULL) {
		char *remote = strchr(new_name, '@');
		if (remote) {
			remote++;
			MARS_DBG("substitute by remote brick '%s' on peer '%s'\n", new_name, remote);
			
			brick = mars_make_brick(global, belongs, _client_brick_type, new_path, new_name);
			if (brick) {
				struct client_brick *_brick = (void*)brick;
				_brick->max_flying = 10000;
			}
		}
	}
	if (!brick && new_brick_type == _bio_brick_type && _aio_brick_type) {
		struct kstat test = {};
		int status = mars_stat(new_path, &test, false);
		if (SKIP_BIO || status < 0 || !S_ISBLK(test.mode)) {
			new_brick_type = _aio_brick_type;
			MARS_DBG("substitute bio by aio\n");
		}
	}
#ifndef ENABLE_MARS_AIO
	if (!brick && new_brick_type == _aio_brick_type && _sio_brick_type) {
		new_brick_type = _sio_brick_type;
		MARS_DBG("substitute aio by sio\n");
	}
#endif

	// create it...
	if (!brick)
		brick = mars_make_brick(global, belongs, new_brick_type, new_path, new_name);
	if (unlikely(!brick)) {
		MARS_ERR("creation failed '%s' '%s'\n", new_path, new_name);
		goto err;
	}
	if (unlikely(brick->nr_inputs < prev_count)) {
		MARS_ERR("'%s' wrong number of arguments: %d < %d\n", new_path, brick->nr_inputs, prev_count);
		goto err;
	}

	// connect the wires
	for (i = 0; i < prev_count; i++) {
		int status;
		status = mars_connect(brick->inputs[i], prev[i]->outputs[0]);
		if (unlikely(status < 0)) {
			MARS_ERR("'%s' '%s' cannot connect input %d\n", new_path, new_name, i);
			goto err;
		}
	}

do_switch:
	// call setup function
	if (setup_fn) {
		int setup_status = setup_fn(brick, private);
		if (setup_status <= 0) {
			switch_state = 0;
		}
	}

	// switch on/off (may fail silently, but responsibility is at the workers)

	status = mars_power_button((void *)brick, switch_state, false);

	/* retry when a stray symlink during O_NOFOLLOW was the reason */
	if (status == -ELOOP && switch_state) {
		mars_unlink(new_path);
		status = mars_power_button((void *)brick, switch_state, false);
	}
	MARS_DBG("switch '%s' to %d status = %d\n", new_path, switch_state, status);
	goto done;

err:
	if (brick) {
		mars_kill_brick(brick);
	}
	brick = NULL;
done:
	for (i = 0; i < prev_count; i++) {
		brick_string_free(paths[i]);
	}
	brick_string_free(_new_path);

	return brick;
}
EXPORT_SYMBOL_GPL(make_brick_all);

/////////////////////////////////////////////////////////////////////////

// generic symlink updates

void update_client_links(struct client_brick *brick)
{
	char val[8];
	const char *name;

	name = backskip_replace(brick->brick_path, '/', true, "/local-%s/connection-", my_id());
	if (unlikely(!name))
		return; // silently

	sprintf(val, "%d", brick->connection_state - 1);
	ordered_symlink(val, name, NULL);

	brick_string_free(name);
}

/////////////////////////////////////////////////////////////////////////

// statistics

int global_show_statist =
#ifdef CONFIG_MARS_DEBUG_DEFAULT
	1;
#else
	0;
#endif
EXPORT_SYMBOL_GPL(global_show_statist);

int global_show_connections =
#ifdef CONFIG_MARS_SHOW_CONNECTIONS
	1;
#else
	0;
#endif
EXPORT_SYMBOL_GPL(global_show_connections);

static
void _show_one(struct mars_brick *test, int *brick_count)
{
	int i;
	if (*brick_count) {
		MARS_STAT("---------\n");
	}
	MARS_STAT("BRICK type = %s path = '%s' name = '%s' "
		  "create_stamp = %lld.%09ld "
		  "size_hint=%d "
		  "mrefs_alloc = %d "
		  "mrefs_apsect_alloc = %d "
		  "total_mrefs_alloc = %d "
		  "total_mrefs_aspects = %d "
		  "killme = %d "
		  "button = %d force_off = %d off = %d on = %d\n",
		  SAFE_STR(test->type->type_name),
		  SAFE_STR(test->brick_path),
		  SAFE_STR(test->brick_name),
		  (s64)test->create_stamp.tv_sec, test->create_stamp.tv_nsec,
		  test->mref_object_layout.size_hint,
		  atomic_read(&test->mref_object_layout.alloc_count),
		  atomic_read(&test->mref_object_layout.aspect_count),
		  atomic_read(&test->mref_object_layout.total_alloc_count),
		  atomic_read(&test->mref_object_layout.total_aspect_count),
		  test->killme,
		  test->power.button,
		  test->power.force_off,
		  test->power.led_off,
		  test->power.led_on);
	(*brick_count)++;
	if (test->ops && test->ops->brick_statistics) {
		char *info = test->ops->brick_statistics(test, 0);
		if (info) {
			MARS_STAT("  %s", info);
			brick_string_free(info);
		}
	}
	for (i = 0; i < test->type->max_inputs; i++) {
		struct mars_input *input = test->inputs[i];
		struct mars_output *output = input ? input->connect : NULL;
		if (output) {
			MARS_STAT("    input %d connected with %s path = '%s' name = '%s'\n", i, SAFE_STR(output->brick->type->type_name), SAFE_STR(output->brick->brick_path), SAFE_STR(output->brick->brick_name));
		} else {
			MARS_STAT("    input %d not connected\n", i);
		}
	}
	for (i = 0; i < test->type->max_outputs; i++) {
		struct mars_output *output = test->outputs[i];
		if (output) {
			MARS_STAT("    output %d nr_connected = %d\n", i, output->nr_connected);
		}
	}
}

static
void _show_dent_list(struct mars_global *global, int *count)
{
	struct list_head *tmp;
	int flat_count = 0;
	int sub_count = 0;

	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent;
		struct list_head *sub;

		dent = container_of(tmp, struct mars_dent, dent_link);
		MARS_STAT("dent %d%d %d '%s' '%s' stamp=%lld.%09ld\n",
			  dent->d_no_scan,
			  dent->d_running,
			  dent->d_class,
			  SAFE_STR(dent->d_path),
			  SAFE_STR(dent->new_link),
			  (s64)dent->new_stat.mtime.tv_sec, dent->new_stat.mtime.tv_nsec);
		(*count)++;
		for (sub = dent->brick_list.next; sub != &dent->brick_list; sub = sub->next) {
			struct mars_brick *test;
			test = container_of(sub, struct mars_brick, dent_brick_link);
			MARS_STAT("  owner of brick '%s'\n", SAFE_STR(test->brick_path));
		}
		if (dent->d_subtree) {
			_show_dent_list(dent->d_subtree, count);
			sub_count++;
		} else {
			flat_count++;
		}
	}
	MARS_STAT("flat_count=%d sub_count=%d\n", flat_count, sub_count);
	MARS_STAT("nr_readdir=%d nr_readitem=%d nr_ordered=%d nr_unordered=%d\n",
		  global->nr_readdir,
		  global->nr_readitem,
		  global->nr_ordered,
		  global->nr_unordered);
	up_read(&global->dent_mutex);
}

void show_statistics(struct mars_global *global, const char *class)
{
	struct list_head *tmp;
	int dent_count = 0;
	int brick_count = 0;

	// update all connection state symlinks
	if (global_show_connections) {
		down_read(&global->brick_mutex);
		for (tmp = global->brick_anchor.next; tmp != &global->brick_anchor; tmp = tmp->next) {
			struct mars_brick *test;
			test = container_of(tmp, struct mars_brick, global_brick_link);
			if (test->type == (void*)&client_brick_type) {
				update_client_links((void*)test);
			}
		}
		up_read(&global->brick_mutex);
	}

	if (!global_show_statist)
		return; // silently
	
	brick_mem_statistics(false);

	down_read(&global->brick_mutex);
	MARS_STAT("================================== %s bricks:\n", class);
	for (tmp = global->brick_anchor.next; tmp != &global->brick_anchor; tmp = tmp->next) {
		struct mars_brick *test;

		test = container_of(tmp, struct mars_brick, global_brick_link);
		_show_one(test, &brick_count);
	}
	up_read(&global->brick_mutex);
	
	MARS_STAT("================================== %s dents:\n", class);
	_show_dent_list(global, &dent_count);
	MARS_STAT("==================== %s STATISTICS: %d dents, %d bricks, %lld KB free\n", class, dent_count, brick_count, global_remaining_space);
}
EXPORT_SYMBOL_GPL(show_statistics);

/////////////////////////////////////////////////////////////////////

// init stuff

int __init init_sy(void)
{
	MARS_INF("init_sy()\n");
	return 0;
}

void exit_sy(void)
{
	MARS_INF("exit_sy()\n");
}
