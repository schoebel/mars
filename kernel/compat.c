// SPDX-License-Identifier: GPL-2.0-or-later
/* Kernel-buffer VFS operations for Linux 7.2 and later. */
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/delayed_call.h>
#include "compat.h"

#ifdef MARS_MODERN_KERNEL
int mars_path_stat(const char *name, struct kstat *stat, bool follow)
{
	struct path path;
	int err = mars_kern_path(name, follow ? LOOKUP_FOLLOW : 0, &path);

	if (err)
		return err;
	err = vfs_getattr(&path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	path_put(&path);
	return err;
}

int mars_path_readlink(struct dentry *dentry, char *buf, int len)
{
	DEFINE_DELAYED_CALL(done);
	const char *link = vfs_get_link(dentry, &done);
	int result;

	if (IS_ERR(link))
		return PTR_ERR(link);
	result = strnlen(link, len);
	memcpy(buf, link, result);
	do_delayed_call(&done);
	return result;
}

int _compat_symlink(const char *target, const char *name,
		    struct lamport_time *mtime)
{
	struct path path;
	struct dentry *dentry;
	int err;

#ifdef scoped_with_init_fs
	CLASS(__override_init_fs, init_fs)();
#endif
	dentry = start_creating_path(AT_FDCWD, name, &path, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	err = vfs_symlink(mnt_idmap(path.mnt), d_inode(path.dentry),
			  dentry, target, NULL);
	if (!err && mtime) {
		struct iattr attr = {
			.ia_valid = ATTR_MTIME | ATTR_MTIME_SET | ATTR_TIMES_SET,
			.ia_mtime = *mtime,
		};

		inode_lock(d_inode(dentry));
		err = notify_change(mnt_idmap(path.mnt), dentry, &attr, NULL);
		inode_unlock(d_inode(dentry));
	}
	end_creating_path(&path, dentry);
	return err;
}

int _compat_mkdir(const char *name, int mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

#ifdef scoped_with_init_fs
	CLASS(__override_init_fs, init_fs)();
#endif
	dentry = start_creating_path(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	dentry = vfs_mkdir(mnt_idmap(path.mnt), d_inode(path.dentry),
			    dentry, mode, NULL);
	err = IS_ERR(dentry) ? PTR_ERR(dentry) : 0;
	end_creating_path(&path, dentry);
	return err;
}

/* MARS metadata paths are absolute and have a nonempty final component. */
static int mars_parent_path(const char *name, struct path *parent,
			    struct qstr *last)
{
	const char *slash = strrchr(name, '/');
	char *dirname;
	int err;

	if (name[0] != '/' || !slash || !slash[1])
		return -EINVAL;
	last->name = slash + 1;
	last->len = strlen(slash + 1);
	last->hash = 0;
	dirname = kstrndup(name, slash == name ? 1 : slash - name, GFP_NOFS);
	if (!dirname)
		return -ENOMEM;
	err = mars_kern_path(dirname, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, parent);
	kfree(dirname);
	return err;
}

int _compat_unlink(const char *name)
{
	struct path path;
	struct qstr last;
	struct dentry *dentry;
	int err = mars_parent_path(name, &path, &last);

	if (err)
		return err;
	err = mnt_want_write(path.mnt);
	if (err)
		goto out;
	dentry = start_removing(mnt_idmap(path.mnt), path.dentry, &last);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
	} else {
		err = vfs_unlink(mnt_idmap(path.mnt), d_inode(path.dentry),
				 dentry, NULL);
		end_removing(dentry);
	}
	mnt_drop_write(path.mnt);
out:
	path_put(&path);
	return err;
}

int _compat_rename(const char *oldname, const char *newname)
{
	struct path oldpath, newpath;
	struct qstr oldlast, newlast;
	struct renamedata rd = {};
	int err = mars_parent_path(oldname, &oldpath, &oldlast);

	if (err)
		return err;
	err = mars_parent_path(newname, &newpath, &newlast);
	if (err)
		goto out_old;
	err = -EXDEV;
	if (oldpath.mnt != newpath.mnt)
		goto out_new;
	err = mnt_want_write(oldpath.mnt);
	if (err)
		goto out_new;
	rd.mnt_idmap = mnt_idmap(oldpath.mnt);
	rd.old_parent = oldpath.dentry;
	rd.new_parent = newpath.dentry;
	err = start_renaming(&rd, 0, &oldlast, &newlast);
	if (!err) {
		err = vfs_rename(&rd);
		end_renaming(&rd);
	}
	mnt_drop_write(oldpath.mnt);
out_new:
	path_put(&newpath);
out_old:
	path_put(&oldpath);
	return err;
}
#endif
