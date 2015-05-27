#ifndef _PROVISIONARY_WRAPPER
#define _PROVISIONARY_WRAPPER

int _provisionary_wrapper_to_vfs_symlink(const char __user *oldname,
					 const char __user *newname,
					 struct timespec *mtime);

int _provisionary_wrapper_to_vfs_mkdir(const char __user *pathname,
				       int mode);

int _provisionary_wrapper_to_vfs_rename(const char __user *oldname,
					const char __user *newname);

int _provisionary_wrapper_to_vfs_unlink(const char __user *pathname);

#endif
