// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

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
#include <linux/utsname.h>

#include "strategy.h"

#include "../mars_client.h"

#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/kthread.h>
#include <linux/statfs.h>

#define SKIP_BIO false

/////////////////////////////////////////////////////////////////////

// meta descriptions

const struct meta mars_kstat_meta[] = {
	META_INI(ino, struct kstat, FIELD_INT),
	META_INI(mode, struct kstat, FIELD_INT),
	META_INI(size, struct kstat, FIELD_INT),
	META_INI_SUB(atime, struct kstat, mars_timespec_meta),
	META_INI_SUB(mtime, struct kstat, mars_timespec_meta),
	META_INI_SUB(ctime, struct kstat, mars_timespec_meta),
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

int mars_stat(const char *path, struct kstat *stat, bool use_lstat)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(get_ds());
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

int mars_mkdir(const char *path)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(get_ds());
	status = sys_mkdir(path, 0700);
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_mkdir);

int mars_rmdir(const char *path)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(get_ds());
	status = sys_rmdir(path);
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_rmdir);

int mars_unlink(const char *path)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(get_ds());
	status = sys_unlink(path);
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_unlink);

int mars_symlink(const char *oldpath, const char *newpath, const struct timespec *stamp, uid_t uid)
{
	char *tmp = backskip_replace(newpath, '/', true, "/.tmp-"); 
	mm_segment_t oldfs;
	struct kstat stat = {};
	struct timespec times[2];
	int status = -ENOMEM;
	
	if (unlikely(!tmp))
		goto done;

	if (stamp)
		memcpy(&times[0], stamp, sizeof(times[0]));
	else
		get_lamport(&times[0]);
	
	oldfs = get_fs();
	set_fs(get_ds());
	/* Some filesystems have only full second resolution.
	 * Thus it may happen that the new timestamp is not
	 * truly moving forward when called twice shortly.
	 * This is a _workaround_, to be replaced by a better
	 * method somewhen.
	 */
	status = vfs_lstat((char*)newpath, &stat);
	if (status >= 0 &&
	    !stamp &&
	    !stat.mtime.tv_nsec &&
	    times[0].tv_sec == stat.mtime.tv_sec) {
		MARS_DBG("workaround timestamp tv_sec=%ld\n", stat.mtime.tv_sec);
		times[0].tv_sec = stat.mtime.tv_sec + 1;
		/* Setting tv_nsec to 1 prevents from unnecessarily reentering
		 * this workaround again if accidentally the original tv_nsec
		 * had been 0 or if the workaround had been triggered.
		 */
		times[0].tv_nsec = 1;
	}

	(void)sys_unlink(tmp);

	status = sys_symlink(oldpath, tmp);

	if (status >= 0) {
		sys_lchown(tmp, uid, 0);
		memcpy(&times[1], &times[0], sizeof(struct timespec));
		status = do_utimes(AT_FDCWD, tmp, times, AT_SYMLINK_NOFOLLOW);
	}

	if (status >= 0) {
		set_lamport(&times[0]);
		status = mars_rename(tmp, newpath);
	}
	set_fs(oldfs);
	brick_string_free(tmp);

done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_symlink);

char *mars_readlink(const char *newpath)
{
	char *res = NULL;
	struct path path = {};
	mm_segment_t oldfs;
	struct inode *inode;
	int len;
	int status = -ENOMEM;

	oldfs = get_fs();
	set_fs(get_ds());

	status = user_path_at(AT_FDCWD, newpath, 0, &path);
	if (unlikely(status < 0)) {
		MARS_DBG("link '%s' does not exist, status = %d\n", newpath, status);
		goto done_fs;
	}

	inode = path.dentry->d_inode;
	if (unlikely(!inode || !S_ISLNK(inode->i_mode))) {
		MARS_ERR("link '%s' has invalid inode\n", newpath);
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

	status = inode->i_op->readlink(path.dentry, res, len + 1);
	if (unlikely(status < 0)) {
		MARS_ERR("cannot read link '%s', status = %d\n", newpath, status);
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
	set_fs(get_ds());
	status = sys_rename(oldpath, newpath);
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_rename);

int mars_chmod(const char *path, mode_t mode)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(get_ds());
	status = sys_chmod(path, mode);
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_chmod);

int mars_lchown(const char *path, uid_t uid)
{
	mm_segment_t oldfs;
	int status;
	
	oldfs = get_fs();
	set_fs(get_ds());
	status = sys_lchown(path, uid, 0);
	set_fs(oldfs);

	return status;
}
EXPORT_SYMBOL_GPL(mars_lchown);

loff_t _compute_space(struct kstatfs *kstatfs, loff_t raw_val)
{
	int fsize = kstatfs->f_frsize;
	if (fsize <= 0)
		fsize = kstatfs->f_bsize;

	MARS_INF("fsize = %d raw_val = %lld\n", fsize, raw_val);
	// illegal values? cannot do anything....
	if (fsize <= 0)
		return 0;

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
	set_fs(get_ds());

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
			if (test->d_use_channel && test->d_path) {
				dent->d_say_channel = make_channel(test->d_path, true);
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
}
EXPORT_SYMBOL_GPL(bind_to_dent);

//////////////////////////////////////////////////////////////

// infrastructure

struct mars_global *mars_global = NULL;
EXPORT_SYMBOL_GPL(mars_global);

static
void __mars_trigger(void)
{
	if (mars_global) {
		mars_global->main_trigger = true;
		wake_up_interruptible_all(&mars_global->main_event);
	}
}

bool mars_check_inputs(struct mars_brick *brick)
{
	int max_inputs;
	int i;
	if (likely(brick->type)) {
		max_inputs = brick->type->max_inputs;
	} else {
		MARS_ERR("uninitialized brick '%s' '%s'\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
		return true;
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
		if (prev_brick->power.led_on)
			continue;
	done:
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(mars_check_inputs);

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
EXPORT_SYMBOL_GPL(mars_check_outputs);

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
			if (unlikely(mars_check_inputs(brick))) {
				MARS_ERR("CANNOT SWITCH ON: brick '%s' '%s' has a turned-off predecessor\n", brick->brick_name, brick->brick_path);
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
				MARS_ERR("CANNOT SWITCH OFF: brick '%s' '%s' has a successor\n", brick->brick_name, brick->brick_path);
				goto done;
			}
		}

		MARS_DBG("brick '%s' '%s' type '%s' power button %d -> %d\n", brick->brick_name, brick->brick_path, brick->type->type_name, oldval, val);

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

	if (val != oldval) {
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
	struct mars_dent *parent;
	int allocsize;
	int depth;
};

static
int get_inode(char *newpath, struct mars_dent *dent)
{
	mm_segment_t oldfs;
	int status;
	struct kstat tmp = {};

	oldfs = get_fs();
	set_fs(get_ds());

	status = vfs_lstat(newpath, &tmp);
	if (status < 0) {
		MARS_WRN("cannot stat '%s', status = %d\n", newpath, status);
		goto done;
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

                inode = path.dentry->d_inode;

		status = -ENOMEM;
		link = brick_string_alloc(len + 2);
		MARS_IO("len = %d\n", len);
		status = inode->i_op->readlink(path.dentry, link, len + 1);
		link[len] = '\0';
		if (status < 0 ||
		    (dent->new_link && !strncmp(dent->new_link, link, len))) {
			brick_string_free(link);
		} else {
			MARS_IO("symlink '%s' -> '%s' (%s) status = %d\n", newpath, link, dent->new_link ? dent->new_link : "", status);
			brick_string_free(dent->old_link);
			dent->old_link = dent->new_link;
			dent->new_link = link;
		}
		path_put(&path);
	}

	if (dent->new_link)
		MARS_IO("symlink '%s'\n", dent->new_link);

 done:
	set_fs(oldfs);
	return status;
}

static
int mars_filler(void *__buf, const char *name, int namlen, loff_t offset,
		u64 ino, unsigned int d_type)
{
	struct mars_cookie *cookie = __buf;
	struct mars_global *global = cookie->global;
	struct list_head *anchor = &global->dent_anchor;
	struct mars_dent *dent;
	struct list_head *tmp;
	struct mars_dent *best = NULL;
	char *newpath;
	int prefix = 0;
	int pathlen;
	int class;
	int serial = 0;
	bool use_channel = false;

	MARS_IO("ino = %llu len = %d offset = %lld type = %u\n", ino, namlen, offset, d_type);

	if (name[0] == '.') {
		return 0;
	}

	class = cookie->checker(cookie->parent, name, namlen, d_type, &prefix, &serial, &use_channel);
	if (class < 0)
		return 0;

	pathlen = strlen(cookie->path);
	newpath = brick_string_alloc(pathlen + namlen + 2);
	if (unlikely(!newpath))
		goto err_mem0;
	memcpy(newpath, cookie->path, pathlen);
	newpath[pathlen++] = '/';
	memcpy(newpath + pathlen, name, namlen);
	pathlen += namlen;
	newpath[pathlen] = '\0';

	MARS_IO("path = '%s'\n", newpath);

	for (tmp = anchor->next; tmp != anchor; tmp = tmp->next) {
		int cmp;
		dent = container_of(tmp, struct mars_dent, dent_link);
		cmp = strcmp(dent->d_path, newpath);
		if (!cmp) {
			goto found;
		}
		// keep the list sorted. find the next smallest member.
		if ((dent->d_class < class ||
		    (dent->d_class == class &&
		     (dent->d_serial < serial ||
		      (dent->d_serial == serial &&
		       cmp < 0))))
		   &&
		   (!best ||
		    best->d_class < dent->d_class ||
		    (best->d_class == dent->d_class &&
		     (best->d_serial < dent->d_serial ||
		      (best->d_serial == dent->d_serial &&
		       strcmp(best->d_path, dent->d_path) < 0))))) {
			best = dent;
		}
	}

	dent = brick_zmem_alloc(cookie->allocsize);
	if (unlikely(!dent))
		goto err_mem1;

	dent->d_name = brick_string_alloc(namlen + 1);
	if (unlikely(!dent->d_name))
		goto err_mem2;
	memcpy(dent->d_name, name, namlen);
	dent->d_name[namlen] = '\0';
	dent->d_rest = brick_strdup(dent->d_name + prefix);
	if (unlikely(!dent->d_rest))
		goto err_mem3;

	dent->d_path = newpath;
	newpath = NULL;

	INIT_LIST_HEAD(&dent->brick_list);

	if (best) {
		list_add(&dent->dent_link, &best->dent_link);
	} else {
		list_add_tail(&dent->dent_link, anchor);
	}

found:
	dent->d_type = d_type;
	dent->d_class = class;
	dent->d_serial = serial;
	if (dent->d_parent)
		dent->d_parent->d_child_count--;
	dent->d_parent = cookie->parent;
	if (dent->d_parent)
		dent->d_parent->d_child_count++;
	dent->d_depth = cookie->depth;
	dent->d_global = global;
	dent->d_killme = false;
	dent->d_use_channel = use_channel;
	brick_string_free(newpath);
	return 0;

err_mem3:
	brick_mem_free(dent->d_name);
err_mem2:
	brick_mem_free(dent);
err_mem1:
	brick_string_free(newpath);
err_mem0:
	return -ENOMEM;
}

static int _mars_readdir(struct mars_cookie *cookie)
{
	struct file *f;
	struct address_space *mapping;
        mm_segment_t oldfs;
	int status = 0;

        oldfs = get_fs();
        set_fs(get_ds());
        f = filp_open(cookie->path, O_DIRECTORY | O_RDONLY, 0);
        set_fs(oldfs);
	if (unlikely(IS_ERR(f))) {
		return PTR_ERR(f);
	}
	if ((mapping = f->f_mapping)) {
		mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));
	}

	for (;;) {
		status = vfs_readdir(f, mars_filler, cookie);
		MARS_IO("vfs_readdir() status = %d\n", status);
		if (status <= 0)
			break;
	}

	filp_close(f, NULL);
	return status;
}

int mars_dent_work(struct mars_global *global, char *dirname, int allocsize, mars_dent_checker_fn checker, mars_dent_worker_fn worker, void *buf, int maxdepth)
{
	static int version = 0;
	struct mars_cookie cookie = {
		.global = global,
		.checker = checker,
		.path = dirname,
		.parent = NULL,
		.allocsize = allocsize,
		.depth = 0,
	};
	struct say_channel *say_channel = NULL;
	struct list_head *tmp;
	struct list_head *next;
	int rounds = 0;
	int status;
	int total_status = 0;
	bool found_dir;

	/* Initialize the flat dent list
	 */
	version++;
	global->global_version = version;
	total_status = _mars_readdir(&cookie);

	if (total_status || !worker) {
		goto done;
	}

	down_write(&global->dent_mutex);

restart:
	MARS_IO("at restart\n");
	found_dir = false;

	/* First, get all the inode information in a separate pass
	 * before starting work.
	 * The separate pass is necessary because some dents may
	 * forward-reference other dents, and it would be a pity if
	 * some inodes were not available or were outdated.
	 */
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		// treat any member only once during this invocation
		if (dent->d_version == version)
			continue;
		dent->d_version = version;

		bind_to_dent(dent, &say_channel);

		//MARS_IO("reading inode '%s'\n", dent->d_path);
		status = get_inode(dent->d_path, dent);
		total_status |= status;

		// recurse into subdirectories by inserting into the flat list
		if (S_ISDIR(dent->new_stat.mode) && dent->d_depth <= maxdepth) {
			struct mars_cookie sub_cookie = {
				.global = global,
				.checker = checker,
				.path = dent->d_path,
				.allocsize = allocsize,
				.parent = dent,
				.depth = dent->d_depth + 1,
			};
			found_dir = true;
			status = _mars_readdir(&sub_cookie);
			total_status |= status;
			if (status < 0) {
				MARS_INF("forward: status %d on '%s'\n", status, dent->d_path);
			}
		}
	}
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
	down_read(&global->dent_mutex);
	MARS_IO("prep pass\n");
	for (tmp = global->dent_anchor.next, next = tmp->next; tmp != &global->dent_anchor; tmp = next, next = next->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);

		up_read(&global->dent_mutex);

		brick_yield();

		bind_to_dent(dent, &say_channel);

		//MARS_IO("forward prepare '%s'\n", dent->d_path);
		status = worker(buf, dent, true, false);
		if (status) {
			//MARS_IO("forward treat '%s' status = %d\n", dent->d_path, status);
		}
		down_read(&global->dent_mutex);
		total_status |= status;
	}
	up_read(&global->dent_mutex);

	bind_to_dent(NULL, &say_channel);

	/* Remove all dents marked for removal.
	 */
	down_write(&global->dent_mutex);
	MARS_IO("removal pass\n");
	for (tmp = global->dent_anchor.next, next = tmp->next; tmp != &global->dent_anchor; tmp = next, next = next->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		if (!dent->d_killme)
			continue;

		bind_to_dent(dent, &say_channel);

		MARS_DBG("killing dent '%s'\n", dent->d_path);
		list_del_init(tmp);
		mars_free_dent(dent);
	}
	up_write(&global->dent_mutex);

	bind_to_dent(NULL, &say_channel);

	/* Forward pass.
	*/
	down_read(&global->dent_mutex);
	MARS_IO("forward pass\n");
	for (tmp = global->dent_anchor.next, next = tmp->next; tmp != &global->dent_anchor; tmp = next, next = next->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		up_read(&global->dent_mutex);

		brick_yield();

		bind_to_dent(dent, &say_channel);

		//MARS_IO("forward treat '%s'\n", dent->d_path);
		status = worker(buf, dent, false, false);
		if (status) {
			//MARS_IO("forward treat '%s' status = %d\n", dent->d_path, status);
		}
		down_read(&global->dent_mutex);
		total_status |= status;
	}
	bind_to_dent(NULL, &say_channel);

	/* Backward pass.
	*/
	MARS_IO("backward pass\n");
	for (tmp = global->dent_anchor.prev, next = tmp->prev; tmp != &global->dent_anchor; tmp = next, next = next->prev) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		up_read(&global->dent_mutex);

		brick_yield();

		bind_to_dent(dent, &say_channel);

		//MARS_IO("backward treat '%s'\n", dent->d_path);
		status = worker(buf, dent, false, true);
		if (status) {
			//MARS_IO("backward treat '%s' status = %d\n", dent->d_path, status);
		}
		down_read(&global->dent_mutex);
		total_status |= status;
		if (status < 0) {
			MARS_INF("backwards: status %d on '%s'\n", status, dent->d_path);
		}
	}
	up_read(&global->dent_mutex);

	bind_to_dent(NULL, &say_channel);

done:
	MARS_IO("total_status = %d\n", total_status);
	return total_status;
}
EXPORT_SYMBOL_GPL(mars_dent_work);

struct mars_dent *_mars_find_dent(struct mars_global *global, const char *path)
{
	struct mars_dent *res = NULL;
	struct list_head *tmp;

	if (!rwsem_is_locked(&global->dent_mutex)) {
		MARS_ERR("dent_mutex not held!\n");
	}

	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *tmp_dent = container_of(tmp, struct mars_dent, dent_link);
		if (!strcmp(tmp_dent->d_path, path)) {
			res = tmp_dent;
			break;
		}
	}

	return res;
}
EXPORT_SYMBOL_GPL(_mars_find_dent);

struct mars_dent *mars_find_dent(struct mars_global *global, const char *path)
{
	struct mars_dent *res;
	if (!global)
		return NULL;
	down_read(&global->dent_mutex);
	res = _mars_find_dent(global, path);
	up_read(&global->dent_mutex);
	return res;
}
EXPORT_SYMBOL_GPL(mars_find_dent);

int mars_find_dent_all(struct mars_global *global, char *prefix, struct mars_dent ***table)
{
	int max = 1024; // provisionary
	int count = 0;
	struct list_head *tmp;
	struct mars_dent **res = brick_zmem_alloc(max * sizeof(void*));
	int prefix_len = strlen(prefix);

	*table = res;
	if (unlikely(!res || !global))
		goto done;

	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *tmp_dent = container_of(tmp, struct mars_dent, dent_link);
		int this_len;
		if (!tmp_dent->d_path) {
			continue;
		}
		this_len = strlen(tmp_dent->d_path);
		if (this_len < prefix_len || strncmp(tmp_dent->d_path, prefix, prefix_len)) {
			continue;
		}
		res[count++] = tmp_dent;
		if (count >= max)
			break;
	}
	up_read(&global->dent_mutex);

done:
	return count;
}
EXPORT_SYMBOL_GPL(mars_find_dent_all);

void mars_kill_dent(struct mars_dent *dent)
{
	dent->d_killme = true;
	mars_kill_brick_all(NULL, &dent->brick_list, true);
}
EXPORT_SYMBOL_GPL(mars_kill_dent);

void mars_free_dent(struct mars_dent *dent)
{
	int i;
	
	MARS_IO("%p path='%s'\n", dent, dent->d_path);

	mars_kill_dent(dent);

	CHECK_HEAD_EMPTY(&dent->dent_link);
	CHECK_HEAD_EMPTY(&dent->brick_list);

	for (i = 0; i < MARS_ARGV_MAX; i++) {
		brick_string_free(dent->d_argv[i]);
	}
	brick_string_free(dent->d_args);
	brick_string_free(dent->d_name);
	brick_string_free(dent->d_rest);
	brick_string_free(dent->d_path);
	brick_string_free(dent->old_link);
	brick_string_free(dent->new_link);
	if (likely(dent->d_parent)) {
		dent->d_parent->d_child_count--;
	}
	if (dent->d_private_destruct) {
		dent->d_private_destruct(dent->d_private);
	}
	brick_mem_free(dent->d_private);
	brick_mem_free(dent);
}
EXPORT_SYMBOL_GPL(mars_free_dent);

void mars_free_dent_all(struct mars_global *global, struct list_head *anchor)
{
	LIST_HEAD(tmp_list);
	if (global)
		down_write(&global->dent_mutex);
	list_replace_init(anchor, &tmp_list);
	if (global)
		up_write(&global->dent_mutex);
	MARS_DBG("is_empty=%d\n", list_empty(&tmp_list));
	while (!list_empty(&tmp_list)) {
		struct mars_dent *dent;
		dent = container_of(tmp_list.prev, struct mars_dent, dent_link);
		list_del_init(&dent->dent_link);
		MARS_IO("freeing dent %p\n", dent);
		mars_free_dent(dent);
	}
}
EXPORT_SYMBOL_GPL(mars_free_dent_all);


/////////////////////////////////////////////////////////////////////

// low-level brick instantiation

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
			MARS_WRN("MEMLEAK: brick '%s' has %d mrefs allocated (total = %d, maxsleep = %d)\n", brick->brick_path, count, atomic_read(&brick->mref_object_layout.total_alloc_count), maxsleep);
		} else {
			MARS_ERR("MEMLEAK: brick '%s' has %d mrefs allocated (total = %d)\n", brick->brick_path, count, atomic_read(&brick->mref_object_layout.total_alloc_count));
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
			generic_disconnect((void*)input);
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

	if (global) {
		down_write(&global->brick_mutex);
		list_del_init(&brick->global_brick_link);
		list_del_init(&brick->dent_brick_link);
		up_write(&global->brick_mutex);
	}

	if (brick->show_status) {
		brick->show_status(brick, true);
	}

	// start shutdown
	set_button_wait((void*)brick, false, true, 0);

	if (likely(brick->power.led_off)) {
		int max_inputs = 0;
		int i;

		if (likely(brick->type)) {
			max_inputs = brick->type->max_inputs;
		} else {
			MARS_ERR("uninitialized brick '%s' '%s'\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
		}

		MARS_DBG("---> freeing '%s' '%s'\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));

		if (brick->kill_ptr)
			*brick->kill_ptr = NULL;
		
		for (i = 0; i < max_inputs; i++) {
			struct generic_input *input = (void*)brick->inputs[i];
			if (!input)
				continue;
			status = generic_disconnect(input);
			if (unlikely(status < 0)) {
				MARS_ERR("brick '%s' '%s' disconnect %d failed, status = %d\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path), i, status);
				goto done;
			}
		}
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
		MARS_ERR("brick '%s' '%s' is not off\n", SAFE_STR(brick->brick_name), SAFE_STR(brick->brick_path));
		status = -EIO;
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

int mars_kill_brick_when_possible(struct mars_global *global, struct list_head *anchor, bool use_dent_link, const struct mars_brick_type *type, bool even_on)
{
	int return_status = 0;
	struct list_head *tmp;

restart:
	if (global) {
		down_write(&global->brick_mutex);
	}
	for (tmp = anchor->next; tmp != anchor; tmp = tmp->next) {
		struct mars_brick *brick;
		int status;
		if (use_dent_link) {
			brick = container_of(tmp, struct mars_brick, dent_brick_link);
		} else {
			brick = container_of(tmp, struct mars_brick, global_brick_link);
		}
		// only kill the right brick types
		if (type && brick->type != type) {
			continue;
		}
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
		/* Workaround FIXME:
		 * only kill bricks which have not been touched during the current mars_dent_work() round.
		 * some bricks like aio seem to have races between startup and termination of threads.
		 * disable this for stress-testing the allocation/deallocation logic.
		 * OTOH, frequently doing useless starts/stops is no good idea.
		 * CHECK: how to avoid too frequent switching by other means?
		 */
		if (brick->kill_round++ < 1) {
			continue;
		}

		list_del_init(tmp);
		if (global) {
			up_write(&global->brick_mutex);
		}

		MARS_DBG("KILLING '%s'\n", brick->brick_name);
		status = mars_kill_brick(brick);

		if (status >= 0) {
			return_status++;
		} else {
			return status;
		}
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
	char *paths[prev_count];
	struct mars_brick *prev[prev_count];
	bool switch_state;
	int i;
	int status;

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
		if (mars_check_outputs(brick)) {
			if (!switch_state)
				MARS_DBG("brick '%s' override 0 -> 1\n", new_path);
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
			switch_state = false;
			MARS_DBG("predecessor power is not on\n");
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
#ifdef CONFIG_MARS_PREFER_SIO
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
		status = generic_connect((void*)brick->inputs[i], (void*)prev[i]->outputs[0]);
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
	status = mars_power_button((void*)brick, switch_state, false);
	MARS_DBG("switch '%s' to %d status = %d\n", new_path, switch_state, status);
	goto done;

err:
	if (brick) {
		mars_kill_brick(brick);
	}
	brick = NULL;
done:
	for (i = 0; i < prev_count; i++) {
		if (paths[i]) {
			brick_string_free(paths[i]);
		}
	}
	if (_new_path)
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
	mars_symlink(val, name, NULL, 0);

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
		  "size_hint=%d "
		  "mrefs_alloc = %d "
		  "mrefs_apsect_alloc = %d "
		  "total_mrefs_alloc = %d "
		  "total_mrefs_aspects = %d "
		  "button = %d off = %d on = %d\n",
		  SAFE_STR(test->type->type_name),
		  SAFE_STR(test->brick_path),
		  SAFE_STR(test->brick_name),
		  test->mref_object_layout.size_hint,
		  atomic_read(&test->mref_object_layout.alloc_count),
		  atomic_read(&test->mref_object_layout.aspect_count),
		  atomic_read(&test->mref_object_layout.total_alloc_count),
		  atomic_read(&test->mref_object_layout.total_aspect_count),
		  test->power.button,
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
	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent;
		struct list_head *sub;
		dent = container_of(tmp, struct mars_dent, dent_link);
		MARS_STAT("dent %d '%s' '%s' stamp=%ld.%09ld\n", dent->d_class, SAFE_STR(dent->d_path), SAFE_STR(dent->new_link), dent->new_stat.mtime.tv_sec, dent->new_stat.mtime.tv_nsec);
		dent_count++;
		for (sub = dent->brick_list.next; sub != &dent->brick_list; sub = sub->next) {
			struct mars_brick *test;
			test = container_of(sub, struct mars_brick, dent_brick_link);
			MARS_STAT("  owner of brick '%s'\n", SAFE_STR(test->brick_path));
		}
	}
	up_read(&global->dent_mutex);

	MARS_STAT("==================== %s STATISTICS: %d dents, %d bricks, %lld KB free\n", class, dent_count, brick_count, global_remaining_space);
}
EXPORT_SYMBOL_GPL(show_statistics);

/////////////////////////////////////////////////////////////////////

// init stuff

int __init init_sy(void)
{
	MARS_INF("init_sy()\n");

	_mars_trigger = __mars_trigger;

	return 0;
}

void __exit exit_sy(void)
{
	MARS_INF("exit_sy()\n");
}

#ifndef CONFIG_MARS_HAVE_BIGMODULE
MODULE_DESCRIPTION("MARS block storage");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_sy);
module_exit(exit_sy);
#endif
