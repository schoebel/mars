// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

//#define BRICK_DEBUGGING
//#define MARS_DEBUGGING

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/utsname.h>

#include "strategy.h"

#include "../mars_client.h"

#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/kthread.h>

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
	META_INI(d_namelen, struct mars_dent, FIELD_INT),
	META_INI(d_pathlen, struct mars_dent, FIELD_INT),
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

int mars_symlink(const char *oldpath, const char *newpath, const struct timespec *stamp, uid_t uid)
{
	char *tmp = backskip_replace(newpath, '/', true, "/.tmp-"); 
	mm_segment_t oldfs;
	int status = -ENOMEM;
	
	if (unlikely(!tmp))
		goto done;

	oldfs = get_fs();
	set_fs(get_ds());
	(void)sys_unlink(tmp);
	status = sys_symlink(oldpath, tmp);

	if (stamp) {
		struct timespec times[2];
		sys_lchown(tmp, uid, 0);
		memcpy(&times[0], stamp, sizeof(struct timespec));
		memcpy(&times[1], stamp, sizeof(struct timespec));
		status = do_utimes(AT_FDCWD, tmp, times, AT_SYMLINK_NOFOLLOW);
	}

	if (status >= 0) {
		status = mars_rename(tmp, newpath);
	}
	set_fs(oldfs);
	brick_string_free(tmp);

done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_symlink);

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

//////////////////////////////////////////////////////////////

// crypto stuff

#include <linux/crypto.h>

struct crypto_hash *mars_tfm = NULL;
int mars_digest_size = 0;
EXPORT_SYMBOL_GPL(mars_digest_size);

void mars_digest(void *digest, void *data, int len)
{
	struct hash_desc desc = {
		.tfm = mars_tfm,
		.flags = 0,
	};
	struct scatterlist sg;

	memset(digest, 0, mars_digest_size);

	crypto_hash_init(&desc);
	sg_init_table(&sg, 1);
	sg_set_buf(&sg, data, len);
	crypto_hash_update(&desc, &sg, sg.length);
	crypto_hash_final(&desc, digest);
}
EXPORT_SYMBOL_GPL(mars_digest);

//////////////////////////////////////////////////////////////

// infrastructure

struct mars_global *mars_global = NULL;
EXPORT_SYMBOL_GPL(mars_global);

static
void __mars_trigger(void)
{
	if (mars_global) {
		mars_global->main_trigger = true;
		wake_up_interruptible(&mars_global->main_event);
	}
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
		MARS_DBG("brick '%s' type '%s' power button %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);

		set_button(&brick->power, val, false);

		if (brick->ops)
			status = brick->ops->brick_switch(brick);

		mars_trigger();
	}
	return status;
}
EXPORT_SYMBOL_GPL(mars_power_button);

int mars_power_button_recursive(struct mars_brick *brick, bool val, bool force_off, int timeout)
{
	int status = 0;
	bool oldval = brick->power.button;

	if (force_off && !val)
		brick->power.force_off = true;

	if (brick->power.force_off)
		val = false;

	if (val != oldval) {
		brick_switch_t mode;
		mode = (val ? BR_ON_ALL : (force_off ? BR_FREE_ALL : BR_OFF_ALL));

		MARS_DBG("brick '%s' type '%s' power button %d -> %d (mode = %d)\n", brick->brick_path, brick->type->type_name, oldval, val, mode);

		status = set_recursive_button((void*)brick, mode, timeout);
	}
	return status;
}
EXPORT_SYMBOL_GPL(mars_power_button_recursive);

/////////////////////////////////////////////////////////////////////

// strategy layer


struct mars_cookie {
	struct mars_global *global;
	mars_dent_checker checker;
	char *path;
	struct mars_dent *parent;
	int pathlen;
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
		MARS_ERR("cannot stat '%s', status = %d\n", newpath, status);
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

		status = user_path_at(AT_FDCWD, newpath, 0, &path);
		if (unlikely(status < 0)) {
			MARS_ERR("cannot read link '%s'\n", newpath);
			goto done;
		}

                inode = path.dentry->d_inode;

		status = -ENOMEM;
		link = brick_string_alloc();
		if (likely(link)) {
			MARS_IO("len = %d\n", len);
			status = inode->i_op->readlink(path.dentry, link, len + 1);
			link[len] = '\0';
			if (status < 0 ||
			   (dent->new_link && !strncmp(dent->new_link, link, len))) {
				//MARS_IO("symlink no change '%s' -> '%s' (%s) status = %d\n", newpath, link, dent->new_link ? dent->new_link : "", status);
				brick_string_free(link);
			} else {
				MARS_IO("symlink '%s' -> '%s' (%s) status = %d\n", newpath, link, dent->new_link ? dent->new_link : "", status);
				brick_string_free(dent->old_link);
				dent->old_link = dent->new_link;
				dent->new_link = link;
			}
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

	MARS_IO("ino = %llu len = %d offset = %lld type = %u\n", ino, namlen, offset, d_type);

	if (name[0] == '.') {
		return 0;
	}

	class = cookie->checker(cookie->parent, name, namlen, d_type, &prefix, &serial);
	if (class < 0)
		return 0;

	pathlen = cookie->pathlen;
	newpath = brick_string_alloc();
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

	dent->d_name = brick_string_alloc();
	if (unlikely(!dent->d_name))
		goto err_mem2;
	memcpy(dent->d_name, name, namlen);
	dent->d_name[namlen] = '\0';
	dent->d_namelen = namlen;
	dent->d_rest = dent->d_name + prefix;

	dent->d_path = newpath;
	newpath = NULL;
	dent->d_pathlen = pathlen;

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
	dent->d_parent = cookie->parent;
	dent->d_depth = cookie->depth;
	dent->d_global = global;
	dent->d_killme = false;
	brick_string_free(newpath);
	return 0;

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
        mm_segment_t oldfs;
	int status = 0;

        oldfs = get_fs();
        set_fs(get_ds());
        f = filp_open(cookie->path, O_DIRECTORY | O_RDONLY, 0);
        set_fs(oldfs);
	if (unlikely(IS_ERR(f))) {
		return PTR_ERR(f);
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

int mars_dent_work(struct mars_global *global, char *dirname, int allocsize, mars_dent_checker checker, mars_dent_worker worker, void *buf, int maxdepth)
{
	static int version = 0;
	struct mars_cookie cookie = {
		.global = global,
		.checker = checker,
		.path = dirname,
		.pathlen = strlen(dirname),
		.allocsize = allocsize,
		.depth = 0,
	};
	struct list_head *tmp;
	struct list_head *next;
	int rounds = 0;
	int status;
	int total_status = 0;
	bool found_dir;

	/* Initialize the flat dent list
	 */
	version++;
	total_status = _mars_readdir(&cookie);

	if (total_status || !worker) {
		goto done;
	}

	down_write(&global->dent_mutex);

restart:
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

		msleep(10); // yield

		MARS_IO("reading inode '%s'\n", dent->d_path);
		status = get_inode(dent->d_path, dent);
		total_status |= status;

		// recurse into subdirectories by inserting into the flat list
		if (S_ISDIR(dent->new_stat.mode) && dent->d_depth <= maxdepth) {
			struct mars_cookie sub_cookie = {
				.global = global,
				.checker = checker,
				.path = dent->d_path,
				.pathlen = dent->d_pathlen,
				.allocsize = allocsize,
				.parent = dent,
				.depth = dent->d_depth + 1,
			};
			found_dir = true;
			status = _mars_readdir(&sub_cookie);
			total_status |= status;
			if (status < 0) {
				MARS_ERR("forward: status %d on '%s'\n", status, dent->d_path);
			}
		}
	}

	if (found_dir && ++rounds < 10) {
		goto restart;
	}

	/* Remove all dents marked for removal.
	 */
	for (tmp = global->dent_anchor.next, next = tmp->next; tmp != &global->dent_anchor; tmp = next, next = next->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		if (!dent->d_killme)
			continue;
		MARS_DBG("killing dent '%s'\n", dent->d_path);
		list_del_init(tmp);
		//... FIXME memleak
	}

	up_write(&global->dent_mutex);

	/* Forward pass.
	*/
	down_read(&global->dent_mutex);
	for (tmp = global->dent_anchor.next, next = tmp->next; tmp != &global->dent_anchor; tmp = next, next = next->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		msleep(10); // yield
		MARS_IO("forward treat '%s'\n", dent->d_path);
		status = worker(buf, dent, false);
		total_status |= status;
		if (status < 0)
			continue;
		if (status < 0) {
			MARS_ERR("backwards: status %d on '%s'\n", status, dent->d_path);
		}
	}

	/* Backward pass.
	*/
	for (tmp = global->dent_anchor.prev; tmp != &global->dent_anchor; tmp = tmp->prev) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, dent_link);
		msleep(10); // yield
		MARS_IO("backward treat '%s'\n", dent->d_path);
		status = worker(buf, dent, true);
		total_status |= status;
		if (status < 0) {
			MARS_ERR("backwards: status %d on '%s'\n", status, dent->d_path);
		}
	}
	up_read(&global->dent_mutex);

done:
	return total_status;
}
EXPORT_SYMBOL_GPL(mars_dent_work);

static
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
//EXPORT_SYMBOL_GPL(_mars_find_dent);

struct mars_dent *mars_find_dent(struct mars_global *global, const char *path)
{
	struct mars_dent *res;
	//down_read(&global->dent_mutex);
	res = _mars_find_dent(global, path);
	//up_read(&global->dent_mutex);
	return res;
}
EXPORT_SYMBOL_GPL(mars_find_dent);

#if 0 // old code! does not work! incorrect locking / races!
void mars_kill_dent(struct mars_dent *dent)
{
	struct mars_global *global = dent->d_global;
	struct list_head *oldtmp = NULL;

	CHECK_PTR(global, done);

	down(&global->mutex);
	while (!list_empty(&dent->brick_list)) {
		struct list_head *tmp = dent->brick_list.next;
		struct mars_brick *brick = container_of(tmp, struct mars_brick, dent_brick_link);

		// just satisfy "defensive" programming style...
		if (unlikely(tmp == oldtmp)) {
			MARS_ERR("oops, something is nasty here\n");
			list_del_init(tmp);
			continue;
		}
		oldtmp = tmp;

		// killing a brick may take a long time...
		up(&global->mutex);
		mars_kill_brick(brick);
		down(&global->mutex);
	}
	up(&global->mutex);
 done: ;
}
#else
void mars_kill_dent(struct mars_dent *dent)
{
	dent->d_killme = true;
	while (!list_empty(&dent->brick_list)) {
		struct list_head *tmp = dent->brick_list.next;
		struct mars_brick *brick = container_of(tmp, struct mars_brick, dent_brick_link);
		list_del_init(tmp);
		// note: locking is now done there....
		mars_kill_brick(brick);
	}
}
#endif
EXPORT_SYMBOL_GPL(mars_kill_dent);

void mars_free_dent(struct mars_dent *dent)
{
	int i;
	
	mars_kill_dent(dent);

	CHECK_HEAD_EMPTY(&dent->dent_link);
	CHECK_HEAD_EMPTY(&dent->brick_list);

	for (i = 0; i < MARS_ARGV_MAX; i++) {
		brick_string_free(dent->d_argv[i]);
	}
	brick_string_free(dent->d_args);
	brick_string_free(dent->d_name);
	brick_string_free(dent->d_path);
	brick_mem_free(dent->d_private);
	brick_string_free(dent->old_link);
	brick_string_free(dent->new_link);
	brick_mem_free(dent);
}
EXPORT_SYMBOL_GPL(mars_free_dent);

void mars_free_dent_all(struct list_head *anchor)
{
	while (!list_empty(anchor)) {
		struct mars_dent *dent;
		dent = container_of(anchor->prev, struct mars_dent, dent_link);
		list_del_init(&dent->dent_link);
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
	int status;

	if (!brick) {
		MARS_ERR("bad brick parameter\n");
		status = -EINVAL;
		goto done;
	}

	if (!brick->power.force_off || !brick->power.led_off) {
		MARS_DBG("brick '%s' is not freeable\n", brick->brick_name);
		status = -ETXTBSY;
		goto done;
	}

	// first check whether the brick is in use somewhere
	for (i = 0; i < brick->nr_outputs; i++) {
		if (brick->outputs[i]->nr_connected > 0) {
			MARS_DBG("brick '%s' not freeable, output %i is used\n", brick->brick_name, i);
			status = -EEXIST;
			goto done;
		}
	}

	MARS_DBG("===> freeing brick name = '%s'\n", brick->brick_name);

	global = brick->global;
	if (global) {
		down_write(&global->brick_mutex);
		list_del_init(&brick->global_brick_link);
		list_del_init(&brick->dent_brick_link);
		up_write(&global->brick_mutex);
	}

	status = generic_brick_exit_full((void*)brick);

	if (status >= 0) {
#ifndef MEMLEAK // TODO: check whether crash remains possible
		brick_string_free(brick->brick_name);
		brick_string_free(brick->brick_path);
		brick_mem_free(brick);
#endif
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
	const char *names[] = { name };
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
		list_add(&res->dent_brick_link, &belongs->brick_list);
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
	CHECK_PTR(global, done);

	MARS_DBG("===> killing brick path = '%s' name = '%s'\n", brick->brick_path, brick->brick_name);

	// start shutdown
	status = set_recursive_button((void*)brick, BR_FREE_ALL, 10 * HZ);

done:
	return status;
}
EXPORT_SYMBOL_GPL(mars_kill_brick);


/////////////////////////////////////////////////////////////////////

// mid-level brick instantiation (identity is based on path strings)

char *vpath_make(const char *fmt, va_list *args)
{
	char *res = brick_string_alloc();

	if (likely(res)) {
		vsnprintf(res, MARS_PATH_MAX, fmt, *args);
	}
	return res;
}
EXPORT_SYMBOL_GPL(vpath_make);

char *path_make(const char *fmt, ...)
{
	va_list args;
	char *res;
	va_start(args, fmt);
	res = vpath_make(fmt, &args);
	va_end(args);
	return res;
}
EXPORT_SYMBOL_GPL(path_make);

char *backskip_replace(const char *path, char delim, bool insert, const char *fmt, ...)
{
	int path_len = strlen(path);
	int total_len = strlen(fmt) + path_len + MARS_PATH_MAX;
	char *res = brick_string_alloc();
	if (likely(res)) {
		va_list args;
		int pos = path_len;
		int plus;

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
		plus = vsnprintf(res + pos, total_len - pos, fmt, args);
		va_end(args);

		if (insert) {
			strncpy(res + pos + plus, path + pos + 1, total_len - pos - plus);
		}
	}
	return res;
}
EXPORT_SYMBOL_GPL(backskip_replace);

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

struct mars_brick *make_brick_all(
	struct mars_global *global,
	struct mars_dent *belongs,
	void (*setup_fn)(struct mars_brick *brick, void *private),
	void *private,
	int timeout,
	const char *new_name,
	const struct generic_brick_type *new_brick_type,
	const struct generic_brick_type *prev_brick_type[],
	const char *switch_fmt,
	const char *new_fmt,
	const char *prev_fmt[],
	int prev_count,
	...
	)
{
	va_list args;
	char *switch_path = NULL;
	const char *new_path;
	char *_new_path = NULL;
	struct mars_brick *brick = NULL;
	char *paths[prev_count];
	struct mars_brick *prev[prev_count];
	int switch_state = true;
	int i;

	// treat variable arguments
	va_start(args, prev_count);
	if (switch_fmt) {
		switch_state = false;
		if (switch_fmt[0]) {
			switch_path = vpath_make(switch_fmt, &args);
		}
	}
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
	if (switch_path) {
		struct mars_dent *test = mars_find_dent(global, switch_path);
		if (test && test->new_link) {
			sscanf(test->new_link, "%d", &switch_state);
		}
	}

	// brick already existing?
	brick = mars_find_brick(global, new_brick_type != _aio_brick_type  && new_brick_type != _bio_brick_type ? new_brick_type : NULL, new_path);
	if (brick) {
		// just switch the power state
		MARS_DBG("found existing brick '%s'\n", new_path);
		goto do_switch;
	}
	if (!switch_state) { // don't start => also don't create
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

		prev[i] = mars_find_brick(global, prev_brick_type[i], path);

		if (!prev[i]) {
			MARS_ERR("prev brick '%s' does not exist\n", path);
			goto err;
		}
		MARS_DBG("------> predecessor %d path = '%s'\n", i, path);
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

	// call setup function
	if (setup_fn) {
		setup_fn(brick, private);
	}

do_switch:
	// switch on/off (may fail silently, but responsibility is at the workers)
	if (timeout > 0 || !switch_state) {
		int status;
		if (switch_state) {
			status = mars_power_button_recursive((void*)brick, switch_state, false, timeout);
		} else {
			status = mars_power_button((void*)brick, switch_state, false);
		}
		MARS_DBG("switch '%s' timeout=%d to %d status = %d\n", new_path, timeout, switch_state, status);
#if 0 // TODO: need cleanup_fn() here FIXME: interferes with logic needing the switched-off brick!
		if (!switch_state && status >= 0 && !brick->power.button && brick->power.led_off) {
			mars_kill_brick(brick);
			brick = NULL;
		}
#endif
	}
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
	if (switch_path)
		brick_string_free(switch_path);

	return brick;
}
EXPORT_SYMBOL_GPL(make_brick_all);

/////////////////////////////////////////////////////////////////////

// init stuff

static int __init init_sy(void)
{
	MARS_INF("init_sy()\n");

	_mars_trigger = __mars_trigger;
	brick_obj_max = BRICK_OBJ_MAX;

	mars_tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (!mars_tfm) {
		MARS_ERR("cannot alloc crypto hash\n");
		return -ENOMEM;
	}
	if (IS_ERR(mars_tfm)) {
		MARS_ERR("alloc crypto hash failed, status = %d\n", (int)PTR_ERR(mars_tfm));
		return PTR_ERR(mars_tfm);
	}
#if 0
	if (crypto_tfm_alg_type(crypto_hash_tfm(mars_tfm)) != CRYPTO_ALG_TYPE_DIGEST) {
		MARS_ERR("bad crypto hash type\n");
		return -EINVAL;
	}
#endif
	mars_digest_size = crypto_hash_digestsize(mars_tfm);
	MARS_INF("digest_size = %d\n", mars_digest_size);

	return 0;
}

static void __exit exit_sy(void)
{
	MARS_INF("exit_sy()\n");
	if (mars_tfm) {
		crypto_free_hash(mars_tfm);
	}
}

MODULE_DESCRIPTION("MARS block storage");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_sy);
module_exit(exit_sy);
