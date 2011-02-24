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

#define _STRATEGY
#include "mars.h"

#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/kthread.h>

// some helpers
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

int mars_symlink(const char *oldpath, const char *newpath, const struct timespec *stamp)
{
	int newlen = strlen(newpath);
	char tmp[newlen + 16];
	mm_segment_t oldfs;
	int status;
	
	snprintf(tmp, sizeof(tmp), "%s.tmp", newpath);
	oldfs = get_fs();
	set_fs(get_ds());
	(void)sys_unlink(tmp);
	status = sys_symlink(oldpath, tmp);
	set_fs(oldfs);

	// TODO NYI: set timestamp

	if (status >= 0) {
		status = mars_rename(tmp, newpath);
	}

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


//////////////////////////////////////////////////////////////

// object stuff

const struct generic_object_type mref_type = {
	.object_type_name = "mref",
	.default_size = sizeof(struct mref_object),
	.brick_obj_nr = BRICK_OBJ_MREF,
};
EXPORT_SYMBOL_GPL(mref_type);

//////////////////////////////////////////////////////////////

// brick stuff

//////////////////////////////////////////////////////////////

// infrastructure

static char *id = NULL;

/* TODO: better use MAC addresses (or motherboard IDs where available).
 * Or, at least, some checks for MAC addresses should be recorded / added.
 * When the nodename is misconfigured, data might be scrambled.
 * MAC addresses should be more secure.
 * In ideal case, further checks should be added to prohibit accidental
 * name clashes.
 */
char *my_id(void)
{
	struct new_utsname *u;
	if (id)
		return id;

	//down_read(&uts_sem); // FIXME: this is currenty not EXPORTed from the kernel!
	u = utsname();
	if (u) {
		id = kstrdup(u->nodename, GFP_MARS);
	}
	//up_read(&uts_sem);
	
	return id;
}
EXPORT_SYMBOL_GPL(my_id);

struct mars_global *mars_global = NULL;
EXPORT_SYMBOL_GPL(mars_global);

void mars_trigger(void)
{
	if (mars_global) {
		MARS_DBG("trigger...\n");
		mars_global->main_trigger = true;
		wake_up_interruptible(&mars_global->main_event);
	}
}
EXPORT_SYMBOL_GPL(mars_trigger);

void mars_power_button(struct mars_brick *brick, bool val)
{
	bool oldval = brick->power.button;
	if (val != oldval) {
		MARS_DBG("brick '%s' type '%s' power button %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);
		set_button(&brick->power, val);
		mars_trigger();
	}
}
EXPORT_SYMBOL_GPL(mars_power_button);

void mars_power_led_on(struct mars_brick *brick, bool val)
{
	bool oldval = brick->power.led_on;
	if (val != oldval) {
		MARS_DBG("brick '%s' type '%s' led_on %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);
		set_led_on(&brick->power, val);
		mars_trigger();
	}
}
EXPORT_SYMBOL_GPL(mars_power_led_on);

void mars_power_led_off(struct mars_brick *brick, bool val)
{
	bool oldval = brick->power.led_off;
	if (val != oldval) {
		MARS_DBG("brick '%s' type '%s' led_off %d -> %d\n", brick->brick_path, brick->type->type_name, oldval, val);
		set_led_off(&brick->power, val);
		mars_trigger();
	}
}
EXPORT_SYMBOL_GPL(mars_power_led_off);

/////////////////////////////////////////////////////////////////////

// strategy layer


struct mars_cookie {
	struct mars_global *global;
	mars_dent_checker checker;
	char *path;
	void *parent;
	int pathlen;
	int allocsize;
	int depth;
};

static
int get_inode(char *newpath, struct mars_dent *dent)
{
	mm_segment_t oldfs;
	int status;
	struct path path;

	oldfs = get_fs();
	set_fs(get_ds());
	
	status = user_path_at(AT_FDCWD, newpath, 0, &path);
	if (!status) {
		struct inode *inode = path.dentry->d_inode;
		memcpy(&dent->old_stat, &dent->new_stat, sizeof(dent->old_stat)); 
		generic_fillattr(inode, &dent->new_stat);
		if (S_ISLNK(dent->new_stat.mode)) {
			int len = dent->new_stat.size;
			char *link;
			status = -ENOMEM;
			link = kmalloc(len + 1, GFP_MARS);
			if (link) {
				status = inode->i_op->readlink(path.dentry, link, len);
				link[len] = '\0';
				if (status < 0 ||
				   (dent->new_link && !strncmp(dent->new_link, link, len))) {
					//MARS_DBG("symlink no change '%s' -> '%s' (%s) status = %d\n", newpath, link, dent->new_link ? dent->new_link : "", status);
					kfree(link);
				} else {
					MARS_DBG("symlink '%s' -> '%s' (%s) status = %d\n", newpath, link, dent->new_link ? dent->new_link : "", status);
					if (dent->old_link)
						kfree(dent->old_link);
					dent->old_link = dent->new_link;
					dent->new_link = link;
				}
			}
		}
		path_put(&path);
	}

	set_fs(oldfs);
	
	if (dent->new_link)
		MARS_IO("symlink '%s'\n", dent->new_link);
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

	class = cookie->checker(cookie->path, name, namlen, d_type, &prefix, &serial);
	if (class < 0)
		return 0;

	pathlen = cookie->pathlen;
	newpath = kmalloc(pathlen + namlen + 2, GFP_MARS);
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
		dent = container_of(tmp, struct mars_dent, sub_link);
		cmp = strcmp(dent->d_path, newpath);
		if (!cmp) {
			kfree(newpath);
			return 0;
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

	dent = kzalloc(cookie->allocsize, GFP_MARS);
	if (unlikely(!dent))
		goto err_mem1;
	dent->d_name = kmalloc(namlen + 1, GFP_MARS);
	if (unlikely(!dent->d_name))
		goto err_mem2;

	dent->d_type = d_type;
	dent->d_class = class;
	dent->d_serial = serial;
	dent->d_parent = cookie->parent;
	dent->d_depth = cookie->depth;

	memcpy(dent->d_name, name, namlen);
	dent->d_name[namlen] = '\0';
	dent->d_namelen = namlen;
	dent->d_rest = dent->d_name + prefix;

	dent->d_path = newpath;
	dent->d_pathlen = pathlen;

	down(&global->mutex);
	if (best) {
		list_add(&dent->sub_link, &best->sub_link);
	} else {
		list_add_tail(&dent->sub_link, anchor);
	}
	up(&global->mutex);
	return 0;

err_mem2:
	kfree(dent);
err_mem1:
	kfree(newpath);
err_mem0:
	return -ENOMEM;
}

static int _mars_dent_work(struct mars_cookie *cookie)
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
	int rounds = 0;
	int status;
	int total_status = 0;
	bool found_dir;

	version++;
	total_status = _mars_dent_work(&cookie);

	if (total_status || !worker) {
		goto done;
	}

restart:
	found_dir = false;

	/* First, get all the inode information in a separate pass
	 * before starting work.
	 * The separate pass is necessary because some dents may
	 * forward-reference other dents, and it would be a pity if
	 * some inodes were not available or were outdated.
	 */
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, sub_link);
		// treat any member only once during this invocation
		if (dent->d_version == version)
			continue;
		dent->d_version = version;

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
			status = _mars_dent_work(&sub_cookie);
			total_status |= status;
			if (status < 0) {
				MARS_ERR("forward: status %d on '%s'\n", status, dent->d_path);
			}
		}
	}
	if (found_dir && ++rounds < 10) {
		goto restart;
	}

	/* Forward pass.
	*/
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *dent = container_of(tmp, struct mars_dent, sub_link);
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
		struct mars_dent *dent = container_of(tmp, struct mars_dent, sub_link);
		MARS_IO("backward treat '%s'\n", dent->d_path);
		status = worker(buf, dent, true);
		total_status |= status;
		if (status < 0) {
			MARS_ERR("backwards: status %d on '%s'\n", status, dent->d_path);
		}
	}

done:
	return total_status;
}
EXPORT_SYMBOL_GPL(mars_dent_work);

struct mars_dent *_mars_find_dent(struct mars_global *global, const char *path)
{
	struct mars_dent *res = NULL;
	struct list_head *tmp;
	
	for (tmp = global->dent_anchor.next; tmp != &global->dent_anchor; tmp = tmp->next) {
		struct mars_dent *tmp_dent = container_of(tmp, struct mars_dent, sub_link);
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
	down(&global->mutex);
	res = _mars_find_dent(global, path);
	up(&global->mutex);
	return res;
}
EXPORT_SYMBOL_GPL(mars_find_dent);

void mars_dent_free(struct mars_dent *dent)
{
	int i;

	list_del(&dent->sub_link);

	for (i = 0; i < MARS_ARGV_MAX; i++) {
		if (dent->d_argv[i])
			kfree(dent->d_argv[i]);
	}
	if (dent->d_args)
		kfree(dent->d_args);
	if (dent->d_private)
		kfree(dent->d_private);
	if (dent->old_link)
		kfree(dent->old_link);
	if (dent->new_link)
		kfree(dent->new_link);
	kfree(dent->d_name);
	kfree(dent->d_path);
	kfree(dent);
}
EXPORT_SYMBOL_GPL(mars_dent_free);

void mars_dent_free_all(struct list_head *anchor)
{
	while (!list_empty(anchor)) {
		struct mars_dent *dent;
		dent = container_of(anchor->prev, struct mars_dent, sub_link);
		mars_dent_free(dent);
	}
}
EXPORT_SYMBOL_GPL(mars_dent_free_all);


struct mars_brick *mars_find_brick(struct mars_global *global, const void *brick_type, const char *path)
{
	struct list_head *tmp;

	if (!global || !path)
		return NULL;

	down(&global->mutex);

	for (tmp = global->brick_anchor.next; tmp != &global->brick_anchor; tmp = tmp->next) {
		struct mars_brick *test = container_of(tmp, struct mars_brick, brick_link);
		if (!strcmp(test->brick_path, path)) {
			up(&global->mutex);
			if (brick_type && test->type != brick_type) {
				MARS_ERR("bad brick type\n");
				return NULL;
			}
			return test;
		}
	}

	up(&global->mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(mars_find_brick);

struct mars_brick *mars_make_brick(struct mars_global *global, const void *_brick_type, const char *path, const char *_name)
{
	const char *name = kstrdup(_name, GFP_MARS);
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
		size += type->input_size;
	}
	output_types = brick_type->default_output_types;
	for (i = 0; i < brick_type->max_outputs; i++) {
		const struct generic_output_type *type = *output_types++;
		if (unlikely(!type)) {
			MARS_ERR("output_type %d is missing\n", i);
			goto err_name;
		}
		size += type->output_size;
	}
	
	res = kzalloc(size, GFP_MARS);
	if (!res) {
		MARS_ERR("cannot grab %d bytes for brick type '%s'\n", size, brick_type->type_name);
		goto err_name;
	}
	res->brick_path = kstrdup(path, GFP_MARS);
	res->global = global;
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

	/* Immediately make it visible, regardless of internal state.
	 * Switching on / etc must be done separately.
	 */
	down(&global->mutex);
	list_add(&res->brick_link, &global->brick_anchor);
	up(&global->mutex);

	return res;

err_path:
	kfree(res->brick_path);
err_res:
	kfree(res);
err_name:
	kfree(name);
	return NULL;
}
EXPORT_SYMBOL_GPL(mars_make_brick);


/////////////////////////////////////////////////////////////////////

// meta descriptions

const struct meta mars_info_meta[] = {
	META_INI(current_size,    struct mars_info, FIELD_INT),
	META_INI(transfer_order,  struct mars_info, FIELD_INT),
	META_INI(transfer_size,   struct mars_info, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_info_meta);

const struct meta mars_mref_meta[] = {
	META_INI(ref_pos,          struct mref_object, FIELD_INT),
	META_INI(ref_len,          struct mref_object, FIELD_INT),
	META_INI(ref_may_write,    struct mref_object, FIELD_INT),
	META_INI(ref_flags,        struct mref_object, FIELD_INT),
	META_INI(ref_rw,           struct mref_object, FIELD_INT),
	META_INI(ref_id,           struct mref_object, FIELD_INT),
	META_INI(_ref_cb.cb_error, struct mref_object, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_mref_meta);

const struct meta mars_timespec_meta[] = {
	META_INI(tv_sec, struct timespec, FIELD_INT),
	META_INI(tv_nsec, struct timespec, FIELD_INT),
	{}
};
EXPORT_SYMBOL_GPL(mars_timespec_meta);

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
	META_INI(d_version, struct mars_dent, FIELD_INT),
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

// init stuff

static int __init init_mars(void)
{
	MARS_INF("init_mars()\n");
	return 0;
}

static void __exit exit_mars(void)
{
	MARS_INF("exit_mars()\n");
	if (id) {
		kfree(id);
		id = NULL;
	}
}

MODULE_DESCRIPTION("MARS block storage");
MODULE_AUTHOR("Thomas Schoebel-Theuer <tst@1und1.de>");
MODULE_LICENSE("GPL");

module_init(init_mars);
module_exit(exit_mars);
