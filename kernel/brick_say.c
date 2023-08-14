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

/* This is historic.
 * To disappear in the long term.
 * When CONFIG_MARS_DEBUG_DEVEL_VIA_SAY is unset, and empty .o
 * should be created (for now).
 * Until it vanishes, the old code may be used as a hint for
 * debugging alternatives.
 */
#ifdef CONFIG_MARS_DEBUG_DEVEL_VIA_SAY

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/pagemap.h>

#include "brick_wait.h"
#include "brick_say.h"
#include "lamport.h"

/////////////////////////////////////////////////////////////////////

// messaging

#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/hardirq.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>

#include "compat.h"

#if defined(MARS_HAS_PREPATCH_V2) ||		\
	defined(MARS_HAS_PREPATCH_V3)
/* needed for mars_rename() */
#include "sy_old/strategy.h"
#endif

#ifndef GFP_BRICK
#define GFP_BRICK GFP_NOIO
#endif

#define SAY_ORDER 0
#define SAY_BUFMAX (PAGE_SIZE << SAY_ORDER)
#define SAY_BUF_LIMIT (SAY_BUFMAX - 1500)
#define MAX_FILELEN 16
#define MAX_IDS     16384

const char *say_class[MAX_SAY_CLASS] = {
	[SAY_DEBUG] = "debug",
	[SAY_INFO] = "info",
	[SAY_WARN] = "warn",
	[SAY_ERROR] = "error",
	[SAY_FATAL] = "fatal",
	[SAY_TOTAL] = "total",
};
EXPORT_SYMBOL_GPL(say_class);

int brick_say_logging = 1;
EXPORT_SYMBOL_GPL(brick_say_logging);
int brick_say_debug =
#ifdef CONFIG_MARS_DEBUG_DEFAULT
	1;
#else
	0;
#endif
EXPORT_SYMBOL_GPL(brick_say_debug);
int brick_say_syslog_min = 1;
EXPORT_SYMBOL_GPL(brick_say_syslog_min);
int brick_say_syslog_max = -1;
EXPORT_SYMBOL_GPL(brick_say_syslog_max);
int brick_say_syslog_flood_class = 3;
EXPORT_SYMBOL_GPL(brick_say_syslog_flood_class);
int brick_say_syslog_flood_limit = 20;
EXPORT_SYMBOL_GPL(brick_say_syslog_flood_limit);
int brick_say_syslog_flood_recovery = 300;
EXPORT_SYMBOL_GPL(brick_say_syslog_flood_recovery);
int delay_say_on_overflow =
#ifdef CONFIG_MARS_DEBUG
	1;
#else
	0;
#endif
EXPORT_SYMBOL_GPL(delay_say_on_overflow);

static atomic_t say_alloc_channels = ATOMIC_INIT(0);
static atomic_t say_alloc_names = ATOMIC_INIT(0);
static atomic_t say_alloc_pages = ATOMIC_INIT(0);

static unsigned long flood_start_jiffies = 0;
static int flood_count = 0;

struct say_channel {
	char *ch_name;
	struct say_channel *ch_next;
	spinlock_t ch_lock[MAX_SAY_CLASS];
	char *ch_buf[MAX_SAY_CLASS][2];
	short ch_index[MAX_SAY_CLASS];
	struct file *ch_filp[MAX_SAY_CLASS][2];
	int ch_overflow[MAX_SAY_CLASS];
	bool ch_written[MAX_SAY_CLASS];
	bool ch_rollover;
	bool ch_must_exist;
	bool ch_is_dir;
	bool ch_delete;
	int ch_status_written;
	int ch_id_max;
	void *ch_ids[MAX_IDS];
	wait_queue_head_t ch_progress;
};

struct say_channel *default_channel = NULL;
EXPORT_SYMBOL_GPL(default_channel);

static struct say_channel *channel_list = NULL;

static DECLARE_RWSEM(say_mutex);

static struct task_struct *say_thread = NULL;

static DECLARE_WAIT_QUEUE_HEAD(say_event);

bool say_dirty = false;

static
bool cannot_schedule(void)
{
	return (preempt_count() & (SOFTIRQ_MASK | HARDIRQ_MASK | NMI_MASK)) != 0 || in_atomic() || irqs_disabled();
}

static
void wait_channel(struct say_channel *ch, int class)
{
	if (delay_say_on_overflow && ch->ch_index[class] > SAY_BUF_LIMIT) {
		bool use_atomic = cannot_schedule();

		if (!use_atomic) {
			say_dirty = true;
			brick_wake_smp(&say_event);
			brick_wait_smp(ch->ch_progress,
				       ch->ch_index[class] < SAY_BUF_LIMIT,
				       HZ / 10);
		}
	}
}

static
struct say_channel *find_channel(const void *id)
{
	struct say_channel *res = default_channel;
	struct say_channel *ch;

	if (!default_channel || cannot_schedule())
		return res;

	down_read(&say_mutex);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		int i;
		for (i = 0; i < ch->ch_id_max; i++) {
			if (ch->ch_ids[i] == id) {
				res = ch;
				goto found;
			}
		}
	}
found:
	up_read(&say_mutex);
	return res;
}

static
void _remove_binding(struct task_struct *whom)
{
	struct say_channel *ch;
	int i;

	for (ch = channel_list; ch; ch = ch->ch_next) {
		for (i = 0; i < ch->ch_id_max; i++) {
			if (ch->ch_ids[i] == whom) {
				ch->ch_ids[i] = NULL;
			}
		}
	}
}

void bind_to_channel(struct say_channel *ch, struct task_struct *whom)
{
	int i;

	if (!default_channel || !ch || cannot_schedule())
		return;

	down_write(&say_mutex);
	_remove_binding(whom);
	for (i = 0; i < ch->ch_id_max; i++) {
		if (!ch->ch_ids[i]) {
			ch->ch_ids[i] = whom;
			goto done;
		}
	}
	if (likely(ch->ch_id_max < MAX_IDS - 1)) {
		ch->ch_ids[ch->ch_id_max++] = whom;
	} else {
		goto err;
	}

done:
	up_write(&say_mutex);
	return;

err:
	up_write(&say_mutex);

	say_to(default_channel, SAY_ERROR, "ID overflow for thread '%s'\n", whom->comm);
}
EXPORT_SYMBOL_GPL(bind_to_channel);

struct say_channel *get_binding(struct task_struct *whom)
{
	struct say_channel *ch;
	int i;

	if (!default_channel || cannot_schedule())
		return NULL;

	down_read(&say_mutex);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		for (i = 0; i < ch->ch_id_max; i++) {
			if (ch->ch_ids[i] == whom) {
				goto found;
			}
		}
	}
	ch = NULL;
found:
	up_read(&say_mutex);
	return ch;
}
EXPORT_SYMBOL_GPL(get_binding);

void remove_binding_from(struct say_channel *ch, struct task_struct *whom)
{
	bool found = false;
	int i;

	if (!default_channel || !ch || cannot_schedule())
		return;

	down_write(&say_mutex);
	for (i = 0; i < ch->ch_id_max; i++) {
		if (ch->ch_ids[i] == whom) {
			ch->ch_ids[i] = NULL;
			found = true;
			break;
		}
	}
	if (!found) {
		_remove_binding(whom);
	}
	up_write(&say_mutex);
}
EXPORT_SYMBOL_GPL(remove_binding_from);

void remove_binding(struct task_struct *whom)
{
	if (!default_channel || cannot_schedule())
		return;

	down_write(&say_mutex);
	_remove_binding(whom);
	up_write(&say_mutex);
}
EXPORT_SYMBOL_GPL(remove_binding);

void rollover_channel(struct say_channel *ch)
{
	if (!default_channel || cannot_schedule())
		return;

	if (!ch) {
		ch = find_channel(current);
	}
	if (likely(ch))
		ch->ch_rollover = true;
}
EXPORT_SYMBOL_GPL(rollover_channel);

void rollover_all(void)
{
	struct say_channel *ch;

	if (!default_channel || cannot_schedule())
		return;

	down_read(&say_mutex);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		ch->ch_rollover = true;
	}
	up_read(&say_mutex);
}
EXPORT_SYMBOL_GPL(rollover_all);

void del_channel(struct say_channel *ch)
{
	if (unlikely(!ch))
		return;
	if (unlikely(ch == default_channel)) {
		say_to(default_channel, SAY_ERROR, "thread '%s' tried to delete the default channel\n", current->comm);
		return;
	}
	
	ch->ch_delete = true;
}
EXPORT_SYMBOL_GPL(del_channel);

static
void _del_channel(struct say_channel *ch)
{
	struct say_channel *tmp;
	struct say_channel **_tmp;
	int i, j;

	if (!ch)
		return;
	if (cannot_schedule())
		return;

	down_write(&say_mutex);
	for (_tmp = &channel_list; (tmp = *_tmp) != NULL; _tmp = &tmp->ch_next) {
		if (tmp == ch) {
			*_tmp = tmp->ch_next;
			break;
		}
	}
	up_write(&say_mutex);

	for (i = 0; i < MAX_SAY_CLASS; i++) {
		for (j = 0; j < 2; j++) {
			if (ch->ch_filp[i][j]) {
				filp_close(ch->ch_filp[i][j], NULL);
				ch->ch_filp[i][j] = NULL;
			}
		}
		for (j = 0; j < 2; j++) {
			char *buf = ch->ch_buf[i][j];
			if (buf) {
				__free_pages(virt_to_page((unsigned long)buf), SAY_ORDER);
				atomic_dec(&say_alloc_pages);
			}
		}
	}
	if (ch->ch_name) {
		kfree(ch->ch_name);
		atomic_dec(&say_alloc_names);
	}
	kfree(ch);
	atomic_dec(&say_alloc_channels);
}

#ifdef MARS_HAS_VFS_GET_LINK

static
int brick_stat(const char *pathname, struct kstat *kstat)
{
	int getattr_flags = 0;
	int lookup_flags = LOOKUP_FOLLOW;
	struct path vfs_path;
	int status;

	status = kern_path(pathname, lookup_flags, &vfs_path);
	if (status < 0) {
		return status;
	}

	status = vfs_getattr(&vfs_path,
			     kstat,
			     STATX_BASIC_STATS,
			     getattr_flags | AT_NO_AUTOMOUNT);

	path_put(&vfs_path);

	return status;
}

#else /* MARS_HAS_VFS_GET_LINK */

static
int brick_stat(const char *pathname, struct kstat *kstat)
{
#ifdef MARS_NEEDS_KERNEL_DS
	mm_segment_t oldfs;
#endif
	int status;

#ifdef MARS_NEEDS_KERNEL_DS
	oldfs = get_fs();
	set_fs(KERNEL_DS);
#endif
	status = vfs_stat((char *)pathname, kstat);
#ifdef MARS_NEEDS_KERNEL_DS
	set_fs(oldfs);
#endif
	return status;
}

#endif /* MARS_HAS_VFS_GET_LINK */

static
struct say_channel *_make_channel(const char *name, bool must_exist)
{
	struct say_channel *res = NULL;
	struct kstat kstat = {};
	int i, j;
	bool is_dir = false;
	int status;

	status = brick_stat(name, &kstat);
	if (unlikely(status < 0)) {
		if (must_exist) {
			say(SAY_ERROR, "cannot create channel '%s', status = %d\n", name, status);
			goto done;
		}
	} else {
		is_dir = S_ISDIR(kstat.mode);
	}

restart:
	res = kzalloc(sizeof(struct say_channel), GFP_BRICK);
	if (unlikely(!res)) {
		cond_resched();
		goto restart;
	}
	atomic_inc(&say_alloc_channels);
	res->ch_must_exist = must_exist;
	res->ch_is_dir = is_dir;
	init_waitqueue_head(&res->ch_progress);
restart2:
	res->ch_name = kstrdup(name, GFP_BRICK);
	if (unlikely(!res->ch_name)) {
		cond_resched();
		goto restart2;
	}
	atomic_inc(&say_alloc_names);
	for (i = 0; i < MAX_SAY_CLASS; i++) {
		spin_lock_init(&res->ch_lock[i]);
		for (j = 0; j < 2; j++) {
			char *buf;
		restart3:
			buf = (void*)__get_free_pages(GFP_BRICK, SAY_ORDER);
			if (unlikely(!buf)) {
				cond_resched();
				goto restart3;
			}
			atomic_inc(&say_alloc_pages);
			res->ch_buf[i][j] = buf;
		}
	}
done:
	return res;
}

struct say_channel *make_channel(const char *name, bool must_exist)
{
	struct say_channel *res = NULL;
	struct say_channel *ch;

	if (must_exist && !default_channel)
		return NULL;

	if (cannot_schedule()) {
		printk(KERN_ERR "trying to make channel in atomic\n");
		return NULL;
	}

	down_read(&say_mutex);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		if (!strcmp(ch->ch_name, name)) {
			res = ch;
			break;
		}
	}
	up_read(&say_mutex);

	if (unlikely(!res)) {
		res = _make_channel(name, must_exist);
		if (unlikely(!res))
			goto done;

		down_write(&say_mutex);

		for (ch = channel_list; ch; ch = ch->ch_next) {
			if (ch != res && unlikely(!strcmp(ch->ch_name, name))) {
				up_write(&say_mutex);
				_del_channel(res);
				res = ch;
				goto done;
			}
		}
		res->ch_next = channel_list;
		channel_list = res;

		up_write(&say_mutex);
	}

done:
	return res;
}
EXPORT_SYMBOL_GPL(make_channel);

// tell gcc to check for varargs errors
static
void _say(struct say_channel *ch, int class, va_list args, bool use_args, const char *fmt, ...)  __attribute__ ((format (printf, 5, 6)));

static
void _say(struct say_channel *ch, int class, va_list args, bool use_args, const char *fmt, ...)
{
	char *start;
	int offset;
	int rest;
	int written;

	if (!default_channel)
		return;

	if (unlikely(!ch))
		return;
	if (unlikely(ch->ch_delete && ch != default_channel)) {
		say_to(default_channel, SAY_ERROR, "thread '%s' tried to write on deleted channel\n", current->comm);
		return;
	}

	offset = ch->ch_index[class];
	start = ch->ch_buf[class][0] + offset;
	rest = SAY_BUFMAX - 1 - offset;
	if (unlikely(rest <= 0)) {
		ch->ch_overflow[class]++;
		return;
	}

	if (use_args) {
		va_list args2; 
		va_start(args2, fmt);
		written = vscnprintf(start, rest, fmt, args2);
		va_end(args2);
	} else {
		written = vscnprintf(start, rest, fmt, args);
	}

	if (likely(rest > written)) {
		start[written] = '\0';
		ch->ch_index[class] += written;
		say_dirty = true;
	} else {
		// indicate overflow
		start[0] = '\0';
		ch->ch_overflow[class]++;
	}
}

void say_to(struct say_channel *ch, int class, const char *fmt, ...)
{
	va_list args;
	unsigned long flags;

	if (!default_channel)
		return;

	if (!class && !brick_say_debug)
		return;

	if (!ch) {
		ch = find_channel(current);
	}

	if (ch && ch != default_channel) {
		if (!ch->ch_is_dir)
			class = SAY_TOTAL;
		if (likely(class >= 0 && class < MAX_SAY_CLASS)) {
			wait_channel(ch, class);
			spin_lock_irqsave(&ch->ch_lock[class], flags);

			va_start(args, fmt);
			_say(ch, class, args, false, fmt);
			va_end(args);

			spin_unlock_irqrestore(&ch->ch_lock[class], flags);
		}
	}

	ch = default_channel;
	if (likely(ch)) {
		class = SAY_TOTAL;
		wait_channel(ch, class);
		spin_lock_irqsave(&ch->ch_lock[class], flags);
		
		va_start(args, fmt);
		_say(ch, class, args, false, fmt);
		va_end(args);

		spin_unlock_irqrestore(&ch->ch_lock[class], flags);

		brick_wake_smp(&say_event);
	}
}
EXPORT_SYMBOL_GPL(say_to);

void brick_say_to(struct say_channel *ch, int class, bool dump, const char *prefix, const char *file, int line, const char *func, const char *fmt, ...) 
{
	const char *channel_name = "-";
	struct lamport_time s_now;
	struct lamport_time l_now;
	int filelen;
	int orig_class;
	va_list args;
	unsigned long flags;

	if (!default_channel)
		return;

	if (!class && !brick_say_debug)
		return;

	get_lamport(&s_now, &l_now);

	if (!ch) {
		ch = find_channel(current);
	}

	orig_class = class;

	// limit the filename
	filelen = strlen(file);
	if (filelen > MAX_FILELEN)
		file += filelen - MAX_FILELEN;
	
	if (likely(ch)) {
		channel_name = ch->ch_name;
		if (!ch->ch_is_dir)
			class = SAY_TOTAL;
		if (likely(class >= 0 && class < MAX_SAY_CLASS)) {
			wait_channel(ch, class);
			spin_lock_irqsave(&ch->ch_lock[class], flags);
#ifdef MARS_OLD_SAY_REPORTING /* to disappear */
			/* No longer print the same info twice during the lock.
			 * Anyway, this code should vanish some day.
			 */
			_say(ch, class, NULL, true,
			     "%lld.%09ld %lld.%09ld %s %s[%d] %s:%d %s(): ",
			     (s64)s_now.tv_sec, s_now.tv_nsec,
			     (s64)l_now.tv_sec, l_now.tv_nsec,
			     prefix,
			     current->comm, (int)smp_processor_id(),
			     file, line,
			     func);
#endif
			va_start(args, fmt);
			_say(ch, class, args, false, fmt);
			va_end(args);
			
			spin_unlock_irqrestore(&ch->ch_lock[class], flags);
		}
	}

	ch = default_channel;
	if (likely(ch)) {
		wait_channel(ch, SAY_TOTAL);
		spin_lock_irqsave(&ch->ch_lock[SAY_TOTAL], flags);
#ifdef MARS_OLD_SAY_REPORTING /* to disappear */
			/* No longer print the same info twice during the lock.
			 * Anyway, this code should vanish some day.
			 */
		_say(ch, SAY_TOTAL, NULL, true,
		     "%lld.%09ld %lld.%09ld %s_%-5s %s %s[%d] %s:%d %s(): ",
		     (s64)s_now.tv_sec, s_now.tv_nsec,
		     (s64)l_now.tv_sec, l_now.tv_nsec,
		     prefix, say_class[orig_class],
		     channel_name,
		     current->comm, (int)smp_processor_id(),
		     file, line,
		     func);
#endif
		va_start(args, fmt);
		_say(ch, SAY_TOTAL, args, false, fmt);
		va_end(args);

		spin_unlock_irqrestore(&ch->ch_lock[SAY_TOTAL], flags);

	}
#ifdef CONFIG_MARS_DEBUG
	if (dump)
		brick_dump_stack();
#endif
	brick_wake_smp(&say_event);
}
EXPORT_SYMBOL_GPL(brick_say_to);

static
void try_open_file(struct file **file, char *filename, bool creat)
{
	struct address_space *mapping;
	int flags = O_APPEND | O_WRONLY | O_LARGEFILE;
	int prot = 0600;

	if (creat)
		flags |= O_CREAT;

	*file = filp_open(filename, flags, prot);
	if (unlikely(IS_ERR(*file))) {
		*file = NULL;
	} else if ((mapping = (*file)->f_mapping)) {
		mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));
	}
}

static
void out_to_file(struct file *file, char *buf, int len)
{
	loff_t log_pos = 0;

	if (file) {
#ifdef MARS_HAS_KERNEL_READ
	  (void)kernel_write(file,
			     buf,
			     len,
			     &log_pos);
#else
#ifdef MARS_NEEDS_KERNEL_DS
		mm_segment_t oldfs = get_fs();

		set_fs(KERNEL_DS);
#endif
		(void)vfs_write(file, buf, len, &log_pos);
#ifdef MARS_NEEDS_KERNEL_DS
		set_fs(oldfs);
#endif
#endif
	}
}

static inline
void reset_flood(void)
{
	if (flood_start_jiffies &&
	    (long)jiffies >= (long)(flood_start_jiffies + brick_say_syslog_flood_recovery * HZ)) {
		flood_start_jiffies = 0;
		flood_count = 0;
	}
}

static
void out_to_syslog(int class, char *buf, int len)
{
	reset_flood();
	if (class >= brick_say_syslog_min && class <= brick_say_syslog_max) {
		buf[len] = '\0';
		printk("%s", buf);
	} else if (class >= brick_say_syslog_flood_class && brick_say_syslog_flood_class >= 0 && class != SAY_TOTAL) {
		flood_start_jiffies = jiffies;
		if (++flood_count <= brick_say_syslog_flood_limit) {
			buf[len] = '\0';
			printk("%s", buf);
		}
	}
}

static inline
char *_make_filename(struct say_channel *ch, int class, int transact, int add_tmp)
{
	char *filename;

restart:
	filename = kmalloc(1024, GFP_KERNEL);
	if (unlikely(!filename)) {
		cond_resched();
		goto restart;
	}
	atomic_inc(&say_alloc_names);
	if (ch->ch_is_dir) {
		snprintf(filename, 1023, "%s/%d.%s.%s%s",
			 ch->ch_name, class, say_class[class],
			 transact ? "status" : "log",
			 add_tmp ? ".tmp" : "");
	} else {
		snprintf(filename, 1023, "%s.%s%s",
			 ch->ch_name,
			 transact ? "status" : "log",
			 add_tmp ? ".tmp" : "");
	}
	return filename;
}

static
void _rollover_channel(struct say_channel *ch)
{
	int start = 0;
	int class;

	ch->ch_rollover = false;
	ch->ch_status_written = 0;

	if (!ch->ch_is_dir)
		start = SAY_TOTAL;

	for (class = start; class < MAX_SAY_CLASS; class++) {
		char *old = _make_filename(ch, class, 1, 1);
		char *new = _make_filename(ch, class, 1, 0);
		
		if (likely(old && new)) {
			int i;
#ifdef MARS_NEEDS_KERNEL_DS
			mm_segment_t oldfs;
#endif
			
			for (i = 0; i < 2; i++) {
				if (ch->ch_filp[class][i]) {
					filp_close(ch->ch_filp[class][i], NULL);
					ch->ch_filp[class][i] = NULL;
				}
			}
			
#ifdef MARS_NEEDS_KERNEL_DS
			oldfs = get_fs();
			set_fs(KERNEL_DS);
#endif
#if defined(MARS_HAS_PREPATCH_V2) ||		\
	defined(MARS_HAS_PREPATCH_V3)
			mars_rename(old, new);
#elif defined(MARS_HAS_PREPATCH)
			sys_rename(old, new);
#elif defined(MARS_NEEDS_OLDCOMPAT_FUNCTIONS)
			__oldcompat_rename(old, new);
#else
#error Build Error - check the sources and/or the pre-patch version
#endif
#ifdef MARS_NEEDS_KERNEL_DS
			set_fs(oldfs);
#endif
		}
		
		if (likely(old)) {
			kfree(old);
			atomic_dec(&say_alloc_names);
		}
		if (likely(new)) {
			kfree(new);
			atomic_dec(&say_alloc_names);
		}
	}
}

static
void treat_channel(struct say_channel *ch, int class)
{
	int len;
	int overflow;
	int transact;
	int start;
	char *buf;
	char *tmp;
	unsigned long flags;

	spin_lock_irqsave(&ch->ch_lock[class], flags);

	buf = ch->ch_buf[class][0];
	tmp = ch->ch_buf[class][1];
	ch->ch_buf[class][1] = buf;
	ch->ch_buf[class][0] = tmp;
	len = ch->ch_index[class];
	ch->ch_index[class] = 0;
	overflow = ch->ch_overflow[class];
	ch->ch_overflow[class] = 0;

	spin_unlock_irqrestore(&ch->ch_lock[class], flags);

	brick_wake_smp(&ch->ch_progress);

	ch->ch_status_written += len;
	out_to_syslog(class, buf, len);
	start = 0;
	if (!brick_say_logging)
		start++;
	for (transact = start; transact < 2; transact++) {
		if (unlikely(!ch->ch_filp[class][transact])) {
			char *filename = _make_filename(ch, class, transact, transact);
			if (likely(filename)) {
				try_open_file(&ch->ch_filp[class][transact], filename, transact);
				kfree(filename);
				atomic_dec(&say_alloc_names);
			}
		}
		out_to_file(ch->ch_filp[class][transact], buf, len);
	}

	if (unlikely(overflow > 0)) {
		struct lamport_time s_now;
		struct lamport_time l_now;

		get_lamport(&s_now, &l_now);
		len = scnprintf(buf,
			       SAY_BUFMAX,
			       "%lld.%09ld %lld.%09ld %s %d OVERFLOW %d times\n",
				(s64)s_now.tv_sec, s_now.tv_nsec,
				(s64)l_now.tv_sec, l_now.tv_nsec,
			       ch->ch_name,
			       class,
			       overflow);
		ch->ch_status_written += len;
		out_to_syslog(class, buf, len);
		for (transact = 0; transact < 2; transact++) {
			out_to_file(ch->ch_filp[class][transact], buf, len);
		}
	}
}

static
int _say_thread(void *data)
{
	while (!kthread_should_stop()) {
		struct say_channel *ch;
		int i;

		brick_wait_smp(say_event, say_dirty, HZ);
		say_dirty = false;
		
	restart_rollover:
		down_read(&say_mutex);
		for (ch = channel_list; ch; ch = ch->ch_next) {
			if (ch->ch_rollover && ch->ch_status_written > 0) {
				up_read(&say_mutex);
				_rollover_channel(ch);
				goto restart_rollover;
			}
		}
		up_read(&say_mutex);

	restart:
		down_read(&say_mutex);
		for (ch = channel_list; ch; ch = ch->ch_next) {
			int start = 0;
			if (!ch->ch_is_dir)
				start = SAY_TOTAL;
			for (i = start; i < MAX_SAY_CLASS; i++) {
				if (ch->ch_index[i] > 0) {
					up_read(&say_mutex);
					treat_channel(ch, i);
					goto restart;
				}
			}
			if (ch->ch_delete) {
				up_read(&say_mutex);
				_del_channel(ch);
				goto restart;
			}
		}
		up_read(&say_mutex);
	}

	return 0;
}

void init_say(void)
{
	/* Only initialize once */
	if (default_channel)
		return;

	default_channel = make_channel(CONFIG_MARS_LOGDIR, false);
	if (!default_channel)
		return;

	if (!say_thread)
		say_thread = kthread_create(_say_thread, NULL, "brick_say");
	if (IS_ERR(say_thread)) {
		say_thread = NULL;
	} else {
		get_task_struct(say_thread);
		wake_up_process(say_thread);
	}

}
EXPORT_SYMBOL_GPL(init_say);

void exit_say(void)
{
	int memleak_channels;
	int memleak_names;
	int memleak_pages;

	if (say_thread) {
		kthread_stop(say_thread);
		put_task_struct(say_thread);
		say_thread = NULL;
	}

	default_channel = NULL;
	while (channel_list) {
		_del_channel(channel_list);
	}

	memleak_channels = atomic_read(&say_alloc_channels);
	memleak_names = atomic_read(&say_alloc_names);
	memleak_pages = atomic_read(&say_alloc_pages);
	if (unlikely(memleak_channels || memleak_names || memleak_pages)) {
		printk("MEMLEAK: channels=%d names=%d pages=%d\n", memleak_channels, memleak_names, memleak_pages);
	}
}
EXPORT_SYMBOL_GPL(exit_say);

#ifdef CONFIG_MARS_DEBUG

static int dump_max = 5;

void brick_dump_stack(void)
{
	if (dump_max > 0) {
		dump_max--; // racy, but does no harm
		dump_stack();
	}
}
EXPORT_SYMBOL(brick_dump_stack);

#endif

#endif /* CONFIG_MARS_DEBUG_DEVEL_VIA_SAY */
