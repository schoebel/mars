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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>


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

#include <linux/uaccess.h>

#include "compat.h"

#ifndef GFP_BRICK
#define GFP_BRICK GFP_NOIO
#endif

#define SAY_ORDER 0
#define SAY_BUFMAX (PAGE_SIZE << SAY_ORDER)
#define SAY_BUF_LIMIT (SAY_BUFMAX - 1500)
#define MAX_FILELEN 16
#define MAX_IDS 1000

const char *say_class[MAX_SAY_CLASS] = {
	[SAY_DEBUG] = "debug",
	[SAY_INFO] = "info",
	[SAY_WARN] = "warn",
	[SAY_ERROR] = "error",
	[SAY_FATAL] = "fatal",
	[SAY_TOTAL] = "total",
};

int brick_say_logging = 1;
module_param_named(say_logging, brick_say_logging, int, 0);
int brick_say_debug;
module_param_named(say_debug, brick_say_debug, int, 0);

int brick_say_syslog_min = 1;
int brick_say_syslog_max = -1;
int brick_say_syslog_flood_class = 3;
int brick_say_syslog_flood_limit = 20;
int brick_say_syslog_flood_recovery = 300;
int delay_say_on_overflow =
#ifdef CONFIG_MARS_DEBUG
	1;
#else
	0;
#endif

static atomic_t say_alloc_channels = ATOMIC_INIT(0);
static atomic_t say_alloc_names = ATOMIC_INIT(0);
static atomic_t say_alloc_pages = ATOMIC_INIT(0);

static unsigned long flood_start_jiffies;
static int flood_count;

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

struct say_channel *default_channel;

static struct say_channel *channel_list;

static rwlock_t say_lock = __RW_LOCK_UNLOCKED(say_lock);

static struct task_struct *say_thread;

static DECLARE_WAIT_QUEUE_HEAD(say_event);

bool say_dirty;

#define use_atomic()							\
	((preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK | HARDIRQ_MASK | NMI_MASK)) != 0 || irqs_disabled())

static
void wait_channel(struct say_channel *ch, int class)
{
	if (delay_say_on_overflow && ch->ch_index[class] > SAY_BUF_LIMIT) {
		if (!use_atomic()) {
			say_dirty = true;
			wake_up_interruptible(&say_event);
			wait_event_interruptible_timeout(ch->ch_progress, ch->ch_index[class] < SAY_BUF_LIMIT, HZ / 10);
		}
	}
}

static
struct say_channel *find_channel(const void *id)
{
	struct say_channel *res = default_channel;
	struct say_channel *ch;

	read_lock(&say_lock);
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
	read_unlock(&say_lock);
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
	write_lock(&say_lock);
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
	write_unlock(&say_lock);
	return;

err:
	write_unlock(&say_lock);

	say_to(default_channel, SAY_ERROR, "ID overflow for thread '%s'\n", whom->comm);
}

struct say_channel *get_binding(struct task_struct *whom)
{
	struct say_channel *ch;
	int i;

	read_lock(&say_lock);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		for (i = 0; i < ch->ch_id_max; i++) {
			if (ch->ch_ids[i] == whom) {
				goto found;
			}
		}
	}
	ch = NULL;
found:
	read_unlock(&say_lock);
	return ch;
}

void remove_binding_from(struct say_channel *ch, struct task_struct *whom)
{
	bool found = false;
	int i;

	write_lock(&say_lock);
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
	write_unlock(&say_lock);
}

void remove_binding(struct task_struct *whom)
{
	write_lock(&say_lock);
	_remove_binding(whom);
	write_unlock(&say_lock);
}

void rollover_channel(struct say_channel *ch)
{
	if (!ch) {
		ch = find_channel(current);
	}
	if (likely(ch))
		ch->ch_rollover = true;
}

void rollover_all(void)
{
	struct say_channel *ch;

	read_lock(&say_lock);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		ch->ch_rollover = true;
	}
	read_unlock(&say_lock);
}

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

static
void _del_channel(struct say_channel *ch)
{
	struct say_channel *tmp;
	struct say_channel **_tmp;
	int i, j;

	if (!ch)
		return;

	write_lock(&say_lock);
	for (_tmp = &channel_list; (tmp = *_tmp) != NULL; _tmp = &tmp->ch_next) {
		if (tmp == ch) {
			*_tmp = tmp->ch_next;
			break;
		}
	}
	write_unlock(&say_lock);

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
		atomic_dec(&say_alloc_names);
		kfree(ch->ch_name);
	}
	kfree(ch);
	atomic_dec(&say_alloc_channels);
}

static
struct say_channel *_make_channel(const char *name, bool must_exist)
{
	struct say_channel *res = NULL;
	struct kstat kstat = {};
	int i, j;
	unsigned long mode = use_atomic() ? GFP_ATOMIC : GFP_BRICK;
	mm_segment_t oldfs;
	bool is_dir = false;
	int status;

	oldfs = get_fs();
	set_fs(get_ds());
	status = vfs_stat((char*)name, &kstat);
	set_fs(oldfs);

	if (unlikely(status < 0)) {
		if (must_exist) {
			say(SAY_ERROR, "cannot create channel '%s', status = %d\n", name, status);
			goto done;
		}
	} else {
		is_dir = S_ISDIR(kstat.mode);
	}

restart:
	res = kzalloc(sizeof(struct say_channel), mode);
	if (unlikely(!res)) {
		schedule();
		goto restart;
	}
	atomic_inc(&say_alloc_channels);
	res->ch_must_exist = must_exist;
	res->ch_is_dir = is_dir;
	init_waitqueue_head(&res->ch_progress);
restart2:
	res->ch_name = kstrdup(name, mode);
	if (unlikely(!res->ch_name)) {
		schedule();
		goto restart2;
	}
	atomic_inc(&say_alloc_names);
	for (i = 0; i < MAX_SAY_CLASS; i++) {
		spin_lock_init(&res->ch_lock[i]);
		for (j = 0; j < 2; j++) {
			char *buf;
		restart3:
			buf = (void*)__get_free_pages(mode, SAY_ORDER);
			if (unlikely(!buf)) {
				schedule();
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

	read_lock(&say_lock);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		if (!strcmp(ch->ch_name, name)) {
			res = ch;
			break;
		}
	}
	read_unlock(&say_lock);

	if (unlikely(!res)) {
		res = _make_channel(name, must_exist);
		if (unlikely(!res))
			goto done;

		write_lock(&say_lock);

		for (ch = channel_list; ch; ch = ch->ch_next) {
			if (ch != res && unlikely(!strcmp(ch->ch_name, name))) {
				_del_channel(res);
				res = ch;
				goto race_found;
			}
		}

		res->ch_next = channel_list;
		channel_list = res;

	race_found:
		write_unlock(&say_lock);
	}

done:
	return res;
}

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

	if (!class && !brick_say_debug)
		return;

	if (!ch) {
		ch = find_channel(current);
	}

	if (likely(ch)) {
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

		wake_up_interruptible(&say_event);
	}
}

void brick_say_to(struct say_channel *ch, int class, bool dump, const char *prefix, const char *file, int line, const char *func, const char *fmt, ...) 
{
	const char *channel_name = "-";
	struct timespec s_now;
	struct timespec l_now;
	int filelen;
	int orig_class;
	va_list args;
	unsigned long flags;

	if (!class && !brick_say_debug)
		return;

	s_now = CURRENT_TIME;
	get_lamport(&l_now);

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
			
			_say(ch, class, NULL, true,
			     "%ld.%09ld %ld.%09ld %s %s[%d] %s:%d %s(): ",
			     s_now.tv_sec, s_now.tv_nsec,
			     l_now.tv_sec, l_now.tv_nsec,
			     prefix,
			     current->comm, (int)smp_processor_id(),
			     file, line,
			     func);

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

		_say(ch, SAY_TOTAL, NULL, true,
		     "%ld.%09ld %ld.%09ld %s_%-5s %s %s[%d] %s:%d %s(): ",
		     s_now.tv_sec, s_now.tv_nsec,
		     l_now.tv_sec, l_now.tv_nsec,
		     prefix, say_class[orig_class],
		     channel_name,
		     current->comm, (int)smp_processor_id(),
		     file, line,
		     func);

		va_start(args, fmt);
		_say(ch, SAY_TOTAL, args, false, fmt);
		va_end(args);

		spin_unlock_irqrestore(&ch->ch_lock[SAY_TOTAL], flags);

	}
#ifdef CONFIG_MARS_DEBUG
	if (dump)
		brick_dump_stack();
#endif
	wake_up_interruptible(&say_event);
}

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
		return;
	}
	mapping = (*file)->f_mapping;
	if (likely(mapping)) {
		mapping_set_gfp_mask(mapping, mapping_gfp_mask(mapping) & ~(__GFP_IO | __GFP_FS));
	}
}

static
void out_to_file(struct file *file, char *buf, int len)
{
	loff_t log_pos = 0;
	mm_segment_t oldfs;

	if (file) {
		oldfs = get_fs();
		set_fs(get_ds());
		(void)vfs_write(file, buf, len, &log_pos);
		set_fs(oldfs);
	}
}

static inline
void reset_flood(void)
{
	if (flood_start_jiffies &&
	    time_is_before_jiffies(flood_start_jiffies + brick_say_syslog_flood_recovery * HZ)) {
		flood_start_jiffies = 0;
		flood_count = 0;
	}
}

static
void printk_with_class(int class, char *buf)
{
	switch (class) {
	case SAY_INFO:
		printk(KERN_INFO "%s", buf);
		break;
	case SAY_WARN:
		printk(KERN_WARNING "%s", buf);
		break;
	case SAY_ERROR:
	case SAY_FATAL:
		printk(KERN_ERR "%s", buf);
		break;
	default:
		printk(KERN_DEBUG "%s", buf);
	}
}

static
void out_to_syslog(int class, char *buf, int len)
{
	reset_flood();
	if (class >= brick_say_syslog_min && class <= brick_say_syslog_max) {
		buf[len] = '\0';
		printk_with_class(class, buf);
	} else if (class >= brick_say_syslog_flood_class && brick_say_syslog_flood_class >= 0 && class != SAY_TOTAL) {
		flood_start_jiffies = jiffies;
		if (++flood_count <= brick_say_syslog_flood_limit) {
			buf[len] = '\0';
			printk_with_class(class, buf);
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
		schedule();
		goto restart;
	}
	atomic_inc(&say_alloc_names);
	if (ch->ch_is_dir) {
		snprintf(filename, 1023, "%s/%d.%s.%s%s", ch->ch_name, class, say_class[class], transact ? "status" : "log", add_tmp ? ".tmp" : "");
	} else {
		snprintf(filename, 1023, "%s.%s%s", ch->ch_name, transact ? "status" : "log", add_tmp ? ".tmp" : "");
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
			mm_segment_t oldfs;
			
			for (i = 0; i < 2; i++) {
				if (ch->ch_filp[class][i]) {
					filp_close(ch->ch_filp[class][i], NULL);
					ch->ch_filp[class][i] = NULL;
				}
			}
			
			oldfs = get_fs();
			set_fs(get_ds());
#ifdef __USE_COMPAT
			_compat_rename(old, new);
#else
			sys_rename(old, new);
#endif
			set_fs(oldfs);
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

	wake_up_interruptible(&ch->ch_progress);

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
		struct timespec s_now = CURRENT_TIME;
		struct timespec l_now;
		get_lamport(&l_now);
		len = scnprintf(buf,
			       SAY_BUFMAX,
			       "%ld.%09ld %ld.%09ld %s %d OVERFLOW %d times\n",
			       s_now.tv_sec, s_now.tv_nsec,
			       l_now.tv_sec, l_now.tv_nsec,
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

		wait_event_interruptible_timeout(say_event, say_dirty, HZ);
		say_dirty = false;
		
	restart_rollover:
		read_lock(&say_lock);
		for (ch = channel_list; ch; ch = ch->ch_next) {
			if (ch->ch_rollover && ch->ch_status_written > 0) {
				read_unlock(&say_lock);
				_rollover_channel(ch);
				goto restart_rollover;
			}
		}
		read_unlock(&say_lock);

	restart:
		read_lock(&say_lock);
		for (ch = channel_list; ch; ch = ch->ch_next) {
			int start = 0;
			if (!ch->ch_is_dir)
				start = SAY_TOTAL;
			for (i = start; i < MAX_SAY_CLASS; i++) {
				if (ch->ch_index[i] > 0) {
					read_unlock(&say_lock);
					treat_channel(ch, i);
					goto restart;
				}
			}
			if (ch->ch_delete) {
				read_unlock(&say_lock);
				_del_channel(ch);
				goto restart;
			}
		}
		read_unlock(&say_lock);
	}

	return 0;
}

void init_say(void)
{
	default_channel = make_channel(CONFIG_MARS_LOGDIR, true);
	say_thread = kthread_create(_say_thread, NULL, "brick_say");
	if (IS_ERR(say_thread)) {
		say_thread = NULL;
	} else {
		get_task_struct(say_thread);
		wake_up_process(say_thread);
	}

}

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

#ifdef CONFIG_MARS_DEBUG

static int dump_max = 5;

void brick_dump_stack(void)
{
	if (dump_max > 0) {
		dump_max--; // racy, but does no harm
		dump_stack();
	}
}

#endif
