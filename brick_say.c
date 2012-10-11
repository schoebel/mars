// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>


#include "brick_say.h"

/////////////////////////////////////////////////////////////////////

// messaging

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/hardirq.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>

#ifndef GFP_BRICK
#define GFP_BRICK GFP_NOIO
#endif

#define SAY_ORDER 0
#define SAY_BUFMAX (PAGE_SIZE << SAY_ORDER)
#define MAX_FILELEN 16
#define MAX_IDS 64

char *say_class[MAX_SAY_CLASS] = {
	[SAY_DEBUG] = "debug",
	[SAY_INFO] = "info",
	[SAY_WARN] = "warn",
	[SAY_ERROR] = "error",
	[SAY_FATAL] = "fatal",
	[SAY_TOTAL] = "total",
};

struct say_channel {
	char *ch_name;
	struct say_channel *ch_next;
	struct say_channel *ch_transact;
	spinlock_t ch_lock[MAX_SAY_CLASS];
	char *ch_buf[MAX_SAY_CLASS][2];
	short ch_index[MAX_SAY_CLASS][2];
	struct file *ch_filp[MAX_SAY_CLASS];
	int ch_overflow[MAX_SAY_CLASS];
	bool ch_written[MAX_SAY_CLASS];
	int ch_id_max;
	void *ch_ids[MAX_IDS];
};

struct say_channel *default_channel = NULL;
EXPORT_SYMBOL_GPL(default_channel);

static struct say_channel *channel_list = NULL;

static rwlock_t say_lock = __RW_LOCK_UNLOCKED(say_lock);

static struct task_struct *say_thread = NULL;

static DECLARE_WAIT_QUEUE_HEAD(say_event);

bool say_dirty = false;

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

void bind_to_channel(struct say_channel *ch, struct task_struct *whom)
{
	int i;
	write_lock(&say_lock);
	for (i = 0; i < ch->ch_id_max; i++) {
		if (!ch->ch_ids[i]) {
			ch->ch_ids[i] = whom;
			goto done;
		}
	}
	if (likely(ch->ch_id_max < MAX_IDS - 1)) {
		ch->ch_ids[ch->ch_id_max++] = current;
	} else {
		say_to(default_channel, SAY_ERROR, "ID overflow for thread '%s'\n", current->comm);
	}
done:
	write_unlock(&say_lock);
}
EXPORT_SYMBOL_GPL(bind_to_channel);

void remove_binding(struct task_struct *whom)
{
	struct say_channel *ch;
	int i;

	write_lock(&say_lock);
	for (ch = channel_list; ch; ch = ch->ch_next) {
		for (i = 0; i < ch->ch_id_max; i++) {
			if (ch->ch_ids[i] == whom) {
				ch->ch_ids[i] = NULL;
			}
		}
	}
	write_unlock(&say_lock);
}
EXPORT_SYMBOL_GPL(remove_binding);

static
void del_channel(struct say_channel *ch)
{
	struct say_channel *tmp;
	struct say_channel **_tmp;

	write_lock(&say_lock);
	for (_tmp = &channel_list; (tmp = *_tmp) != NULL; _tmp = &tmp->ch_next) {
		if (tmp == ch) {
			*_tmp = tmp->ch_next;
			break;
		}
	}
	write_unlock(&say_lock);

	while (ch) {
		int i, j;
		for (i = 0; i < MAX_SAY_CLASS; i++) {
			if (ch->ch_filp[i]) {
				filp_close(ch->ch_filp[i], NULL);
			}
			for (j = 0; j < 2; j++) {
				char *buf = ch->ch_buf[i][j];
				if (buf)
					__free_pages(virt_to_page((unsigned long)buf), SAY_ORDER);
			}
		}
		tmp = ch;
		ch = ch->ch_transact;
		kfree(tmp);
	}
}

static
struct say_channel *_make_channel(const char *name)
{
	struct say_channel *res = NULL;
	int i, j;
	bool use_atomic = (preempt_count() & (SOFTIRQ_MASK | HARDIRQ_MASK | NMI_MASK)) != 0 || in_atomic() || irqs_disabled();
	unsigned long mode = use_atomic ? GFP_ATOMIC : GFP_BRICK;
	
	res = kzalloc(sizeof(struct say_channel), mode);
	if (unlikely(!res)) {
		goto done;
	}
	res->ch_name = kstrdup(name, mode);
	if (unlikely(!res->ch_name)) {
		kfree(res);
		goto done;
	}
	for (i = 0; i < MAX_SAY_CLASS; i++) {
		spin_lock_init(&res->ch_lock[i]);
		for (j = 0; j < 2; j++) {
			char *buf = (void*)__get_free_pages(mode, SAY_ORDER);
			if (unlikely(!buf)) {
				del_channel(res);
				res = NULL;
				goto done;
			}
			res->ch_buf[i][j] = buf;
		}
	}
done:
	return res;
}

struct say_channel *make_channel(const char *name)
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
		res = _make_channel(name);
		if (unlikely(!res))
			goto done;

		res->ch_transact = _make_channel(name);
		if (unlikely(!res->ch_transact)) {
			del_channel(res);
			res = NULL;
			goto done;
		}

		write_lock(&say_lock);

		for (ch = channel_list; ch; ch = ch->ch_next) {
			if (unlikely(!strcmp(ch->ch_name, name))) {
				del_channel(res);
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
EXPORT_SYMBOL_GPL(make_channel);

// tell gcc to check for varargs errors
static
void _say(struct say_channel *ch, int class, va_list args, bool use_args, const char *fmt, ...)  __attribute__ ((format (printf, 5, 6)));

static
void _say(struct say_channel *ch, int class, va_list args, bool use_args, const char *fmt, ...)
{
	char *start;
	int rest;
	int written;

	if (!ch) {
		ch = find_channel(current);
	}
	if (!ch)
		return;

	start = ch->ch_buf[class][0] + ch->ch_index[class][0];
	rest = SAY_BUFMAX - 1 - ch->ch_index[class][0];
	if (unlikely(rest <= 0)) {
		ch->ch_overflow[class]++;
		return;
	}

	if (use_args) {
		va_list args2; 
		va_start(args2, fmt);
		written = vsnprintf(start, rest, fmt, args2);
		va_end(args2);
	} else {
		written = vsnprintf(start, rest, fmt, args);
	}

	if (likely(rest > written)) {
		start[written] = '\0';
		ch->ch_index[class][0] += written;
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

	if (!ch) {
		ch = find_channel(current);
	}

	if (likely(ch)) {
		if (likely(class >= 0 && class < MAX_SAY_CLASS)) {
			spin_lock_irqsave(&ch->ch_lock[class], flags);

			va_start(args, fmt);
			_say(ch, class, args, false, fmt);
			va_end(args);

			spin_unlock_irqrestore(&ch->ch_lock[class], flags);
		}

		class = SAY_TOTAL;
		spin_lock_irqsave(&ch->ch_lock[class], flags);
		
		va_start(args, fmt);
		_say(ch, class, args, false, fmt);
		va_end(args);

		va_start(args, fmt);
		_say(ch->ch_transact, class, args, false, fmt);
		va_end(args);
		
		spin_unlock_irqrestore(&ch->ch_lock[class], flags);

		wake_up_interruptible(&say_event);
	}
}
EXPORT_SYMBOL_GPL(say_to);

void brick_say_to(struct say_channel *ch, int class, bool dump, const char *prefix, const char *file, int line, const char *func, const char *fmt, ...) 
{
	struct timespec now = CURRENT_TIME;
	int filelen;
	va_list args;
	unsigned long flags;

	if (!ch) {
		ch = find_channel(current);
	}

	// limit the filename
	filelen = strlen(file);
	if (filelen > MAX_FILELEN)
		file += filelen - MAX_FILELEN;
	
	for (; ch; ch = ch->ch_transact) {
		if (likely(class >= 0 && class < MAX_SAY_CLASS)) {
			spin_lock_irqsave(&ch->ch_lock[class], flags);
			
			_say(ch, class, NULL, true, "%ld.%09ld %s %s[%d] %s %d %s(): ", now.tv_sec, now.tv_nsec, prefix, current->comm, (int)smp_processor_id(), file, line, func);
			va_start(args, fmt);
			_say(ch, class, args, false, fmt);
			va_end(args);
			
			spin_unlock_irqrestore(&ch->ch_lock[class], flags);
		}

		spin_lock_irqsave(&ch->ch_lock[SAY_TOTAL], flags);

		_say(ch, SAY_TOTAL, NULL, true, "%ld.%09ld %s_%-5s %s[%d] %s %d %s(): ", now.tv_sec, now.tv_nsec, prefix, say_class[class], current->comm, (int)smp_processor_id(), file, line, func);
		va_start(args, fmt);
		_say(ch, SAY_TOTAL, args, false, fmt);
		va_end(args);

		spin_unlock_irqrestore(&ch->ch_lock[SAY_TOTAL], flags);

		wake_up_interruptible(&say_event);
	}
#ifdef CONFIG_MARS_DEBUG
	if (dump)
		brick_dump_stack();
#endif
}
EXPORT_SYMBOL_GPL(brick_say_to);

const char *proc_say_get(int class, int *len)
{
	struct say_channel *ch;
	if (likely(class >= 0 && class < MAX_SAY_CLASS &&
		   default_channel && (ch = default_channel->ch_transact))) {
		*len = ch->ch_index[class][1];
		return ch->ch_buf[class][1];
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(proc_say_get);

void proc_say_commit(void)
{
	struct say_channel *ch;
	if (likely(default_channel && (ch = default_channel->ch_transact))) {
		int class;
		for (class = 0; class < MAX_SAY_CLASS; class++) {
			char *tmp;
			unsigned long flags;

			spin_lock_irqsave(&ch->ch_lock[class], flags);

			tmp = ch->ch_buf[class][1];
			ch->ch_buf[class][1] = ch->ch_buf[class][0];
			ch->ch_buf[class][0] = tmp;
			ch->ch_index[class][1] = ch->ch_index[class][0];
			ch->ch_index[class][0] = 0;
			ch->ch_written[class] = false;

			spin_unlock_irqrestore(&ch->ch_lock[class], flags);
		}
	}
}
EXPORT_SYMBOL_GPL(proc_say_commit);

static
void try_open_file(struct file **file, char *filename, bool creat)
{
	int flags = O_APPEND | O_WRONLY | O_LARGEFILE;
	int prot = 0600;

	if (creat)
		flags |= O_CREAT | O_TRUNC;

	*file = filp_open(filename, flags, prot);
	if (unlikely(IS_ERR(*file))) {
		*file = NULL;
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
#ifdef CONFIG_MARS_USE_SYSLOG
	} else {
		printk("%s", buf);
#endif
	}
}

static
void treat_channel(struct say_channel *ch, int class, bool transact)
{
	int len;
	int overflow;
	char *buf;
	char *tmp;
	unsigned long flags;

	if (unlikely(!ch->ch_filp[class])) {
		char *filename = kmalloc(1024, GFP_KERNEL);
		if (unlikely(!filename))
			return;

		snprintf(filename, 1023, "%s/%d.%s.%s", ch->ch_name, class, say_class[class], transact ? "status" : "log");
		try_open_file(&ch->ch_filp[class], filename, transact);
		kfree(filename);
	}

	spin_lock_irqsave(&ch->ch_lock[class], flags);

	if (transact) {
		buf = ch->ch_buf[class][1];
		len = ch->ch_index[class][1];
	} else {
		buf = ch->ch_buf[class][0];
		tmp = ch->ch_buf[class][1];
		ch->ch_buf[class][1] = buf;
		ch->ch_buf[class][0] = tmp;
		len = ch->ch_index[class][0];
		ch->ch_index[class][0] = 0;
	}
	overflow = ch->ch_overflow[class];
	ch->ch_overflow[class] = 0;

	spin_unlock_irqrestore(&ch->ch_lock[class], flags);

	out_to_file(ch->ch_filp[class], buf, len);

	if (unlikely(overflow > 0)) {
		struct timespec now = CURRENT_TIME;
		len = snprintf(buf, SAY_BUFMAX, "%ld.%09ld OVERFLOW %d times\n", now.tv_sec, now.tv_nsec, overflow);
		out_to_file(ch->ch_filp[class], buf, len);
	}

	if (transact && ch->ch_filp[class]) {
		filp_close(ch->ch_filp[class], NULL);
		ch->ch_filp[class] = NULL;
	}
}

static
int _say_thread(void *data)
{
	while (!kthread_should_stop()) {
		struct say_channel *ch;
		struct say_channel *tmp;
		int i;

		wait_event_interruptible_timeout(say_event, say_dirty, HZ);
		say_dirty = false;

	restart:
		ch = NULL;
		read_lock(&say_lock);
		for (tmp = channel_list; tmp; tmp = tmp->ch_next) {
			for (i = 0; i < MAX_SAY_CLASS; i++) {
				if (likely(tmp->ch_transact) &&
				    unlikely(!tmp->ch_transact->ch_written[i])) {
					treat_channel(tmp->ch_transact, i, true);
					tmp->ch_transact->ch_written[i] = true;
				}
				if (tmp->ch_index[i][0] > 0) {
					ch = tmp;
					break;
				}
			}
		}
		read_unlock(&say_lock);

		if (ch) {
			treat_channel(ch, i, false);
			goto restart;
		}
	}

	return 0;
}

void init_say(void)
{
	default_channel = make_channel("/mars");
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
	if (say_thread) {
		kthread_stop(say_thread);
		put_task_struct(say_thread);
		say_thread = NULL;
	}

	default_channel = NULL;
	while (channel_list) {
		del_channel(channel_list);
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
