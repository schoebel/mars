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

#include <asm/uaccess.h>

#ifndef GFP_BRICK
#define GFP_BRICK GFP_NOIO
#endif

#define SAY_ORDER 0
#define SAY_BUFMAX (PAGE_SIZE << SAY_ORDER)
#define MAX_FILELEN 16

static char *say_buf[NR_CPUS] = {};
static int say_index[NR_CPUS] = {};
static int dump_max = 5;
static atomic_t overflow = ATOMIC_INIT(0);

static spinlock_t proc_lock = __SPIN_LOCK_UNLOCKED(proc_lock);
static char *proc_buf1[MAX_SAY_CLASS] = {};
static char *proc_buf2[MAX_SAY_CLASS] = {};
static int proc_index1[MAX_SAY_CLASS] = {};
static int proc_index2[MAX_SAY_CLASS] = {};
static long long proc_stamp[MAX_SAY_CLASS] = {};

static struct file *log_file = NULL;

const char *proc_say_get(int class, int *len)
{
	*len = 0;
	if (class >= 0 && class < MAX_SAY_CLASS) {
		*len = proc_index2[class];
		return proc_buf2[class];
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(proc_say_get);

void proc_say_commit(void)
{
	unsigned long flags;
	int class;
	
	spin_lock_irqsave(&proc_lock, flags);

	for (class = 0; class < MAX_SAY_CLASS; class++) {
		char *tmp = proc_buf1[class];
		if (!tmp || (!proc_index1[class] && proc_stamp[class] - (long long)jiffies < 60 * HZ))
			continue;
		proc_buf1[class] = proc_buf2[class];
		proc_buf2[class] = tmp;
		proc_index2[class] = proc_index1[class];
		proc_index1[class] = 0;
		proc_stamp[class] = jiffies;
	}

	spin_unlock_irqrestore(&proc_lock, flags);
}
EXPORT_SYMBOL_GPL(proc_say_commit);

static inline
void say_alloc(unsigned long cpu, bool use_atomic)
{
	char *ptr;
	if (likely(say_buf[cpu]) || unlikely(cpu >= NR_CPUS))
		goto done;

	ptr = (void*)__get_free_pages(use_atomic ? GFP_ATOMIC : GFP_BRICK, SAY_ORDER);
	if (likely(ptr)) {
		ptr[0] = '\0';
		say_buf[cpu] = ptr;
		say_index[cpu] = 0;
	}

done: ;
}

static
void _say_mark(unsigned long cpu)
{
	char *ptr;
	bool use_atomic = (preempt_count() & (SOFTIRQ_MASK | HARDIRQ_MASK | NMI_MASK)) != 0 || in_atomic() || irqs_disabled();

	say_alloc(cpu, use_atomic);
	if (unlikely(use_atomic || cpu >= NR_CPUS))
		goto done;

	ptr = say_buf[cpu];
	if (unlikely(!ptr) || !ptr[0])
		goto done;
	
	if (log_file) {
		loff_t log_pos = 0;
		int rest = say_index[cpu];
		int len = 0;
		while (rest > 0) {
			int status;
			mm_segment_t oldfs;

			oldfs = get_fs();
			set_fs(get_ds());
			status = vfs_write(log_file, ptr + len, rest, &log_pos);
			set_fs(oldfs);
			if (unlikely(status <= 0))
				break;
			len += status;
			rest -= status;
		}
#ifdef CONFIG_MARS_USE_SYSLOG
	} else {
		printk("%s", ptr);
#endif
	}

	ptr[0] = '\0';
	say_index[cpu] = 0;
	
	{
		static long long old_jiffies = 0;
		if (((long long)jiffies) - old_jiffies >= HZ * 5) {
			static spinlock_t lock = __SPIN_LOCK_UNLOCKED(lock);
			bool won_the_race = false;

			spin_lock(&lock);
			if (((long long)jiffies) - old_jiffies >= HZ * 5) {
				old_jiffies = jiffies;
				won_the_race = true;
			}
			spin_unlock(&lock);
			if (won_the_race)
				check_close(CONFIG_MARS_LOGFILE, false, true);
		}
	}

done: ;
}

void say_mark(void)
{
	unsigned long cpu = get_cpu();
	_say_mark(cpu);
	put_cpu();
}
EXPORT_SYMBOL_GPL(say_mark);

static
void _say(int class, unsigned long cpu, va_list args, bool use_args, const char *fmt, ...)  __attribute__ ((format (printf, 5, 6)));
static
void _say(int class, unsigned long cpu, va_list args, bool use_args, const char *fmt, ...)
{
	char *start = NULL;
	int rest;
	int written = 0;

	if (!say_buf[cpu])
		goto done;

	rest = SAY_BUFMAX - say_index[cpu];
	if (rest <= 0)
		goto done;

	start = say_buf[cpu] + say_index[cpu];
	if (use_args) {
		/* bug in gcc: use register variable
		 * shading the parameter
		 */
		va_list args; 
		va_start(args, fmt);
		written = vsnprintf(start, rest, fmt, args);
		va_end(args);
	} else {
		written = vsnprintf(start, rest, fmt, args);
	}

	if (likely(rest > written)) {
		start[written] = '\0';
		say_index[cpu] += written;
	} else {
		// indicate overflow
		start[0] = '\0';
		written = 0;
		atomic_inc(&overflow);
	}

done:
	if (class >= 0 && class < MAX_SAY_CLASS && start && written > 0) {
		char *pstart;
		unsigned long flags;

		spin_lock_irqsave(&proc_lock, flags);

		if (!proc_buf1[class])
			goto proc_done;

		rest = SAY_BUFMAX - proc_index1[class];
		if (rest <= 0)
			goto proc_done;

		if (likely(rest > written)) {
			pstart = proc_buf1[class] + proc_index1[class];
			memcpy(pstart, start, written);
			pstart[written] = '\0';
			proc_index1[class] += written;
		}
	proc_done:
		spin_unlock_irqrestore(&proc_lock, flags);
	}
}

static inline
void _check_overflow(unsigned long cpu)
{
	int count = 0;
	atomic_xchg(&overflow, count);
	if (unlikely(count > 0)) {
		if (likely(say_index[cpu] < SAY_BUFMAX - 8)) {
			_say(0, cpu, NULL, true, "#%d#\n", count);
		}
	}
}

void say(int class, const char *fmt, ...)
{
	unsigned long cpu = get_cpu();
	va_list args;

	_say_mark(cpu);
	if (unlikely(!say_buf[cpu]))
		goto done;
	_check_overflow(cpu);

	va_start(args, fmt);
	_say(class, cpu, args, false, fmt);
	va_end(args);

	_say_mark(cpu);
done:
	put_cpu();
}
EXPORT_SYMBOL_GPL(say);

void brick_say(int class, bool dump, const char *prefix, const char *file, int line, const char *func, const char *fmt, ...) 
{
	struct timespec now = CURRENT_TIME;
	unsigned long cpu = get_cpu();
	int filelen;
	va_list args;

	_say_mark(cpu);
	if (unlikely(!say_buf[cpu]))
		goto done;
	_check_overflow(cpu);

	// limit the filename
	filelen = strlen(file);
	if (filelen > MAX_FILELEN)
		file += filelen - MAX_FILELEN;

	_say(class, cpu, NULL, true, "%ld.%09ld %s %s[%d] %s %d %s(): ", now.tv_sec, now.tv_nsec, prefix, current->comm, (int)cpu, file, line, func);
	va_start(args, fmt);
	_say(class, cpu, args, false, fmt);
	va_end(args);

	_say_mark(cpu);
#ifdef CONFIG_MARS_DEBUG
	if (dump)
		brick_dump_stack();
#endif
done:
	put_cpu();
}
EXPORT_SYMBOL_GPL(brick_say);

void check_open(const char *filename, bool must_exist)
{
	int flags = O_EXCL | O_APPEND | O_WRONLY | O_LARGEFILE;
	int prot = 0600;
	mm_segment_t oldfs;

	if (log_file)
		return;

	if (!must_exist)
		flags |= O_CREAT;

	oldfs = get_fs();
	set_fs(get_ds());
 	log_file = filp_open(filename, flags, prot);
	set_fs(oldfs);
	if (unlikely(IS_ERR(log_file))) {
		int status = PTR_ERR(log_file);
		log_file = NULL;
		say(1, "cannot open logfile '%s', status = %d\n", filename, status);
	} else {
		say(0, "opened logfile '%s' %p\n", filename, log_file);
	}
}

void check_close(const char *filename, bool force, bool re_open)
{
	struct kstat st = {};
	int status;

	if (!force) {
		mm_segment_t oldfs;
		oldfs = get_fs();
		set_fs(get_ds());
		status = vfs_stat((char*)filename, &st);
		set_fs(oldfs);
		force = (status < 0 || !st.size);
	}
	
	if (force) {
		if (log_file) {
			struct file *old;
			say(0, "closing logfile....\n");
			old = log_file;
			log_file = NULL;
			// FIXME: this may race against vfs_write(). Use rcu here.
			filp_close(old, NULL);
			say(0, "closed logfile.\n");
		}
		if (re_open)
			check_open(filename, true);
	}
}

void init_say(void)
{
	int i;
	for (i = 0; i < MAX_SAY_CLASS; i++) {
		proc_buf1[i] = (void*)__get_free_pages(GFP_KERNEL, SAY_ORDER);
		proc_buf2[i] = (void*)__get_free_pages(GFP_KERNEL, SAY_ORDER);
	}
	check_open(CONFIG_MARS_LOGFILE, true);
}
EXPORT_SYMBOL_GPL(init_say);

void exit_say(void)
{
	int i;
	for (i = 0; i < NR_CPUS; i++) {
		if (!say_buf[i])
			continue;
		__free_pages(virt_to_page((unsigned long)say_buf[i]), SAY_ORDER);
		say_buf[i] = NULL;
	}
	check_close(CONFIG_MARS_LOGFILE, true, false);
	for (i = 0; i < MAX_SAY_CLASS; i++) {
		if (proc_buf1[i])
			__free_pages(virt_to_page((unsigned long)proc_buf1[i]), SAY_ORDER);
		if (proc_buf2[i])
			__free_pages(virt_to_page((unsigned long)proc_buf2[i]), SAY_ORDER);
		proc_buf1[i] = NULL;
		proc_buf2[i] = NULL;
	}
}
EXPORT_SYMBOL_GPL(exit_say);

#ifdef CONFIG_MARS_DEBUG

void brick_dump_stack(void)
{
	if (dump_max > 0) {
		dump_max--; // racy, but does no harm
		dump_stack();
	}
}
EXPORT_SYMBOL(brick_dump_stack);

#endif

