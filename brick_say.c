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

#define SAY_ORDER 0
#define SAY_BUFMAX (PAGE_SIZE << SAY_ORDER)
#define MAX_FILELEN 16

static char *say_buf[NR_CPUS] = {};
static int say_index[NR_CPUS] = {};
static int dump_max = 5;
static atomic_t overflow = ATOMIC_INIT(0);

static struct file *log_file = NULL;

static inline
void say_alloc(unsigned long cpu, bool use_atomic)
{
	if (cpu >= NR_CPUS || say_buf[cpu])
		goto done;

	say_buf[cpu] = (void*)__get_free_pages(use_atomic? GFP_ATOMIC : GFP_KERNEL, SAY_ORDER);
	if (likely(say_buf[cpu])) {
		say_buf[cpu][0] = '\0';
		say_index[cpu] = 0;
	}

done: ;
}

static inline
void _say_mark(unsigned long cpu)
{
	bool use_atomic = (preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK | HARDIRQ_MASK)) != 0;

	say_alloc(cpu, use_atomic);
	if (use_atomic || cpu >= NR_CPUS)
		goto done;


	if (!say_buf[cpu] ||
	    !say_buf[cpu][0])
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
			status = vfs_write(log_file, say_buf[cpu] + len, rest, &log_pos);
			set_fs(oldfs);
			if (status <= 0)
				break;
			len += status;
			rest -= status;
		}
#ifdef CONFIG_MARS_USE_SYSLOG
	} else {
		printk("%s", say_buf[cpu]);
#endif
	}

	say_buf[cpu][0] = '\0';
	say_index[cpu] = 0;
	
	{
		static long long old_jiffies = 0;
		if (((long long)jiffies) - old_jiffies >= HZ * 5) {
			static spinlock_t lock = SPIN_LOCK_UNLOCKED;
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
void _say(unsigned long cpu, va_list args, bool use_args, const char *fmt, ...)
{
	char *start;
	int rest;
	int written;

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
		atomic_inc(&overflow);
	}
done: ;
}

static inline
void _check_overflow(unsigned long cpu)
{
	if (say_index[cpu] < SAY_BUFMAX - 8) {
		int count = 0;
		atomic_xchg(&overflow, count);
		if (unlikely(count > 0)) {
			_say(cpu, NULL, true, "#%d#\n", count);
		}
	}
}

void say(const char *fmt, ...)
{
	unsigned long cpu = get_cpu();
	va_list args;

	_say_mark(cpu);
	if (!say_buf[cpu])
		goto done;
	_check_overflow(cpu);

	va_start(args, fmt);
	_say(cpu, args, false, fmt);
	va_end(args);

	_say_mark(cpu);
done:
	put_cpu();
}
EXPORT_SYMBOL_GPL(say);

void brick_say(bool dump, const char *prefix, const char *file, int line, const char *func, const char *fmt, ...)
{
	struct timespec now = CURRENT_TIME;
	unsigned long cpu = get_cpu();
	int filelen;
	va_list args;

	_say_mark(cpu);
	if (!say_buf[cpu])
		goto done;
	_check_overflow(cpu);

	// limit the filename
	filelen = strlen(file);
	if (filelen > MAX_FILELEN)
		file += filelen - MAX_FILELEN;

	_say(cpu, NULL, true, "%ld.%09ld %s %s[%d] %s %d %s(): ", now.tv_sec, now.tv_nsec, prefix, current->comm, (int)cpu, file, line, func);
	va_start(args, fmt);
	_say(cpu, args, false, fmt);
	va_end(args);

	_say_mark(cpu);
#ifdef CONFIG_DEBUG_KERNEL
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
	if (IS_ERR(log_file)) {
		int status = PTR_ERR(log_file);
		log_file = NULL;
		say("cannot open logfile '%s', status = %d\n", filename, status);
	} else {
		say("opened logfile '%s' %p\n", filename, log_file);
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
			say("closing logfile....\n");
			old = log_file;
			log_file = NULL;
			// FIXME: this may race against vfs_write(). Use rcu here.
			filp_close(old, NULL);
			say("closed logfile.\n");
		}
		if (re_open)
			check_open(filename, true);
	}
}

void init_say(void)
{
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
}
EXPORT_SYMBOL_GPL(exit_say);

#ifdef CONFIG_DEBUG_KERNEL

void brick_dump_stack(void)
{
	if (dump_max > 0) {
		dump_max--; // racy, but does no harm
		dump_stack();
	}
}
EXPORT_SYMBOL(brick_dump_stack);

#endif

