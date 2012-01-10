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

#ifndef CONFIG_MARS_USE_SYSLOG
static struct file *log_file = NULL;
#endif

static
void say_alloc(unsigned long cpu)
{
	if (cpu >= NR_CPUS || say_buf[cpu])
		goto done;

	say_buf[cpu] = (void*)__get_free_pages(GFP_ATOMIC, SAY_ORDER);
	if (likely(say_buf[cpu])) {
		say_buf[cpu][0] = '\0';
		say_index[cpu] = 0;
	}

done: ;
}

static inline
void _say_mark(unsigned long cpu)
{
	if (preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK | HARDIRQ_MASK) ||
	    cpu >= NR_CPUS)
		goto done;

	say_alloc(cpu);

	if (!say_buf[cpu] ||
	    !say_buf[cpu][0])
		goto done;
	
#ifdef CONFIG_MARS_USE_SYSLOG
	printk("%s", say_buf[cpu]);
#else
	if (log_file) {
		loff_t log_pos = 0;
		int rest = say_index[cpu];
		int len = 0;
		while (rest > 0) {
			int status = vfs_write(log_file, say_buf[cpu] + len, rest, &log_pos);
			if (status <= 0)
				break;
			len += status;
			rest -= status;
		}
	} else {
		printk("%s", say_buf[cpu]);
	}
#endif
	say_buf[cpu][0] = '\0';
	say_index[cpu] = 0;
	
done: ;
}

void say_mark(void)
{
	unsigned long cpu = get_cpu();
	_say_mark(cpu);
	put_cpu();
}
EXPORT_SYMBOL_GPL(say_mark);

void say(const char *fmt, ...)
{
	unsigned long cpu = get_cpu();
	va_list args;

	_say_mark(cpu);
	if (!say_buf[cpu])
		goto done;

	va_start(args, fmt);
	say_index[cpu] += vsnprintf(say_buf[cpu] + say_index[cpu], SAY_BUFMAX - say_index[cpu], fmt, args);
	va_end(args);

	if (unlikely(say_index[cpu] >= SAY_BUFMAX)) {
		say_index[cpu] = SAY_BUFMAX;
		say_buf[cpu][SAY_BUFMAX-1] = '\0';
	}

	_say_mark(cpu);
done:
	put_cpu();
}
EXPORT_SYMBOL_GPL(say);

void brick_say(const char *prefix, const char *file, int line, const char *func, const char *fmt, ...)
{
	struct timespec now = CURRENT_TIME;
	unsigned long cpu = get_cpu();
	int filelen;
	va_list args;

	_say_mark(cpu);
	if (!say_buf[cpu])
		goto done;

	// limit the
	filelen = strlen(file);
	if (filelen > MAX_FILELEN)
		file += filelen - MAX_FILELEN;

	
	say_index[cpu] += snprintf(say_buf[cpu] + say_index[cpu], SAY_BUFMAX - say_index[cpu], "%ld.%09ld %s %s[%d] %s %d %s(): ", now.tv_sec, now.tv_nsec, prefix, current->comm, (int)cpu, file, line, func);

	va_start(args, fmt);
	say_index[cpu] += vsnprintf(say_buf[cpu] + say_index[cpu], SAY_BUFMAX - say_index[cpu], fmt, args);
	va_end(args);

	if (unlikely(say_index[cpu] >= SAY_BUFMAX)) {
		say_index[cpu] = SAY_BUFMAX;
		say_buf[cpu][SAY_BUFMAX-1] = '\0';
	}

	_say_mark(cpu);
done:
	put_cpu();
}
EXPORT_SYMBOL_GPL(brick_say);

void init_say(void)
{
#ifndef CONFIG_MARS_USE_SYSLOG
	int flags = O_CREAT | O_APPEND | O_RDWR | O_LARGEFILE;
	int prot = 0600;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(get_ds());
 	log_file = filp_open("/mars/log.txt", flags, prot);
	set_fs(oldfs);
	if (IS_ERR(log_file)) {
		say("cannot create logfile, status = %ld\n", PTR_ERR(log_file));
		log_file = NULL;
	}
#endif
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
#ifndef CONFIG_MARS_USE_SYSLOG
	if (log_file) {
		filp_close(log_file, NULL);
		log_file = NULL;
	}
#endif
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

