// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>


#include "brick_say.h"

/////////////////////////////////////////////////////////////////////

// messaging

#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/hardirq.h>

#define SAY_ORDER 0
#define SAY_BUFMAX (PAGE_SIZE << SAY_ORDER)
#define MAX_FILELEN 16

static char *say_buf[NR_CPUS] = {};
static int say_index[NR_CPUS] = {};
static int dump_max = 5;

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
	
	printk("%s", say_buf[cpu]);
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

	say_index[cpu] += snprintf(say_buf[cpu] + say_index[cpu], SAY_BUFMAX - say_index[cpu], "%s %s[%d] %s %d %s(): ", prefix, current->comm, (int)cpu, file, line, func);

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

extern void exit_say(void)
{
	int i;
	for (i = 0; i < NR_CPUS; i++) {
		if (!say_buf[i])
			continue;
		__free_pages(virt_to_page((unsigned long)say_buf[i]), SAY_ORDER);
		say_buf[i] = NULL;
	}
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

