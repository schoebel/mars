// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>


#include "brick_say.h"

/////////////////////////////////////////////////////////////////////

// messaging

#ifdef CONFIG_DEBUG_KERNEL

#include <linux/preempt.h>
#include <linux/hardirq.h>

static char say_buf[PAGE_SIZE * 8] = {};
static int say_index = 0;
static int dump_max = 5;

/* This is racy.
 * But we don't want to contend the CPUs neither by global locks nor by RCU.
 * We just emit some limited kind of "garbage" upon overflow or races.
 * This kind of informational garbage for humans will not hurt correctness
 * of the real logic in any way, we just take it into account.
 */
void say_mark(void)
{
	if (say_buf[0]) {
		printk("# %s", say_buf);
		say_buf[0] = '\0';
		say_index = 0;
	}
}
EXPORT_SYMBOL(say_mark);

void say(const char *fmt, ...)
{
	va_list args;

	if (preempt_count() & (PREEMPT_MASK | SOFTIRQ_MASK | HARDIRQ_MASK)) {
		va_start(args, fmt);
		say_index += vsnprintf(say_buf + say_index, sizeof(say_buf) - say_index, fmt, args);
		va_end(args);
		if (unlikely(say_index >= sizeof(say_buf))) {
			say_index = sizeof(say_buf);
			say_buf[say_index-1] = '\0';
		}
	} else {
		say_mark();
		va_start(args, fmt);
		vprintk(fmt, args);
		va_end(args);
	}
}
EXPORT_SYMBOL(say);

void brick_dump_stack(void)
{
	if (dump_max > 0) {
		dump_max--; // racy, but does no harm
		dump_stack();
	}
}
EXPORT_SYMBOL(brick_dump_stack);

#endif

