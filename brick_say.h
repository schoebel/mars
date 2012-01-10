// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_SAY_H
#define BRICK_SAY_H

/////////////////////////////////////////////////////////////////////////

// printk() replacements

extern void say(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
extern void say_mark(void);

extern void brick_say(const char *prefix, const char *file, int line, const char *func, const char *fmt, ...) __attribute__ ((format (printf, 5, 6)));

extern void init_say(void);
extern void exit_say(void);

#ifdef CONFIG_DEBUG_KERNEL
#define INLINE static inline
//#define INLINE __attribute__((__noinline__))
extern void brick_dump_stack(void);

#else // CONFIG_DEBUG_KERNEL

#define INLINE static inline
#define brick_dump_stack() /*empty*/

#endif // CONFIG_DEBUG_KERNEL

#endif
