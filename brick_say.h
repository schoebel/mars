// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_SAY_H
#define BRICK_SAY_H

/////////////////////////////////////////////////////////////////////////

// printk() replacements

#ifdef CONFIG_DEBUG_KERNEL
#define INLINE static inline
//#define INLINE __attribute__((__noinline__))
extern void say(const char *fmt, ...);
extern void say_mark(void);
extern void brick_dump_stack(void);

#else // CONFIG_DEBUG_KERNEL

#define INLINE static inline
#define say printk
#define say_mark() /*empty*/
#define brick_dump_stack() /*empty*/

#endif // CONFIG_DEBUG_KERNEL

#endif
