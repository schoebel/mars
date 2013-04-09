// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
#ifndef BRICK_SAY_H
#define BRICK_SAY_H

// include default config
#include "mars_config.h"

/////////////////////////////////////////////////////////////////////////

extern int brick_say_logging;
extern int brick_say_debug;
extern int brick_say_syslog_min;
extern int brick_say_syslog_max;
extern int delay_say_on_overflow;

// printk() replacements

enum {
	SAY_DEBUG,
	SAY_INFO,
	SAY_WARN,
	SAY_ERROR,
	SAY_FATAL,
	SAY_TOTAL,
	MAX_SAY_CLASS
};

extern const char *say_class[MAX_SAY_CLASS];

struct say_channel;

extern struct say_channel *default_channel;

extern struct say_channel *make_channel(const char *name, bool must_exit);

extern void del_channel(struct say_channel *ch);

extern void bind_to_channel(struct say_channel *ch, struct task_struct *whom);

#define bind_me(_name)					\
	bind_to_channel(make_channel(_name), current)

extern struct say_channel *get_binding(struct task_struct *whom);

extern void remove_binding_from(struct say_channel *ch, struct task_struct *whom);
extern void remove_binding(struct task_struct *whom);

extern void rollover_channel(struct say_channel *ch);
extern void rollover_all(void);

extern void say_to(struct say_channel *ch, int class, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

#define say(_class, _fmt, _args...)			\
	say_to(NULL, _class, _fmt, ##_args)

extern void brick_say_to(struct say_channel *ch, int class, bool dump, const char *prefix, const char *file, int line, const char *func, const char *fmt, ...) __attribute__ ((format (printf, 8, 9)));

#define brick_say(_class, _dump, _prefix, _file, _line, _func, _fmt, _args...) \
	brick_say_to(NULL, _class, _dump, _prefix, _file, _line, _func, _fmt, ##_args)

extern void init_say(void);
extern void exit_say(void);

#ifdef CONFIG_MARS_DEBUG
#define INLINE static inline
//#define INLINE __attribute__((__noinline__))
extern void brick_dump_stack(void);

#else // CONFIG_MARS_DEBUG

#define INLINE static inline
#define brick_dump_stack() /*empty*/

#endif // CONFIG_MARS_DEBUG

#endif
