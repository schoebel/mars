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

#ifndef BRICK_SAY_H
#define BRICK_SAY_H
//	remove_this

#ifndef CONFIG_MARS_MODULE
// when unsure, include faked config file
#include "mars_config.h"
#endif
//	end_remove_this

/////////////////////////////////////////////////////////////////////////

extern int brick_say_logging;
extern int brick_say_debug;
extern int brick_say_syslog_min;
extern int brick_say_syslog_max;
extern int brick_say_syslog_flood_class;
extern int brick_say_syslog_flood_limit;
extern int brick_say_syslog_flood_recovery;
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

#define bind_me(_name)							\
	bind_to_channel(make_channel(_name), current)

extern struct say_channel *get_binding(struct task_struct *whom);

extern void remove_binding_from(struct say_channel *ch, struct task_struct *whom);
extern void remove_binding(struct task_struct *whom);

extern void rollover_channel(struct say_channel *ch);
extern void rollover_all(void);

extern void say_to(struct say_channel *ch, int class, const char *fmt, ...) __printf(3, 4);

#define say(_class, _fmt, _args...)					\
	say_to(NULL, _class, _fmt, ##_args)

extern void brick_say_to(struct say_channel *ch,
	int class,
	bool dump,
	const char *prefix,
	const char *file,
	int line,
	const char *func,
	const char *fmt,

	...) __printf(8,
	9);

#define brick_say(_class, _dump, _prefix, _file, _line, _func, _fmt, _args...)\
	brick_say_to(NULL, _class, _dump, _prefix, _file, _line, _func, _fmt, ##_args)

extern void init_say(void);
extern void exit_say(void);

#ifdef CONFIG_MARS_DEBUG
extern void brick_dump_stack(void);
#else // CONFIG_MARS_DEBUG
#define brick_dump_stack() /*empty*/
#endif // CONFIG_MARS_DEBUG

#endif
