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

#ifndef BRICK_LOCKS_H
#define BRICK_LOCKS_H

#include <linux/spinlock.h>

#include "brick_say.h"

# define LOCK_CHECK(OP) 0

#if 0
# define traced_lock(spinlock,flags)   spin_lock_irqsave(spinlock,flags)
# define traced_unlock(spinlock,flags) spin_unlock_irqrestore(spinlock,flags)
# define traced_readlock(spinlock,flags)   read_lock_irqsave(spinlock,flags)
# define traced_readunlock(spinlock,flags) read_unlock_irqrestore(spinlock,flags)
# define traced_writelock(spinlock,flags)   write_lock_irqsave(spinlock,flags)
# define traced_writeunlock(spinlock,flags) write_unlock_irqrestore(spinlock,flags)
#else
# define traced_lock(spinlock,flags)   do { (void)flags; spin_lock(spinlock); } while (0)
# define traced_unlock(spinlock,flags) do { (void)flags; spin_unlock(spinlock); } while (0)
# define traced_readlock(spinlock,flags)   do { (void)flags; read_lock(spinlock); } while (0)
# define traced_readunlock(spinlock,flags) do { (void)flags; read_unlock(spinlock); } while (0)
# define traced_writelock(spinlock,flags)   do { (void)flags; write_lock(spinlock); } while (0)
# define traced_writeunlock(spinlock,flags) do { (void)flags; write_unlock(spinlock); } while (0)
#endif

#endif
