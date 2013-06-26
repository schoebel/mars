// (c) 2010 Thomas Schoebel-Theuer / 1&1 Internet AG
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
