/*
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

/* configure guarantees us that we have pthreads on any host except
 * mingw32, which doesn't support any of the user-only targets.
 * So we can simply assume we have pthread mutexes here.
 */

/* Empty implementations, on the theory that system mode emulation
 * is single-threaded. This means that these functions should only
 * be used from code run in the TCG cpu thread, and cannot protect
 * data structures which might also be accessed from the IO thread
 * or from signal handlers.
 */

#ifndef _QEMU_LOCK_H_
#define _QEMU_LOCK_H_

typedef int spinlock_t;
#define SPIN_LOCK_UNLOCKED 0

__INLINE__ void spin_lock(spinlock_t *lock)
{
	// TODO:
}

__INLINE__ void spin_unlock(spinlock_t *lock)
{
	// TODO:
}

#endif /* _QEMU_LOCK_H_ */
