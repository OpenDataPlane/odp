/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/spinlock.h>
#include <odp/api/cpu.h>
#include <odp_atomic_internal.h>

#include <odp/api/plat/cpu_inlines.h>

void odp_spinlock_init(odp_spinlock_t *spinlock)
{
	_odp_atomic_flag_init(&spinlock->lock, 0);
}

void odp_spinlock_lock(odp_spinlock_t *spinlock)
{
	/* While the lock is already taken... */
	while (_odp_atomic_flag_tas(&spinlock->lock))
		/* ...spin reading the flag (relaxed MM),
		 * the loop will exit when the lock becomes available
		 * and we will retry the TAS operation above */
		while (_odp_atomic_flag_load(&spinlock->lock))
			odp_cpu_pause();
}

int odp_spinlock_trylock(odp_spinlock_t *spinlock)
{
	return (_odp_atomic_flag_tas(&spinlock->lock) == 0);
}

void odp_spinlock_unlock(odp_spinlock_t *spinlock)
{
	_odp_atomic_flag_clear(&spinlock->lock);
}

int odp_spinlock_is_locked(odp_spinlock_t *spinlock)
{
	return _odp_atomic_flag_load(&spinlock->lock) != 0;
}
