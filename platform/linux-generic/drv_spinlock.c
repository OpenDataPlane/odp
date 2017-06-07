/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/drv/spinlock.h>
#include <odp_atomic_internal.h>

void odpdrv_spinlock_init(odpdrv_spinlock_t *spinlock)
{
	_odp_atomic_flag_init(&spinlock->lock, 0);
}

void odpdrv_spinlock_lock(odpdrv_spinlock_t *spinlock)
{
	/* While the lock is already taken... */
	while (_odp_atomic_flag_tas(&spinlock->lock))
		/* ...spin reading the flag (relaxed MM),
		 * the loop will exit when the lock becomes available
		 * and we will retry the TAS operation above */
		while (_odp_atomic_flag_load(&spinlock->lock))
			odp_cpu_pause();
}

int odpdrv_spinlock_trylock(odpdrv_spinlock_t *spinlock)
{
	return (_odp_atomic_flag_tas(&spinlock->lock) == 0);
}

void odpdrv_spinlock_unlock(odpdrv_spinlock_t *spinlock)
{
	_odp_atomic_flag_clear(&spinlock->lock);
}

int odpdrv_spinlock_is_locked(odpdrv_spinlock_t *spinlock)
{
	return _odp_atomic_flag_load(&spinlock->lock) != 0;
}
