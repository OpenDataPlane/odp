/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_spinlock.h>
#include <odp_spin_internal.h>


void odp_spinlock_init(odp_spinlock_t *spinlock)
{
	__sync_lock_release(&spinlock->lock);
}


void odp_spinlock_lock(odp_spinlock_t *spinlock)
{
	while (__sync_lock_test_and_set(&spinlock->lock, 1))
		while (spinlock->lock)
			odp_spin();
}


int odp_spinlock_trylock(odp_spinlock_t *spinlock)
{
	return (__sync_lock_test_and_set(&spinlock->lock, 1) == 0);
}


void odp_spinlock_unlock(odp_spinlock_t *spinlock)
{
	__sync_lock_release(&spinlock->lock);
}


int odp_spinlock_is_locked(odp_spinlock_t *spinlock)
{
	return spinlock->lock != 0;
}
