/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_atomic.h>
#include <odp_rwlock.h>

#include "odp_spin_internal.h"

void odp_rwlock_init(odp_rwlock_t *rwlock)
{
	rwlock->cnt = 0;
}

void odp_rwlock_read_lock(odp_rwlock_t *rwlock)
{
	int32_t cnt;
	int  is_locked = 0;

	while (is_locked == 0) {
		cnt = rwlock->cnt;
		/* waiting for read lock */
		if (cnt < 0) {
			odp_spin();
			continue;
		}
		is_locked = odp_atomic_cmpset_u32(
					(volatile uint32_t *)&rwlock->cnt,
					      cnt, cnt + 1);
	}
}

void odp_rwlock_read_unlock(odp_rwlock_t *rwlock)
{
	odp_atomic_dec_u32((odp_atomic_u32_t *)(intptr_t)&rwlock->cnt);
}

void odp_rwlock_write_lock(odp_rwlock_t *rwlock)
{
	int32_t cnt;
	int is_locked = 0;

	while (is_locked == 0) {
		cnt = rwlock->cnt;
		/* lock aquired, wait */
		if (cnt != 0) {
			odp_spin();
			continue;
		}
		is_locked = odp_atomic_cmpset_u32(
					(volatile uint32_t *)&rwlock->cnt,
					      0, -1);
	}
}

void odp_rwlock_write_unlock(odp_rwlock_t *rwlock)
{
	odp_atomic_inc_u32((odp_atomic_u32_t *)(intptr_t)&rwlock->cnt);
}
