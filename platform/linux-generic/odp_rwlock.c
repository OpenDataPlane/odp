/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdbool.h>
#include <odp_atomic.h>
#include <odp_rwlock.h>

#include <odp_spin_internal.h>

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
		is_locked = __atomic_compare_exchange_n(&rwlock->cnt,
				&cnt,
				cnt + 1,
				false/*strong*/,
				__ATOMIC_ACQUIRE,
				__ATOMIC_RELAXED);
	}
}

void odp_rwlock_read_unlock(odp_rwlock_t *rwlock)
{
	(void)__atomic_sub_fetch(&rwlock->cnt, 1, __ATOMIC_RELEASE);
}

void odp_rwlock_write_lock(odp_rwlock_t *rwlock)
{
	int32_t cnt;
	int is_locked = 0;

	while (is_locked == 0) {
		int32_t zero = 0;
		cnt = rwlock->cnt;
		/* lock aquired, wait */
		if (cnt != 0) {
			odp_spin();
			continue;
		}
		is_locked = __atomic_compare_exchange_n(&rwlock->cnt,
				&zero,
				-1,
				false/*strong*/,
				__ATOMIC_ACQUIRE,
				__ATOMIC_RELAXED);
	}
}

void odp_rwlock_write_unlock(odp_rwlock_t *rwlock)
{
	(void)__atomic_add_fetch(&rwlock->cnt, 1, __ATOMIC_RELEASE);
}
