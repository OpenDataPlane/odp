/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdbool.h>
#include <odp/atomic.h>
#include <odp_atomic_internal.h>
#include <odp/rwlock.h>

#include <odp_spin_internal.h>

void odp_rwlock_init(odp_rwlock_t *rwlock)
{
	odp_atomic_init_u32(&rwlock->cnt, 0);
}

void odp_rwlock_read_lock(odp_rwlock_t *rwlock)
{
	uint32_t cnt;
	int  is_locked = 0;

	while (is_locked == 0) {
		cnt = _odp_atomic_u32_load_mm(&rwlock->cnt, _ODP_MEMMODEL_RLX);
		/* waiting for read lock */
		if ((int32_t)cnt < 0) {
			odp_spin();
			continue;
		}
		is_locked = _odp_atomic_u32_cmp_xchg_strong_mm(&rwlock->cnt,
				&cnt,
				cnt + 1,
				_ODP_MEMMODEL_ACQ,
				_ODP_MEMMODEL_RLX);
	}
}

void odp_rwlock_read_unlock(odp_rwlock_t *rwlock)
{
	_odp_atomic_u32_sub_mm(&rwlock->cnt, 1, _ODP_MEMMODEL_RLS);
}

void odp_rwlock_write_lock(odp_rwlock_t *rwlock)
{
	uint32_t cnt;
	int is_locked = 0;

	while (is_locked == 0) {
		uint32_t zero = 0;
		cnt = _odp_atomic_u32_load_mm(&rwlock->cnt, _ODP_MEMMODEL_RLX);
		/* lock acquired, wait */
		if (cnt != 0) {
			odp_spin();
			continue;
		}
		is_locked = _odp_atomic_u32_cmp_xchg_strong_mm(&rwlock->cnt,
				&zero,
				(uint32_t)-1,
				_ODP_MEMMODEL_ACQ,
				_ODP_MEMMODEL_RLX);
	}
}

void odp_rwlock_write_unlock(odp_rwlock_t *rwlock)
{
	_odp_atomic_u32_store_mm(&rwlock->cnt, 0, _ODP_MEMMODEL_RLS);
}
