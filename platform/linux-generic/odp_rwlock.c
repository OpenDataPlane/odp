/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdbool.h>
#include <odp/api/atomic.h>
#include <odp/api/rwlock.h>
#include <odp/api/cpu.h>

#include <odp/api/plat/atomic_inlines.h>
#include <odp/api/plat/cpu_inlines.h>

void odp_rwlock_init(odp_rwlock_t *rwlock)
{
	odp_atomic_init_u32(&rwlock->cnt, 0);
}

void odp_rwlock_read_lock(odp_rwlock_t *rwlock)
{
	uint32_t cnt;
	int  is_locked = 0;

	while (is_locked == 0) {
		cnt = odp_atomic_load_u32(&rwlock->cnt);
		/* waiting for read lock */
		if ((int32_t)cnt < 0) {
			odp_cpu_pause();
			continue;
		}
		is_locked = odp_atomic_cas_acq_u32(&rwlock->cnt,
						   &cnt, cnt + 1);
	}
}

int odp_rwlock_read_trylock(odp_rwlock_t *rwlock)
{
	uint32_t cnt = odp_atomic_load_u32(&rwlock->cnt);

	while (cnt != (uint32_t)-1) {
		if (odp_atomic_cas_acq_u32(&rwlock->cnt, &cnt, cnt + 1))
			return 1;
	}

	return 0;
}

void odp_rwlock_read_unlock(odp_rwlock_t *rwlock)
{
	odp_atomic_sub_rel_u32(&rwlock->cnt, 1);
}

void odp_rwlock_write_lock(odp_rwlock_t *rwlock)
{
	uint32_t cnt;
	int is_locked = 0;

	while (is_locked == 0) {
		uint32_t zero = 0;
		cnt = odp_atomic_load_u32(&rwlock->cnt);
		/* lock acquired, wait */
		if (cnt != 0) {
			odp_cpu_pause();
			continue;
		}
		is_locked = odp_atomic_cas_acq_u32(&rwlock->cnt,
						   &zero, (uint32_t)-1);
	}
}

int odp_rwlock_write_trylock(odp_rwlock_t *rwlock)
{
	uint32_t zero = 0;

	return odp_atomic_cas_acq_u32(&rwlock->cnt, &zero, (uint32_t)-1);
}

void odp_rwlock_write_unlock(odp_rwlock_t *rwlock)
{
	odp_atomic_store_rel_u32(&rwlock->cnt, 0);
}
