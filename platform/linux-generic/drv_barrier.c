/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/drv/barrier.h>
#include <odp/drv/sync.h>
#include <odp/api/cpu.h>
#include <odp/drv/atomic.h>

void odpdrv_barrier_init(odpdrv_barrier_t *barrier, int count)
{
	barrier->count = (uint32_t)count;
	odpdrv_atomic_init_u32(&barrier->bar, 0);
}

/*
 * Efficient barrier_sync -
 *
 *   Barriers are initialized with a count of the number of callers
 *   that must sync on the barrier before any may proceed.
 *
 *   To avoid race conditions and to permit the barrier to be fully
 *   reusable, the barrier value cycles between 0..2*count-1. When
 *   synchronizing the wasless variable simply tracks which half of
 *   the cycle the barrier was in upon entry.  Exit is when the
 *   barrier crosses to the other half of the cycle.
 */
void odpdrv_barrier_wait(odpdrv_barrier_t *barrier)
{
	uint32_t count;
	int wasless;

	odpdrv_mb_full();

	count   = odpdrv_atomic_fetch_inc_u32(&barrier->bar);
	wasless = count < barrier->count;

	if (count == 2 * barrier->count - 1) {
		/* Wrap around *atomically* */
		odpdrv_atomic_sub_u32(&barrier->bar, 2 * barrier->count);
	} else {
		while ((odpdrv_atomic_load_u32(&barrier->bar) < barrier->count)
				== wasless)
			odp_cpu_pause();
	}

	odpdrv_mb_full();
}
