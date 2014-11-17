/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_barrier.h>
#include <odp_sync.h>
#include <odp_spin_internal.h>

void odp_barrier_init(odp_barrier_t *barrier, int count)
{
	barrier->count = count;
	barrier->bar   = 0;
	odp_sync_stores();
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

void odp_barrier_wait(odp_barrier_t *barrier)
{
	uint32_t count;
	int wasless;

	odp_sync_stores();
	wasless = barrier->bar < barrier->count;
	count   = odp_atomic_fetch_inc_u32(&barrier->bar);

	if (count == 2*barrier->count-1) {
		barrier->bar = 0;
	} else {
		while ((barrier->bar < barrier->count) == wasless)
			odp_spin();
	}

	odp_mem_barrier();
}
