/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_barrier.h>
#include <odp_system_info.h>
#include <odp_sync.h>
#include <odp_spin_internal.h>

#include <string.h>


void odp_barrier_init_count(odp_barrier_t *barrier, int count)
{
	barrier->count     = count;
	barrier->cur_count = 0;
	odp_sync_stores();
}


void odp_barrier_sync(odp_barrier_t *barrier)
{
	int count;

	count = odp_atomic_fetch_inc_int(&barrier->cur_count);

	if (count == barrier->count - 1) {
		/* If last, reset count */
		barrier->cur_count = 0;
		odp_sync_stores();
	} else {
		/* Spin */
		while (barrier->cur_count)
			odp_spin();
	}
}
