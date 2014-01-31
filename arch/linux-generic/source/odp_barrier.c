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
	barrier->count = count;
	barrier->in    = 0;
	barrier->out   = count - 1;
	odp_sync_stores();
}


void odp_barrier_sync(odp_barrier_t *barrier)
{
	int count;

	odp_sync_stores();

	count = odp_atomic_fetch_inc_int(&barrier->in);

	if (count == barrier->count - 1) {
		/* If last thread, release others */
		barrier->in = 0;
		odp_sync_stores();

		/* Wait for others to exit */
		while (barrier->out)
			odp_spin();

		/* Ready, reset out counter */
		barrier->out = barrier->count - 1;
		odp_sync_stores();

	} else {
		/* Wait for the last thread*/
		while (barrier->in)
			odp_spin();

		/* Ready */
		odp_atomic_dec_int(&barrier->out);
		odp_mem_barrier();
	}
}
