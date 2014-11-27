/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_ticketlock.h>
#include <odp_atomic.h>
#include <odp_atomic_internal.h>
#include <odp_sync.h>
#include <odp_spin_internal.h>


void odp_ticketlock_init(odp_ticketlock_t *ticketlock)
{
	odp_atomic_init_u32(&ticketlock->next_ticket, 0);
	odp_atomic_init_u32(&ticketlock->cur_ticket, 0);
}


void odp_ticketlock_lock(odp_ticketlock_t *ticketlock)
{
	uint32_t ticket;

	ticket = odp_atomic_fetch_inc_u32(&ticketlock->next_ticket);

	while (ticket != _odp_atomic_u32_load_mm(&ticketlock->cur_ticket,
						 _ODP_MEMMODEL_ACQ))
		odp_spin();
}


void odp_ticketlock_unlock(odp_ticketlock_t *ticketlock)
{
	_odp_atomic_u32_add_mm(&ticketlock->cur_ticket, 1, _ODP_MEMMODEL_RLS);

#if defined __OCTEON__
	odp_sync_stores(); /* SYNCW to flush write buffer */
#endif
}


int odp_ticketlock_is_locked(odp_ticketlock_t *ticketlock)
{
	return odp_atomic_load_u32(&ticketlock->cur_ticket) !=
		odp_atomic_load_u32(&ticketlock->next_ticket);
}
