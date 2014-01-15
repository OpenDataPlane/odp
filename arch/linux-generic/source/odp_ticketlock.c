/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_ticketlock.h>
#include <odp_atomic.h>
#include <odp_sync.h>
#include <odp_spin_internal.h>


void odp_ticketlock_init(odp_ticketlock_t *ticketlock)
{
	ticketlock->next_ticket = 0;
	ticketlock->cur_ticket  = 0;
	odp_sync_stores();
}


void odp_ticketlock_lock(odp_ticketlock_t *ticketlock)
{
	uint32_t ticket;

	ticket = odp_atomic_fetch_inc_u32(&ticketlock->next_ticket);

	while (ticket != ticketlock->cur_ticket)
		odp_spin();

	odp_mem_barrier();
}


void odp_ticketlock_unlock(odp_ticketlock_t *ticketlock)
{
	odp_sync_stores();

	ticketlock->cur_ticket++;

	odp_mem_barrier();
}


int odp_ticketlock_is_locked(odp_ticketlock_t *ticketlock)
{
	return ticketlock->cur_ticket != ticketlock->next_ticket;
}
