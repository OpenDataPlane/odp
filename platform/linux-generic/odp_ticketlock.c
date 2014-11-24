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
	odp_atomic_init_u32(&ticketlock->next_ticket, 0);
	ticketlock->cur_ticket  = 0;
}


void odp_ticketlock_lock(odp_ticketlock_t *ticketlock)
{
	uint32_t ticket;

	ticket = odp_atomic_fetch_inc_u32(&ticketlock->next_ticket);

	while (ticket != ticketlock->cur_ticket)
		odp_spin();

	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}


void odp_ticketlock_unlock(odp_ticketlock_t *ticketlock)
{
	__atomic_thread_fence(__ATOMIC_RELEASE);

	ticketlock->cur_ticket++;

#if defined __OCTEON__
	odp_sync_stores(); /* SYNCW to flush write buffer */
#endif
}


int odp_ticketlock_is_locked(odp_ticketlock_t *ticketlock)
{
	return ticketlock->cur_ticket !=
		odp_atomic_load_u32(&ticketlock->next_ticket);
}
