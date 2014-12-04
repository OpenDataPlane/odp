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

	/* Take a ticket using an atomic increment of 'next_ticket'.
	 * This can be a relaxed operation but it cannot have the
	 * acquire semantics since we haven't acquired the lock yet */
	ticket = odp_atomic_fetch_inc_u32(&ticketlock->next_ticket);

	/* Spin waiting for our turn. Use load-acquire so that we acquire
	 * all stores from the previous lock owner */
	while (ticket != _odp_atomic_u32_load_mm(&ticketlock->cur_ticket,
						 _ODP_MEMMODEL_ACQ))
		odp_spin();
}


void odp_ticketlock_unlock(odp_ticketlock_t *ticketlock)
{
	/* Release the lock by incrementing 'cur_ticket'. As we are the
	 * lock owner and thus the only thread that is allowed to write
	 * 'cur_ticket', we don't need to do this with an (expensive)
	 * atomic RMW operation. Instead load-relaxed the current value
	 * and a store-release of the incremented value */
	uint32_t cur = _odp_atomic_u32_load_mm(&ticketlock->cur_ticket,
					       _ODP_MEMMODEL_RLX);
	_odp_atomic_u32_store_mm(&ticketlock->cur_ticket, cur + 1,
				 _ODP_MEMMODEL_RLS);

#if defined __OCTEON__
	odp_sync_stores(); /* SYNCW to flush write buffer */
#endif
}


int odp_ticketlock_is_locked(odp_ticketlock_t *ticketlock)
{
	/* Compare 'cur_ticket' with 'next_ticket'. Ideally we should read
	 * both variables atomically but the information can become stale
	 * immediately anyway so the function can only be used reliably in
	 * a quiescent system where non-atomic loads should not pose a
	 * problem */
	return odp_atomic_load_u32(&ticketlock->cur_ticket) !=
		odp_atomic_load_u32(&ticketlock->next_ticket);
}
