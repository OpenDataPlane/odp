/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/plat/ticketlock_inlines.h>

void odp_ticketlock_init(odp_ticketlock_t *ticketlock)
{
	odp_atomic_init_u32(&ticketlock->next_ticket, 0);
	odp_atomic_init_u32(&ticketlock->cur_ticket, 0);
}

void odp_ticketlock_lock(odp_ticketlock_t *lock)
{
	return _odp_ticketlock_lock(lock);
}

int odp_ticketlock_trylock(odp_ticketlock_t *lock)
{
	return _odp_ticketlock_trylock(lock);
}

void odp_ticketlock_unlock(odp_ticketlock_t *lock)
{
	_odp_ticketlock_unlock(lock);
}

int odp_ticketlock_is_locked(odp_ticketlock_t *lock)
{
	return _odp_ticketlock_is_locked(lock);
}
