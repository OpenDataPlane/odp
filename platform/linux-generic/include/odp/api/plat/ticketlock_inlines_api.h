/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Ticketlock inline functions
 */

#ifndef _ODP_PLAT_TICKETLOCK_INLINES_API_H_
#define _ODP_PLAT_TICKETLOCK_INLINES_API_H_

_ODP_INLINE void odp_ticketlock_lock(odp_ticketlock_t *lock)
{
	return _odp_ticketlock_lock(lock);
}

_ODP_INLINE int odp_ticketlock_trylock(odp_ticketlock_t *lock)
{
	return _odp_ticketlock_trylock(lock);
}

_ODP_INLINE void odp_ticketlock_unlock(odp_ticketlock_t *lock)
{
	_odp_ticketlock_unlock(lock);
}

_ODP_INLINE int odp_ticketlock_is_locked(odp_ticketlock_t *lock)
{
	return _odp_ticketlock_is_locked(lock);
}

#endif
