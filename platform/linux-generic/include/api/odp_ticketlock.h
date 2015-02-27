/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP ticketlock
 */

#ifndef ODP_TICKETLOCK_H_
#define ODP_TICKETLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>
#include <odp_atomic.h>

/** @addtogroup odp_synchronizers
 * Operations on ticket locks.
 * Acquiring a ticket lock happens in two phases. First the threads takes a
 * ticket. Second it waits (spins) until it is its turn.
 * Ticket locks are believed to be more fair than spin locks.
 * Ticket locks shall not be used in the presence of preemption.
 *  @{
 */

/**
 * ODP ticket lock
 */
typedef struct odp_ticketlock_t {
	odp_atomic_u32_t  next_ticket; /**< @private Next ticket */
	odp_atomic_u32_t  cur_ticket;  /**< @private Current ticket */
} odp_ticketlock_t;


/**
 * Initialize ticket lock.
 *
 * @param tklock Pointer to a ticket lock
 */
void odp_ticketlock_init(odp_ticketlock_t *tklock);


/**
 * Acquire ticket lock.
 *
 * @param tklock Pointer to a ticket lock
 */
void odp_ticketlock_lock(odp_ticketlock_t *tklock);

/**
 * Try to acquire ticket lock.
 *
 * @param tklock Pointer to a ticket lock
 *
 * @retval 1 lock acquired
 * @retval 0 lock not acquired
 */
int odp_ticketlock_trylock(odp_ticketlock_t *tklock);

/**
 * Release ticket lock.
 *
 * @param tklock Pointer to a ticket lock
 */
void odp_ticketlock_unlock(odp_ticketlock_t *tklock);


/**
 * Check if ticket lock is locked.
 *
 * @param tklock Pointer to a ticket lock
 *
 * @retval 1 the lock is busy (locked)
 * @retval 0 the lock is available (unlocked)
 */
int odp_ticketlock_is_locked(odp_ticketlock_t *tklock);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
