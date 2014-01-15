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


/**
 * ODP ticketlock
 */
typedef struct odp_ticketlock_t {
	odp_atomic_u32_t  next_ticket;
	volatile uint32_t cur_ticket;
} odp_ticketlock_t;


/**
 * Init ticketlock
 *
 * @param ticketlock  Ticketlock
 */
void odp_ticketlock_init(odp_ticketlock_t *ticketlock);


/**
 * Lock ticketlock
 *
 * @param ticketlock  Ticketlock
 */
void odp_ticketlock_lock(odp_ticketlock_t *ticketlock);


/**
 * Try to lock ticketlock
 *
 * @param ticketlock  Ticketlock
 *
 * @return 1 if the lock was taken, otherwise 0.
 */
int odp_ticketlock_trylock(odp_ticketlock_t *ticketlock);


/**
 * Unlock ticketlock
 *
 * @param ticketlock  Ticketlock
 */
void odp_ticketlock_unlock(odp_ticketlock_t *ticketlock);


/**
 * Test if ticketlock is locked
 *
 * @param ticketlock  Ticketlock
 *
 * @return 1 if the lock is locked, otherwise 0.
 */
int odp_ticketlock_is_locked(odp_ticketlock_t *ticketlock);


#ifdef __cplusplus
}
#endif

#endif
