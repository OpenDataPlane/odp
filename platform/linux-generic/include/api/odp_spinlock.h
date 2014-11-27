/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP spinlock
 */

#ifndef ODP_SPINLOCK_H_
#define ODP_SPINLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>

/** @addtogroup odp_synchronizers
 *  Operations on spinlock.
 *  @{
 */

/**
 * ODP spinlock
 */
typedef struct odp_spinlock_t {
	char lock;  /**< @private Lock */
} odp_spinlock_t;


/**
 * Init spinlock
 *
 * @param spinlock  Spinlock
 */
void odp_spinlock_init(odp_spinlock_t *spinlock);


/**
 * Lock spinlock
 *
 * @param spinlock  Spinlock
 */
void odp_spinlock_lock(odp_spinlock_t *spinlock);


/**
 * Try to lock spinlock
 *
 * @param spinlock  Spinlock
 *
 * @return 1 if the lock was taken, otherwise 0.
 */
int odp_spinlock_trylock(odp_spinlock_t *spinlock);


/**
 * Unlock spinlock
 *
 * @param spinlock  Spinlock
 */
void odp_spinlock_unlock(odp_spinlock_t *spinlock);


/**
 * Test if spinlock is locked
 *
 * @param spinlock  Spinlock
 *
 * @return 1 if the lock is locked, otherwise 0.
 */
int odp_spinlock_is_locked(odp_spinlock_t *spinlock);



/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
