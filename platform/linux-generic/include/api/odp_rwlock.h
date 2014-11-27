/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_RWLOCK_H_
#define ODP_RWLOCK_H_

/**
 * @file
 *
 * ODP RW Locks
 */

#include <odp_atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_synchronizers ODP SYNCROIZERS
 *  Operations to a read/write lock.
 *  @{
 */

/**
 * The odp_rwlock_t type.
 * write lock count is -1,
 * read lock count > 0
 */
typedef struct {
	odp_atomic_u32_t cnt; /**< -1 Write lock,
				> 0 for Read lock. */
} odp_rwlock_t;


/**
 * Initialize the rwlock to an unlocked state.
 *
 * @param rwlock pointer to the RW Lock.
 */
void odp_rwlock_init(odp_rwlock_t *rwlock);

/**
 * Aquire a read lock.
 *
 * @param rwlock pointer to a RW Lock.
 */
void odp_rwlock_read_lock(odp_rwlock_t *rwlock);

/**
 * Release a read lock.
 *
 * @param rwlock pointer to the RW Lock.
 */
void odp_rwlock_read_unlock(odp_rwlock_t *rwlock);

/**
 * Aquire a write lock.
 *
 * @param rwlock pointer to a RW Lock.
 */
void odp_rwlock_write_lock(odp_rwlock_t *rwlock);

/**
 * Release a write lock.
 *
 * @param rwlock pointer to a RW Lock.
 */
void odp_rwlock_write_unlock(odp_rwlock_t *rwlock);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ODP_RWLOCK_H_ */
