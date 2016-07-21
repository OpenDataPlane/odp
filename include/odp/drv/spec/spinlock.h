/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV spinlock
 */

#ifndef ODPDRV_API_SPINLOCK_H_
#define ODPDRV_API_SPINLOCK_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup odpdrv_locks
 * @details
 * <b> Spin lock (odpdrv_spinlock_t) </b>
 *
 * Spinlock simply re-tries to acquire the lock as long as takes to succeed.
 * Spinlock is not fair since some threads may succeed more often than others.
 * @{
 */

/**
 * @typedef odpdrv_spinlock_t
 * ODPDRV spinlock
 */

/**
 * Initialize spin lock.
 *
 * @param splock Pointer to a spin lock
 */
void odpdrv_spinlock_init(odpdrv_spinlock_t *splock);

/**
 * Acquire spin lock.
 *
 * @param splock Pointer to a spin lock
 */
void odpdrv_spinlock_lock(odpdrv_spinlock_t *splock);

/**
 * Try to acquire spin lock.
 *
 * @param splock Pointer to a spin lock
 *
 * @retval  0 lock not acquired
 * @retval !0 lock acquired
 */
int odpdrv_spinlock_trylock(odpdrv_spinlock_t *splock);

/**
 * Release spin lock.
 *
 * @param splock Pointer to a spin lock
 */
void odpdrv_spinlock_unlock(odpdrv_spinlock_t *splock);

/**
 * Check if spin lock is busy (locked).
 *
 * @param splock Pointer to a spin lock
 *
 * @retval 1 lock busy (locked)
 * @retval 0 lock not busy.
 */
int odpdrv_spinlock_is_locked(odpdrv_spinlock_t *splock);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
