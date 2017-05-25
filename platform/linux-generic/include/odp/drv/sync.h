/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV synchronisation
 */

#ifndef ODPDRV_PLAT_SYNC_H_
#define ODPDRV_PLAT_SYNC_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odpdrv_barrier
 *  @{
 */

static inline void odpdrv_mb_release(void)
{
	__atomic_thread_fence(__ATOMIC_RELEASE);
}

static inline void odpdrv_mb_acquire(void)
{
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static inline void odpdrv_mb_full(void)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
}

/**
 * @}
 */

#include <odp/drv/spec/sync.h>

#ifdef __cplusplus
}
#endif

#endif
