/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP synchronisation inlines
 */

#ifndef ODP_PLAT_SYNC_INLINE_H_
#define ODP_PLAT_SYNC_INLINE_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_barrier
 *  @{
 */

_ODP_INLINE void odp_mb_release(void)
{
	__atomic_thread_fence(__ATOMIC_RELEASE);
}

_ODP_INLINE void odp_mb_acquire(void)
{
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

_ODP_INLINE void odp_mb_full(void)
{
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
