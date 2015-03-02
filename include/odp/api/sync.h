/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP synchronisation
 */

#ifndef ODP_API_SYNC_H_
#define ODP_API_SYNC_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_synchronizers
 *  @{
 */

/**
 * Synchronise stores
 *
 * Ensures that all CPU store operations that precede the odp_sync_stores()
 * call are globally visible before any store operation that follows it.
 */
static inline void odp_sync_stores(void)
{
#if defined __x86_64__ || defined __i386__

	__asm__  __volatile__ ("sfence\n" : : : "memory");

#elif defined(__arm__)
#if __ARM_ARCH == 6
	__asm__ __volatile__ ("mcr p15, 0, %0, c7, c10, 5" \
			: : "r" (0) : "memory");
#elif __ARM_ARCH >= 7 || defined __aarch64__

	__asm__ __volatile__ ("dmb st" : : : "memory");
#else
	__asm__ __volatile__ ("" : : : "memory");
#endif

#elif defined __OCTEON__

	__asm__  __volatile__ ("syncws\n" : : : "memory");

#else
	__sync_synchronize();
#endif
}


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
