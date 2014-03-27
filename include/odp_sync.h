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

#ifndef ODP_SYNC_H_
#define ODP_SYNC_H_

#ifdef __cplusplus
extern "C" {
#endif


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

#elif defined __arm__

	__asm__ __volatile__ ("dmb st" : : : "memory");

#elif defined __OCTEON__

	__asm__  __volatile__ ("syncws\n" : : : "memory");

#else
	__sync_synchronize();
#endif
}


#ifdef __cplusplus
}
#endif

#endif







