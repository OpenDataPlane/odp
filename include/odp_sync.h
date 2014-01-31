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


static inline void odp_sync_stores(void)
{
#if defined __x86_64__ || defined __i386__

	asm __volatile__ ("sfence\n" : : : "memory");

#elif defined __arm__

	asm __volatile__ ("dmb st" : : : "memory");

#elif defined __OCTEON__

	asm __volatile__ ("syncws\n" : : : "memory");

#else
	__sync_synchronize();
#endif
}


#ifdef __cplusplus
}
#endif

#endif







