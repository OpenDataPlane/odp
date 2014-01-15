/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */



#ifndef ODP_SPIN_INTERNAL_H_
#define ODP_SPIN_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


/**
 * GCC memory barrier for ODP internal use
 */
static inline void odp_mem_barrier(void)
{
	asm __volatile__ ("" : : : "memory");
}


/**
 * Spin loop for ODP internal use
 */
static inline void odp_spin(void)
{
#if defined __x86_64__ || defined __i386__

	#ifdef __SSE2__
	asm __volatile__ ("pause");
	#else
	asm __volatile__ ("rep; nop");
	#endif

#elif defined __arm__

	#if __ARM_ARCH == 7
	asm __volatile__ ("nop");
	asm __volatile__ ("nop");
	asm __volatile__ ("nop");
	asm __volatile__ ("nop");
	#endif

#endif
}




#ifdef __cplusplus
}
#endif

#endif
