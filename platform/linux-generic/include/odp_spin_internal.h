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
	__asm__ __volatile__ ("" : : : "memory");
}


/**
 * Spin loop for ODP internal use
 */
static inline void odp_spin(void)
{
#if defined __x86_64__ || defined __i386__

	#ifdef __SSE2__
	__asm__ __volatile__ ("pause");
	#else
	__asm__ __volatile__ ("rep; nop");
	#endif

#elif defined __arm__

	#if __ARM_ARCH == 7
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	#endif

#elif defined __OCTEON__

	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");
	__asm__ __volatile__ ("nop");

#endif
}


#ifdef __cplusplus
}
#endif

#endif
