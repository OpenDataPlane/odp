/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODPH_PAUSE_H_
#define ODPH_PAUSE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Spin loop for helper internal use
 */
static inline void odph_pause(void)
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
