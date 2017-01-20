/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP internal alignments
 */

#ifndef ODP_ALIGN_INTERNAL_H_
#define ODP_ALIGN_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <stdint.h>

/* Macros to calculate ODP_ROUNDUP_POWER2_U32() in five rounds of shift
 * and OR operations. */
#define _RSHIFT_U32(x, y) (((uint32_t)(x)) >> (y))
#define _POW2_U32_R1(x)   (((uint32_t)(x)) | _RSHIFT_U32(x, 1))
#define _POW2_U32_R2(x)   (_POW2_U32_R1(x) | _RSHIFT_U32(_POW2_U32_R1(x), 2))
#define _POW2_U32_R3(x)   (_POW2_U32_R2(x) | _RSHIFT_U32(_POW2_U32_R2(x), 4))
#define _POW2_U32_R4(x)   (_POW2_U32_R3(x) | _RSHIFT_U32(_POW2_U32_R3(x), 8))
#define _POW2_U32_R5(x)   (_POW2_U32_R4(x) | _RSHIFT_U32(_POW2_U32_R4(x), 16))

/* Round up a uint32_t value 'x' to the next power of two.
 *
 * The value is not round up, if it's already a power of two (including 1).
 * The value must be larger than 0 and not exceed 0x80000000.
 */
#define ROUNDUP_POWER2_U32(x) \
	((((uint32_t)(x)) > 0x80000000) ? 0 : (_POW2_U32_R5(x - 1) + 1))

/*
 * Round up 'x' to alignment 'align'
 */
#define ROUNDUP_ALIGN(x, align)\
	((align) * (((x) + (align) - 1) / (align)))

/*
 * Round up 'x' to cache line size alignment
 */
#define ROUNDUP_CACHE_LINE(x)\
	ROUNDUP_ALIGN(x, ODP_CACHE_LINE_SIZE)

/*
 * Round down 'x' to 'align' alignment, which is a power of two
 */
#define ROUNDDOWN_POWER2(x, align)\
	((x) & (~((align) - 1)))

/*
 * Check if value is a power of two
 */
#define CHECK_IS_POWER2(x) ((((x) - 1) & (x)) == 0)

#ifdef __cplusplus
}
#endif

#endif
