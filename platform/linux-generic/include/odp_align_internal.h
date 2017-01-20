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

/** @addtogroup odp_compiler_optim
 *  @{
 */

/*
 * Round up
 */

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
#define ODP_ROUNDUP_POWER2_U32(x) \
	((((uint32_t)(x)) > 0x80000000) ? 0 : (_POW2_U32_R5(x - 1) + 1))

/**
 * @internal
 * Round up 'x' to alignment 'align'
 */
#define ODP_ALIGN_ROUNDUP(x, align)\
	((align) * (((x) + (align) - 1) / (align)))

/**
 * @internal
 * Round up pointer 'x' to alignment 'align'
 */
#define ODP_ALIGN_ROUNDUP_PTR(x, align)\
	((void *)ODP_ALIGN_ROUNDUP((uintptr_t)(x), (uintptr_t)(align)))

/**
 * @internal
 * Round up 'x' to cache line size alignment
 */
#define ODP_CACHE_LINE_SIZE_ROUNDUP(x)\
	ODP_ALIGN_ROUNDUP(x, ODP_CACHE_LINE_SIZE)

/**
 * @internal
 * Round up pointer 'x' to cache line size alignment
 */
#define ODP_CACHE_LINE_SIZE_ROUNDUP_PTR(x)\
	((void *)ODP_CACHE_LINE_SIZE_ROUNDUP((uintptr_t)(x)))

/**
 * @internal
 * Round up 'x' to page size alignment
 */
#define ODP_PAGE_SIZE_ROUNDUP(x)\
	ODP_ALIGN_ROUNDUP(x, ODP_PAGE_SIZE)

/*
 * Round down
 */

/**
 * @internal
 * Round down 'x' to 'align' alignment, which is a power of two
 */
#define ODP_ALIGN_ROUNDDOWN_POWER_2(x, align)\
	((x) & (~((align) - 1)))
/**
 * @internal
 * Round down 'x' to cache line size alignment
 */
#define ODP_CACHE_LINE_SIZE_ROUNDDOWN(x)\
	ODP_ALIGN_ROUNDDOWN_POWER_2(x, ODP_CACHE_LINE_SIZE)

/**
 * @internal
 * Round down pointer 'x' to 'align' alignment, which is a power of two
 */
#define ODP_ALIGN_ROUNDDOWN_PTR_POWER_2(x, align)\
((void *)ODP_ALIGN_ROUNDDOWN_POWER_2((uintptr_t)(x), (uintptr_t)(align)))

/**
 * @internal
 * Round down pointer 'x' to cache line size alignment
 */
#define ODP_CACHE_LINE_SIZE_ROUNDDOWN_PTR(x)\
	((void *)ODP_CACHE_LINE_SIZE_ROUNDDOWN((uintptr_t)(x)))

/*
 * Check align
 */

/**
 * @internal
 * Check if pointer 'x' is aligned to 'align', which is a power of two
 */
#define ODP_ALIGNED_CHECK_POWER_2(x, align)\
	((((uintptr_t)(x)) & (((uintptr_t)(align))-1)) == 0)

/**
 * @internal
 * Check if value is a power of two
 */
#define ODP_VAL_IS_POWER_2(x) ((((x)-1) & (x)) == 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
