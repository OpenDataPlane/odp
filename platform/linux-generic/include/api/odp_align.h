/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */


/**
 * @file
 *
 * ODP alignments
 */

#ifndef ODP_ALIGN_H_
#define ODP_ALIGN_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_compiler_optim
 *  Macros that allow cache line size configuration, check that
 *  alignment is a power of two etc.
 *  @{
 */

#ifdef __GNUC__

/* Checkpatch complains, but cannot use __aligned(size) for this purpose. */

/**
 * Defines type/struct/variable alignment in bytes
 */
#define ODP_ALIGNED(x) __attribute__((__aligned__(x)))

/**
 * Defines type/struct to be packed
 */
#define ODP_PACKED __attribute__((__packed__))

/**
 * Returns offset of member in type
 */
#define ODP_OFFSETOF(type, member) __builtin_offsetof(type, member)

/**
 * Returns sizeof member
 */
#define ODP_FIELD_SIZEOF(type, member) sizeof(((type *)0)->member)

#if defined __x86_64__ || defined __i386__

/** Cache line size */
#define ODP_CACHE_LINE_SIZE 64

#elif defined __arm__ || defined __aarch64__

/** Cache line size */
#define ODP_CACHE_LINE_SIZE 64

#elif defined __OCTEON__

/** Cache line size */
#define ODP_CACHE_LINE_SIZE 128

#elif defined __powerpc__

/** Cache line size */
#define ODP_CACHE_LINE_SIZE 64

#else
#error GCC target not found
#endif

#else
#error Non-gcc compatible compiler
#endif

/** Page size */
#define ODP_PAGE_SIZE       4096


/*
 * Round up
 */


/**
 * @internal
 * Round up pointer 'x' to alignment 'align'
 */
#define ODP_ALIGN_ROUNDUP_PTR(x, align)\
	((void *)ODP_ALIGN_ROUNDUP((uintptr_t)(x), (uintptr_t)(align)))


/**
 * @internal
 * Round up pointer 'x' to cache line size alignment
 */
#define ODP_CACHE_LINE_SIZE_ROUNDUP_PTR(x)\
	((void *)ODP_CACHE_LINE_SIZE_ROUNDUP((uintptr_t)(x)))



/*
 * Round down
 */


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


/** Defines type/struct/variable to be cache line size aligned */
#define ODP_ALIGNED_CACHE   ODP_ALIGNED(ODP_CACHE_LINE_SIZE)

/** Defines type/struct/variable to be page size aligned */
#define ODP_ALIGNED_PAGE    ODP_ALIGNED(ODP_PAGE_SIZE)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
