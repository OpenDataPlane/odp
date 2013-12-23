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


#ifdef __GNUC__

/* Checkpatch complains, but cannot use __aligned(size) for this purpose. */
#define ODP_ALIGNED(x) __attribute__((__aligned__(x)))
#define ODP_OFFSETOF(type, member) __builtin_offsetof((type), (member))


#if defined __x86_64__ || defined __i386__

#define ODP_CACHE_LINE_SIZE 64

#elif defined __arm__

#define ODP_CACHE_LINE_SIZE 64

#elif defined __OCTEON__

#define ODP_CACHE_LINE_SIZE 128

#else
#error GCC target not found
#endif

#else
#error Non-gcc compatible compiler
#endif


#define ODP_PAGE_SIZE       4096


/*
 * Round up
 */

#define ODP_ALIGN_ROUNDUP_POWER_2(x, align)\
	((align) * (((x) + align - 1) / (align)))

#define ODP_ALIGN_ROUNDUP_PTR_POWER_2(x, align)\
	((void *)ODP_ALIGN_ROUNDUP_POWER_2((uintptr_t)(x), (uintptr_t)(align)))

#define ODP_CACHE_LINE_SIZE_ROUNDUP(x)\
	ODP_ALIGN_ROUNDUP_POWER_2(x, ODP_CACHE_LINE_SIZE)

#define ODP_CACHE_LINE_SIZE_ROUNDUP_PTR(x)\
	((void *)ODP_CACHE_LINE_SIZE_ROUNDUP((uintptr_t)(x)))

#define ODP_PAGE_SIZE_ROUNDUP(x)\
	ODP_ALIGN_ROUNDUP_POWER_2(x, ODP_PAGE_SIZE)


/*
 * Round down
 */

#define ODP_ALIGN_ROUNDDOWN_POWER_2(x, align)\
	((x) & (~((align) - 1)))

#define ODP_ALIGN_ROUNDDOWN_PTR_POWER_2(x, align)\
((void *)ODP_ALIGN_ROUNDDOWN_POWER_2((uintptr_t)(x), (uintptr_t)(align)))

#define ODP_CACHE_LINE_SIZE_ROUNDDOWN(x)\
	ODP_ALIGN_ROUNDDOWN_POWER_2(x, ODP_CACHE_LINE_SIZE)

#define ODP_CACHE_LINE_SIZE_ROUNDDOWN_PTR(x)\
	((void *)ODP_CACHE_LINE_SIZE_ROUNDDOWN((uintptr_t)(x)))


#define ODP_ALIGNED_CACHE   ODP_ALIGNED(ODP_CACHE_LINE_SIZE)
#define ODP_ALIGNED_PAGE    ODP_ALIGNED(ODP_PAGE_SIZE)



/*
 * Check align
 */


#define ODP_ALIGNED_CHECK_POWER_2(x, align)\
	((((uintptr_t)(x)) & (((uintptr_t)(align))-1)) == 0)




#ifdef __cplusplus
}
#endif

#endif







