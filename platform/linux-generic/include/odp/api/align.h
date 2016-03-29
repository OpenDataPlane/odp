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

#ifndef ODP_PLAT_ALIGN_H_
#define ODP_PLAT_ALIGN_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_compiler_optim
 *  @{
 */

#ifdef __GNUC__

#define ODP_ALIGNED(x) __attribute__((__aligned__(x)))

#define ODP_PACKED __attribute__((__packed__))

#define ODP_OFFSETOF(type, member) __builtin_offsetof(type, member)

#define ODP_FIELD_SIZEOF(type, member) sizeof(((type *)0)->member)

#if defined __arm__ || defined __aarch64__

#define ODP_CACHE_LINE_SIZE 64

#endif

#else
#error Non-gcc compatible compiler
#endif

#define ODP_PAGE_SIZE       4096

#define ODP_ALIGNED_CACHE   ODP_ALIGNED(ODP_CACHE_LINE_SIZE)

#define ODP_ALIGNED_PAGE    ODP_ALIGNED(ODP_PAGE_SIZE)

/**
 * @}
 */

#include <odp/api/spec/align.h>
#include <odp/api/cpu_arch.h>

#ifdef __cplusplus
}
#endif

#endif
