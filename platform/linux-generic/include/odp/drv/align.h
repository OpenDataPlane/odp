/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV alignments
 */

#ifndef ODPDRV_PLAT_ALIGN_H_
#define ODPDRV_PLAT_ALIGN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/cpu_arch.h>

/** @ingroup odpdrv_compiler_optim
 *  @{
 */

#ifdef __GNUC__

#define ODPDRV_ALIGNED(x) __attribute__((__aligned__(x)))

#define ODPDRV_PACKED __attribute__((__packed__))

#define ODPDRV_OFFSETOF(type, member) __builtin_offsetof(type, member)

#define ODPDRV_FIELD_SIZEOF(type, member) sizeof(((type *)0)->member)

#else
#error Non-gcc compatible compiler
#endif

#define ODPDRV_CACHE_LINE_SIZE _ODP_CACHE_LINE_SIZE

#define ODPDRV_PAGE_SIZE       4096

#define ODPDRV_ALIGNED_CACHE   ODPDRV_ALIGNED(ODPDRV_CACHE_LINE_SIZE)

#define ODPDRV_ALIGNED_PAGE    ODPDRV_ALIGNED(ODPDRV_PAGE_SIZE)

/**
 * @}
 */

#include <odp/drv/spec/align.h>

#ifdef __cplusplus
}
#endif

#endif
