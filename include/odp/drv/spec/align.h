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

#ifndef ODPDRV_API_ALIGN_H_
#define ODPDRV_API_ALIGN_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_compiler_optim
 *  Macros that allow cache line size configuration, check that
 *  alignment is a power of two etc.
 *  @{
 */

/* Checkpatch complains, but cannot use __aligned(size) for this purpose. */

/**
 * @def ODPDRV_ALIGNED
 * Defines type/struct/variable alignment in bytes
 */

/**
 * @def ODPDRV_PACKED
 * Defines type/struct to be packed
 */

/**
 * @def ODPDRV_OFFSETOF
 * Returns offset of member in type
 */

/**
 * @def ODPDRV_FIELD_SIZEOF
 * Returns sizeof member
 */

/**
 * @def ODPDRV_CACHE_LINE_SIZE
 * Cache line size
 */

/**
 * @def ODPDRV_PAGE_SIZE
 * Page size
 */

/**
 * @def ODPDRV_ALIGNED_CACHE
 * Defines type/struct/variable to be cache line size aligned
 */

/**
 * @def ODPDRV_ALIGNED_PAGE
 * Defines type/struct/variable to be page size aligned
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
