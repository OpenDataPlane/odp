/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP alignments
 */

#ifndef ODP_API_SPEC_ALIGN_H_
#define ODP_API_SPEC_ALIGN_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_compiler_optim
 *  Macros that allow cache line size configuration, check that
 *  alignment is a power of two etc.
 *  @{
 */

/* Checkpatch complains, but cannot use __aligned(size) for this purpose. */

/**
 * @def ODP_ALIGNED
 * Defines type/struct/variable alignment in bytes
 */

/**
 * @def ODP_PACKED
 * Defines type/struct to be packed
 */

/**
 * @def ODP_OFFSETOF
 * Returns offset of member in type
 */

/**
 * @def ODP_FIELD_SIZEOF
 * Returns sizeof member
 */

/**
 * @def ODP_CACHE_LINE_SIZE
 * Cache line size in bytes
 */

/**
 * @def ODP_PAGE_SIZE
 * Page size in bytes
 */

/**
 * @def ODP_ALIGNED_CACHE
 * Defines type/struct/variable to be cache line size aligned
 */

/**
 * @def ODP_ALIGNED_PAGE
 * Defines type/struct/variable to be page size aligned
 */

/**
 * @def ODP_CACHE_LINE_ROUNDUP
 * Round up to cache line size
 *
 * Rounds up the passed value to the next multiple of cache line size
 * (ODP_CACHE_LINE_SIZE). Returns the original value if it is already
 * a multiple of cache line size or zero.
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
