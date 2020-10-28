/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Standard C language types and definitions for ODP.
 *
 */

#ifndef ODP_API_SPEC_STD_TYPES_H_
#define ODP_API_SPEC_STD_TYPES_H_
#include <odp/visibility_begin.h>
/* uint64_t, uint32_t, etc */
#include <stdint.h>
#include <odp/api/align.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_system ODP SYSTEM
 *  @{
 */

/**
 * @typedef odp_bool_t
 * Use odp boolean type to have it well-defined and known size,
 * regardless which compiler is used as this facilities interoperability
 * between e.g. different compilers.
 */

/**
 * Percentage type
 * Use odp_percent_t for specifying fields that are percentages. It is a fixed
 * point integer whose units are expressed as one-hundredth of a percent.
 * Hence 100% is represented as integer value 10000.
 */
typedef uint32_t odp_percent_t;

/** Unaligned uint16_t type */
typedef uint16_t odp_una_u16_t ODP_ALIGNED(1);

/** Unaligned uint32_t type */
typedef uint32_t odp_una_u32_t ODP_ALIGNED(1);

/** Unaligned uint64_t type */
typedef uint64_t odp_una_u64_t ODP_ALIGNED(1);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
