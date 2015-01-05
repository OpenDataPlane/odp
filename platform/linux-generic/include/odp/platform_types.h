/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 * ODP implementation types
 * This file contains all of the implementation-defined types for ODP abstract
 * definitions. Having this in one file means that other ODP API files are
 * implementation-independent and avoids circular dependencies for files that
 * refer to types managed by other components. Included here are typedefs and
 * related typed constants that are referenced by other ODP API files.
 */

#ifndef ODP_IMPL_TYPES_H_
#define ODP_IMPL_TYPES_H_

#include <odp/std_types.h>
#include <odp/buffer_types.h>

/** @defgroup odp_platform_types ODP PLATFORM TYPES
 *  Implementation specific definitions for ODP abstract types.
 *  @{
 */

/** ODP event */
typedef odp_buffer_t odp_event_t;

/** Invalid event */
#define ODP_EVENT_INVALID ODP_BUFFER_INVALID

/** ODP Class of service handle */
typedef uint32_t odp_cos_t;

/**
 * @}
 */

#endif
