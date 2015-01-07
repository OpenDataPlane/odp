/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP buffer descriptor
 */

#ifndef ODP_BUFFER_TYPES_H_
#define ODP_BUFFER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_buffer ODP BUFFER
 *  Operations on a buffer.
 *  @{
 */

/** ODP buffer */
typedef uint32_t odp_buffer_t;

/** Invalid buffer */
#define ODP_BUFFER_INVALID (0xffffffff)

/** ODP buffer segment */
typedef odp_buffer_t odp_buffer_seg_t;

/** Invalid segment */
#define ODP_SEGMENT_INVALID ODP_BUFFER_INVALID

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
