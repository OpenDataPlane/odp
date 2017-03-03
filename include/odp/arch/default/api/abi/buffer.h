/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_BUFFER_H_
#define ODP_ABI_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_buffer_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_buffer_seg_t;

/** @ingroup odp_buffer
 *  @{
 */

typedef _odp_abi_buffer_t *odp_buffer_t;
typedef _odp_abi_buffer_seg_t *odp_buffer_seg_t;

#define ODP_BUFFER_INVALID   ((odp_buffer_t)0xffffffff)
#define ODP_SEGMENT_INVALID  ((odp_buffer_seg_t)0xffffffff)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
