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

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/buffer.h>
#else

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_buffer
 *  @{
 */

typedef ODP_HANDLE_T(odp_buffer_t);

#define ODP_BUFFER_INVALID _odp_cast_scalar(odp_buffer_t, 0xffffffff)

typedef ODP_HANDLE_T(odp_buffer_seg_t);

#define ODP_SEGMENT_INVALID ((odp_buffer_seg_t)ODP_BUFFER_INVALID)

/**
 * @}
 */

#endif

#ifdef __cplusplus
}
#endif

#endif
