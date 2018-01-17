/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP buffer descriptor
 */

#ifndef ODP_API_ABI_BUFFER_H_
#define ODP_API_ABI_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_buffer
 *  @{
 */

typedef ODP_HANDLE_T(odp_buffer_t);

#define ODP_BUFFER_INVALID _odp_cast_scalar(odp_buffer_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
