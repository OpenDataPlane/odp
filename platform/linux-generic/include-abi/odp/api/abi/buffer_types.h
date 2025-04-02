/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2023 Nokia
 */

/**
 * @file
 *
 * ODP buffer types
 */

#ifndef ODP_API_ABI_BUFFER_TYPES_H_
#define ODP_API_ABI_BUFFER_TYPES_H_

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_buffer
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
