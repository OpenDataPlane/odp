/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_BUFFER_TYPES_H_
#define ODP_ABI_BUFFER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_buffer_t;

/** @ingroup odp_buffer
 *  @{
 */

typedef _odp_abi_buffer_t *odp_buffer_t;

#define ODP_BUFFER_INVALID   ((odp_buffer_t)0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
