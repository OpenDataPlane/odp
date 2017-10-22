/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_API_ABI_QUEUE_H_
#define ODP_API_ABI_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_queue
 *  @{
 */

typedef ODP_HANDLE_T(odp_queue_t);

#define ODP_QUEUE_INVALID  _odp_cast_scalar(odp_queue_t, 0)

#define ODP_QUEUE_NAME_LEN 32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
