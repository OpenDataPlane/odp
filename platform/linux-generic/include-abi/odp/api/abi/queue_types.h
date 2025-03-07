/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_API_ABI_QUEUE_TYPES_H_
#define ODP_API_ABI_QUEUE_TYPES_H_

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_queue
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
