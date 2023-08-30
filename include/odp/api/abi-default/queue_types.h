/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_ABI_QUEUE_TYPES_H_
#define ODP_ABI_QUEUE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_queue_t;

/** @ingroup odp_queue
 *  @{
 */

typedef _odp_abi_queue_t *odp_queue_t;

#define ODP_QUEUE_INVALID   ((odp_queue_t)0)

#define ODP_QUEUE_NAME_LEN  32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
