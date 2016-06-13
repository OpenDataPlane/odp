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

#ifndef ODP_QUEUE_TYPES_H_
#define ODP_QUEUE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_queue ODP QUEUE
 *  Macros and operation on a queue.
 *  @{
 */

typedef ODP_HANDLE_T(odp_queue_t);

typedef ODP_HANDLE_T(odp_queue_group_t);

#define ODP_QUEUE_INVALID  _odp_cast_scalar(odp_queue_t, 0)

#define ODP_QUEUE_NAME_LEN 32

/**
 * @def ODP_QUEUE_TYPE_TM
 * Traffic manager queue
 * @note Internal to the implementation -- not part of queue type API
 */
#define ODP_QUEUE_TYPE_TM     4

/** Get printable format of odp_queue_t */
static inline uint64_t odp_queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
