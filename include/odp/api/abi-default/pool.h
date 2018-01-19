/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_POOL_H_
#define ODP_ABI_POOL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/abi/event.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_pool_t;

/** @ingroup odp_pool
 *  @{
 */

typedef _odp_abi_pool_t *odp_pool_t;

#define ODP_POOL_INVALID   ((odp_pool_t)0xffffffff)

#define ODP_POOL_NAME_LEN  32

typedef enum odp_pool_type_t {
	ODP_POOL_BUFFER  = ODP_EVENT_BUFFER,
	ODP_POOL_PACKET  = ODP_EVENT_PACKET,
	ODP_POOL_TIMEOUT = ODP_EVENT_TIMEOUT
} odp_pool_type_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
