/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP pool
 */

#ifndef ODP_POOL_TYPES_H_
#define ODP_POOL_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/pool.h>
#else

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>
#include <odp/api/plat/event_types.h>

/** @ingroup odp_pool
 *  @{
 */

typedef ODP_HANDLE_T(odp_pool_t);

#define ODP_POOL_INVALID _odp_cast_scalar(odp_pool_t, 0xffffffff)

#define ODP_POOL_NAME_LEN  32

typedef enum odp_pool_type_t {
	ODP_POOL_BUFFER  = ODP_EVENT_BUFFER,
	ODP_POOL_PACKET  = ODP_EVENT_PACKET,
	ODP_POOL_TIMEOUT = ODP_EVENT_TIMEOUT,
} odp_pool_type_t;

/**
 * @}
 */

#endif

#ifdef __cplusplus
}
#endif

#endif
