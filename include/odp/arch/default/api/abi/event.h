/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_EVENT_H_
#define ODP_ABI_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_event_t;

/** @ingroup odp_event
 *  @{
 */

typedef _odp_abi_event_t *odp_event_t;

#define ODP_EVENT_INVALID  ((odp_event_t)0xffffffff)

typedef enum odp_event_type_t {
	ODP_EVENT_BUFFER       = 1,
	ODP_EVENT_PACKET       = 2,
	ODP_EVENT_TIMEOUT      = 3,
	ODP_EVENT_CRYPTO_COMPL = 4
} odp_event_type_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
