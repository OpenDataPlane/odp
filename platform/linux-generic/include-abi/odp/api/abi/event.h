/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP event
 */

#ifndef ODP_API_ABI_EVENT_H_
#define ODP_API_ABI_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @ingroup odp_event
 *  @{
 */

typedef ODP_HANDLE_T(odp_event_t);

#define ODP_EVENT_INVALID _odp_cast_scalar(odp_event_t, 0)

typedef enum odp_event_type_t {
	ODP_EVENT_BUFFER       = 1,
	ODP_EVENT_PACKET       = 2,
	ODP_EVENT_TIMEOUT      = 3,
	ODP_EVENT_CRYPTO_COMPL = 4,
	ODP_EVENT_IPSEC_STATUS = 5
} odp_event_type_t;

typedef enum odp_event_subtype_t {
	ODP_EVENT_NO_SUBTYPE   = 0,
	ODP_EVENT_PACKET_BASIC = 1,
	ODP_EVENT_PACKET_CRYPTO = 2,
	ODP_EVENT_PACKET_IPSEC = 3
} odp_event_subtype_t;

/* Inlined functions for non-ABI compat mode */
#include <odp/api/plat/event_inlines.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
