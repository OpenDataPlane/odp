/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2022-2023 Nokia
 */

/**
 * @file
 *
 * ODP event type definitions
 */

#ifndef ODP_API_ABI_EVENT_TYPES_H_
#define ODP_API_ABI_EVENT_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_event
 *  @{
 */

typedef ODP_HANDLE_T(odp_event_t);

#define ODP_EVENT_INVALID _odp_cast_scalar(odp_event_t, 0)

typedef enum odp_event_type_t {
	ODP_EVENT_BUFFER = 1,
	ODP_EVENT_PACKET = 2,
	ODP_EVENT_TIMEOUT = 3,
	ODP_EVENT_IPSEC_STATUS = 5,
	ODP_EVENT_PACKET_VECTOR = 6,
	ODP_EVENT_PACKET_TX_COMPL = 7,
	ODP_EVENT_DMA_COMPL = 8,
	ODP_EVENT_ML_COMPL = 9
} odp_event_type_t;

typedef enum odp_event_subtype_t {
	ODP_EVENT_NO_SUBTYPE   = 0,
	ODP_EVENT_PACKET_BASIC = 1,
	ODP_EVENT_PACKET_CRYPTO = 2,
	ODP_EVENT_PACKET_IPSEC = 3,
	ODP_EVENT_PACKET_COMP = 4,
	ODP_EVENT_ML_COMPL_LOAD = 5,
	ODP_EVENT_ML_COMPL_RUN = 6
} odp_event_subtype_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
