/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP event
 */

#ifndef ODP_EVENT_H_
#define ODP_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif


/** @defgroup odp_event ODP EVENT
 *  Operations on an event.
 *  @{
 */


/**
 * @typedef odp_event_t
 * ODP event
 */

/**
 * @def ODP_EVENT_INVALID
 * Invalid event
 */

/**
 * @def ODP_EVENT_BUFFER
 * Buffer event
 */

/**
 * @def ODP_EVENT_PACKET
 * Packet event
 */

/**
 * @def ODP_EVENT_TIMEOUT
 * Timeout event
 */

/**
 * @def ODP_EVENT_CRYPTO_COMPL
 * Crypto completion event
 */

/**
 * Get event type
 *
 * @param event    Event handle
 *
 * @return Event type
 */
int odp_event_type(odp_event_t event);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
