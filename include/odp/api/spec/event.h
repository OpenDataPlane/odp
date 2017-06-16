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

#ifndef ODP_API_EVENT_H_
#define ODP_API_EVENT_H_
#include <odp/visibility_begin.h>

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
 * @typedef odp_event_type_t
 * Event type
 *
 * Event type specifies purpose and general format of an event. It can be
 * checked with odp_event_type() or odp_event_types(). Each event type has
 * functions (e.g. odp_buffer_from_event()) to convert between the generic event
 * handle (odp_event_t) and the type specific handle (e.g. odp_buffer_t).
 * Results are undefined, if conversion function of a wrong event type is used.
 * Application cannot change event type by chaining conversion functions.
 *
 * List of event types:
 * - ODP_EVENT_BUFFER
 *     - Buffer event (odp_buffer_t) for simple data storage and message passing
 * - ODP_EVENT_PACKET
 *     - Packet event (odp_packet_t) containing packet data and plenty of
 *       packet processing related metadata
 * - ODP_EVENT_TIMEOUT
 *     - Timeout event (odp_timeout_t) from a timer
 * - ODP_EVENT_CRYPTO_COMPL
 *     - Crypto completion event (odp_crypto_compl_t)
 * - ODP_EVENT_IPSEC_STATUS
 *     - IPSEC status update event (odp_ipsec_status_t)
 */

/**
 * @typedef odp_event_subtype_t
 * Event subtype
 *
 * Event subtype expands event type specification by providing more detailed
 * purpose and format of an event. It can be checked with odp_event_subtype() or
 * odp_event_types(). Each event subtype may define specific functions
 * (e.g. odp_ipsec_packet_from_event()) to convert between the generic event
 * handle (odp_event_t) and event type specific handle (e.g. odp_packet_t). When
 * subtype is known, these subtype specific functions should be preferred over
 * the event type general function (e.g. odp_packet_from_event()). Results are
 * undefined, if conversion function of a wrong event subtype is used.
 * Application cannot change event subtype by chaining conversion functions.
 *
 *  List of event subtypes:
 * - ODP_EVENT_PACKET_BASIC
 *     - Packet event (odp_packet_t) with basic packet metadata
 * - ODP_EVENT_PACKET_IPSEC
 *     - Packet event (odp_packet_t) generated as a result of an IPsec
 *       operation. It contains IPSEC specific metadata in addition to the basic
 *       packet metadata.
 * - ODP_EVENT_NO_SUBTYPE
 *     - An event type does not have any subtypes defined
 */

/**
 * Event type of an event
 *
 * Event type specifies purpose and general format of an event.
 *
 * @param      event    Event handle
 *
 * @return Event type
 */
odp_event_type_t odp_event_type(odp_event_t event);

/**
 * Event subtype of an event
 *
 * Event subtype expands event type specification by providing more detailed
 * purpose and format of an event.
 *
 * @param      event    Event handle
 *
 * @return Event subtype
 */
odp_event_subtype_t odp_event_subtype(odp_event_t event);

/**
 * Event type and subtype of an event
 *
 * Returns event type and outputs event subtype.
 *
 * @param      event    Event handle
 * @param[out] subtype  Pointer to event subtype for output
 *
 * @return Event type
 */
odp_event_type_t odp_event_types(odp_event_t event,
				 odp_event_subtype_t *subtype);

/**
 * Get printable value for an odp_event_t
 *
 * @param hdl  odp_event_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_event_t handle.
 */
uint64_t odp_event_to_u64(odp_event_t hdl);

/**
 * Free event
 *
 * Frees the event based on its type. Results are undefined if event
 * type is unknown.
 *
 * @param event    Event handle
 *
 */
void odp_event_free(odp_event_t event);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
