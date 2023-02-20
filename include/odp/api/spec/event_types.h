/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP event API type definitions
 */

#ifndef ODP_API_SPEC_EVENT_TYPES_H_
#define ODP_API_SPEC_EVENT_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_event
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
 * - ODP_EVENT_IPSEC_STATUS
 *     - IPSEC status update event (odp_ipsec_status_t)
 * - ODP_EVENT_PACKET_VECTOR
 *     - Vector of packet events (odp_packet_t) as odp_packet_vector_t
 * - ODP_EVENT_PACKET_TX_COMPL
 *     - Packet Tx completion event (odp_packet_tx_compl_t) generated as a result of a Packet Tx
 *       completion.
 * - ODP_EVENT_DMA_COMPL
 *     - DMA completion event (odp_dma_compl_t) indicates that a DMA transfer has finished
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
 * - ODP_EVENT_PACKET_COMP
 *     - Packet event (odp_packet_t) generated as a result of a compression/
 *       decompression operation. It contains compression specific metadata in
 *       addition to the basic packet metadata.
 * - ODP_EVENT_PACKET_CRYPTO
 *     - Packet event (odp_packet_t) generated as a result of a Crypto
 *       operation. It contains crypto specific metadata in addition to the
 *       basic packet metadata.
 * - ODP_EVENT_PACKET_IPSEC
 *     - Packet event (odp_packet_t) generated as a result of an IPsec
 *       operation. It contains IPSEC specific metadata in addition to the basic
 *       packet metadata.
 * - ODP_EVENT_NO_SUBTYPE
 *     - An event type does not have any subtypes defined
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
