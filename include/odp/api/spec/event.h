/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2022-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP event
 */

#ifndef ODP_API_SPEC_EVENT_H_
#define ODP_API_SPEC_EVENT_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event_types.h>
#include <odp/api/packet_types.h>

/** @defgroup odp_event ODP EVENT
 *  Generic event metadata and operations.
 *  @{
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
 * Event type of multiple events
 *
 * Returns the number of first events in the array which have the same event
 * type. Outputs the event type of those events.
 *
 * @param      event    Array of event handles
 * @param      num      Number of events (> 0)
 * @param[out] type     Event type pointer for output
 *
 * @return Number of first events (1 ... num) with the same event type
 *         (includes event[0])
 */
int odp_event_type_multi(const odp_event_t event[], int num,
			 odp_event_type_t *type);

/**
 * Event user area
 *
 * Returns pointer to the user area associated with the event. This maps to the
 * user area of underlying event type (e.g. odp_packet_user_area() for packets).
 * If the event does not have user area, NULL is returned.
 *
 * @param      event    Event handle
 *
 * @return Pointer to the user area of the event
 * @retval NULL  The event does not have user area
 */
void *odp_event_user_area(odp_event_t event);

/**
 * Filter and convert packet events
 *
 * Checks event type of all input events, converts all packet events and outputs
 * packet handles. Returns the number packet handles outputted. Outputs the
 * remaining, non-packet event handles to 'remain' array. Handles are outputted
 * to both arrays in the same order those are stored in 'event' array. Both
 * output arrays must fit 'num' elements.
 *
 * @param      event    Array of event handles
 * @param[out] packet   Packet handle array for output
 * @param[out] remain   Event handle array for output of remaining, non-packet
 *                      events
 * @param      num      Number of events (> 0)
 *
 * @return Number of packets outputted (0 ... num)
 */
int odp_event_filter_packet(const odp_event_t event[],
			    odp_packet_t packet[],
			    odp_event_t remain[], int num);

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
 * Check that event is valid
 *
 * This function can be used for debugging purposes to check if an event handle represents
 * a valid event. The level of error checks depends on the implementation. The call should not
 * crash if the event handle is corrupted.
 *
 * @param event    Event handle
 *
 * @retval 1 Event handle represents a valid event.
 * @retval 0 Event handle does not represent a valid event.
 */
int odp_event_is_valid(odp_event_t event);

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
 * Free multiple events
 *
 * Otherwise like odp_event_free(), but frees multiple events to their
 * originating pools.
 *
 * @param event    Array of event handles
 * @param num      Number of events to free
 */
void odp_event_free_multi(const odp_event_t event[], int num);

/**
 * Free multiple events to the same pool
 *
 * Otherwise like odp_event_free_multi(), but all events must be from the
 * same originating pool.
 *
 * @param event    Array of event handles
 * @param num      Number of events to free
 */
void odp_event_free_sp(const odp_event_t event[], int num);

/**
 * Event flow id value
 *
 * Returns the flow id value set in the event.
 * Usage of flow id enables scheduler to maintain multiple synchronization
 * contexts per single queue. For example, when multiple flows are assigned to
 * an atomic queue, events of a single flow (events from the same queue with
 * the same flow id value) are guaranteed to be processed by only single thread
 * at a time.  For packets received through packet input initial
 * event flow id will be same as flow hash generated for packets. The hash
 * algorithm and therefore the resulting flow id value is implementation
 * specific. Use pktio API configuration options to select the fields used for
 * initial flow id calculation. For all other events initial flow id is zero
 * An application can change event flow id using odp_event_flow_id_set().
 *
 * @param	event	Event handle
 *
 * @return		Flow id of the event
 *
 */
uint32_t odp_event_flow_id(odp_event_t event);

/**
 * Set event flow id value
 *
 * Store the event flow id for the event and sets the flow id flag.
 * When scheduler is configured as flow aware, scheduled queue synchronization
 * will be based on this id within each queue.
 * When scheduler is configured as flow unaware, event flow id is ignored by
 * the implementation.
 * The value of flow id must be less than the number of flows configured in the
 * scheduler.
 *
 * @param      event		Event handle
 * @param      flow_id          Flow event id to be set.
 */
void odp_event_flow_id_set(odp_event_t event, uint32_t flow_id);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
