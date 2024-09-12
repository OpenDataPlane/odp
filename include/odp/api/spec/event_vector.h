/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 Nokia
 */

/**
 * @file
 *
 * ODP event vector
 */

#ifndef ODP_API_SPEC_EVENT_VECTOR_H_
#define ODP_API_SPEC_EVENT_VECTOR_H_
#include <odp/visibility_begin.h>

#include <odp/api/event_types.h>
#include <odp/api/event_vector_types.h>
#include <odp/api/pool_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_event_vector
 *  Event vector metadata and operations.
 *  @{
 */

/**
 * Get event vector handle from event
 *
 * Converts an ODP_EVENT_VECTOR type event to an event vector handle.
 *
 * @param ev Event handle
 *
 * @return Event vector handle
 */
odp_event_vector_t odp_event_vector_from_event(odp_event_t ev);

/**
 * Convert event vector handle to event
 *
 * @param evv Event vector handle
 *
 * @return Event handle
 */
odp_event_t odp_event_vector_to_event(odp_event_vector_t evv);

/**
 * Allocate event vector from event vector pool
 *
 * Allocates an event vector from the specified event vector pool. The pool must
 * have been created with the ODP_POOL_EVENT_VECTOR type.
 *
 * A newly allocated vector shall not contain any events, instead, alloc
 * operation shall reserve the space for odp_pool_param_t::event_vector.max_size
 * events.
 *
 * @param pool Event vector pool handle
 *
 * @return Handle of allocated event vector
 * @retval ODP_EVENT_VECTOR_INVALID  Event vector could not be allocated
 */
odp_event_vector_t odp_event_vector_alloc(odp_pool_t pool);

/**
 * Free event vector
 *
 * Frees the event vector into the event vector pool it was allocated from.
 *
 * This API just frees the vector, not any events inside the vector. Application
 * can use odp_event_free() to free the vector and events inside the vector.
 *
 * @param evv Event vector handle
 */
void odp_event_vector_free(odp_event_vector_t evv);

/**
 * Get event vector table
 *
 * Event vector table is an array of events (odp_event_t) stored in contiguous
 * memory location. Upon completion of this API, the implementation returns the
 * event table pointer in event_tbl.
 *
 * The maximum number of events this vector can hold is defined by
 * odp_pool_param_t::event_vector.max_size. The return value of this function
 * will not be greater than odp_pool_param_t::event_vector.max_size
 *
 * The event_tbl points to the event vector table. Application can edit the
 * event handles in the table directly (up to odp_pool_param_t::event_vector.max_size).
 * Application must update the size of the table using odp_event_vector_size_set()
 * when there is a change in the size of the vector.
 *
 * Invalid event handles (ODP_EVENT_INVALID) are not allowed to be stored in the
 * table to allow consumers of odp_event_vector_t handle to have optimized
 * implementation. So consumption of events in the middle of the vector would
 * call for moving the remaining events up to form a contiguous array of events
 * and update the size of the new vector using odp_event_vector_size_set().
 *
 * The table memory is backed by an event vector pool buffer. The ownership of
 * the table memory is linked to the ownership of the event. I.e. after
 * sending the event to a queue, the sender loses ownership to the table also.
 *
 * @param      evv       Event vector handle
 * @param[out] event_tbl Points to event vector table
 *
 * @return Number of events available in the vector.
 */
uint32_t odp_event_vector_tbl(odp_event_vector_t evv, odp_event_t **event_tbl);

/**
 * Number of events in a vector
 *
 * @param evv Event vector handle
 *
 * @return The number of events available in the vector
 */
uint32_t odp_event_vector_size(odp_event_vector_t evv);

/**
 * Type of events stored in event vector
 *
 * If all events in the vector are of the same type, function returns the
 * particular event type. If the vector is empty or includes multiple event
 * types, ODP_EVENT_ANY is returned instead.
 *
 * @param      evv        Event vector handle
 *
 * @return Event type
 */
odp_event_type_t odp_event_vector_type(odp_event_vector_t evv);

/**
 * Set the number of events stored in a vector
 *
 * Update the number of events stored in a vector. When the application is
 * producing an event vector, this function shall be used by the application
 * to set the number of events available in this vector.
 *
 * The maximum number of events this vector can hold is defined by
 * odp_pool_param_t::event_vector.max_size. The size value must not be greater
 * than odp_pool_param_t::event_vector.max_size
 *
 * All handles in the vector table (0 .. size - 1) need to be valid event
 * handles.
 *
 * @param evv    Event vector handle
 * @param size   Number of events in this vector
 *
 * @see odp_event_vector_tbl()
 */
void odp_event_vector_size_set(odp_event_vector_t evv, uint32_t size);

/**
 * Event vector user area
 *
 * Returns pointer to the user area associated with the event vector. Size of
 * the area is fixed and defined in vector pool parameters.
 *
 * @param  evv  Event vector handle
 *
 * @return       Pointer to the user area of the event vector
 * @retval NULL  The event vector does not have user area
 */
void *odp_event_vector_user_area(odp_event_vector_t evv);

/**
 * Check user flag
 *
 * Implementation clears user flag during new event vector creation (e.g. alloc
 * and packet input) and reset. User may set the flag with
 * odp_event_vector_user_flag_set(). Implementation never sets the flag, only
 * clears it. The flag may be useful e.g. to mark when the user area content is
 * valid.
 *
 * @param evv  Event vector handle
 *
 * @retval 0    User flag is clear
 * @retval >0   User flag is set
 */
int odp_event_vector_user_flag(odp_event_vector_t evv);

/**
 * Set user flag
 *
 * Set (or clear) the user flag.
 *
 * @param evv  Event vector handle
 * @param val  New value for the flag. Zero clears the flag, other values set
 *             the flag.
 */
void odp_event_vector_user_flag_set(odp_event_vector_t evv, int val);

/**
 * Event vector pool
 *
 * Returns handle to the event vector pool where the event vector was allocated
 * from.
 *
 * @param evv Event vector handle
 *
 * @return Event vector pool handle
 */
odp_pool_t odp_event_vector_pool(odp_event_vector_t evv);

/**
 * Print debug information about event vector
 *
 * Print implementation defined information about event vector to the ODP log.
 * The information is intended to be used for debugging.
 *
 * @param evv Event vector handle
 */
void odp_event_vector_print(odp_event_vector_t evv);

/**
 * Get printable value for event vector handle
 *
 * @param evv Handle to be converted for debugging
 *
 * @return uint64_t value that can be used to print/display this handle
 */
uint64_t odp_event_vector_to_u64(odp_event_vector_t evv);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
