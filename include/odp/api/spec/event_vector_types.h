/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 Nokia
 */

/**
 * @file
 *
 * ODP event vector API type definitions
 */

#ifndef ODP_API_SPEC_EVENT_VECTOR_TYPES_H_
#define ODP_API_SPEC_EVENT_VECTOR_TYPES_H_
#include <odp/visibility_begin.h>

#include <odp/api/event_types.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_event_vector ODP EVENT VECTOR
 *  @{
 */

/**
 * @typedef odp_event_vector_t
 * ODP event vector
 */

/**
 * @def ODP_EVENT_VECTOR_INVALID
 * Invalid event vector
 */

/**
 * Event vector configuration
 */
typedef struct odp_event_aggr_config_t {
	/** Event vector pool
	 *
	 * Pool from which to allocate event vectors. The pool must have been
	 * created with the ODP_POOL_EVENT_VECTOR type.
	 */
	odp_pool_t pool;

	/** Maximum time to wait for events
	 *
	 * Maximum time in nanoseconds for an event aggregator to form an event
	 * vector. This value should be in the range of
	 * odp_event_aggr_capability_t::min_tmo_ns to
	 * odp_event_aggr_capability_t::max_tmo_ns.
	 *
	 * Value of zero means there is no timeout. Events may wait aggregation
	 * indefinitely in the aggregation queue.
	 */
	uint64_t max_tmo_ns;

	/** Maximum number of events in vector
	 *
	 * Event aggregator forms an event vector event after 'max_size' events
	 * have been collected or 'max_tmo_ns' has passed. 'max_size' value
	 * should be in the range of odp_event_aggr_capability_t::min_size
	 * to odp_event_aggr_capability_t::max_size.
	 *
	 * The maximum number of events an event vector can hold is defined by
	 * odp_pool_param_t::event_vector.max_size of the event vector pool.
	 * 'max_size' must not be greater than that value.
	 */
	uint32_t max_size;

	/** Event type
	 *
	 * Event type of event aggregator. If 'event_type' is ODP_EVENT_ANY,
	 * application is allowed to enqueue any event types, except event
	 * vectors, to the event aggregator. Otherwise, only events of type
	 * 'event_type' are allowed. The default value is ODP_EVENT_ANY.
	 *
	 * Regardless of 'event_type', an application is never allowed to
	 * enqueue event vector or packet vector events (ODP_EVENT_VECTOR or
	 * ODP_EVENT_PACKET_VECTOR) to an event aggregator queue
	 * (i.e. vectors within vectors).
	 */
	odp_event_type_t event_type;

} odp_event_aggr_config_t;

/**
 * Event aggregator capabilities
 */
typedef struct odp_event_aggr_capability_t {
	/** Maximum number of event aggregators for this queue type */
	uint32_t max_num;

	/** Maximum number of event aggregators per queue */
	uint32_t max_num_per_queue;

	/** Maximum number of events that can be aggregated into an event vector */
	uint32_t max_size;

	/** Minimum number of events that can be aggregated into an event vector */
	uint32_t min_size;

	/** Maximum allowed value of odp_event_aggr_config_t::max_tmo_ns */
	uint64_t max_tmo_ns;

	/** Minimum time in nanoseconds for an aggregator to form an event vector.
	 *
	 *  odp_event_aggr_config_t::max_tmo_ns must not be less than this
	 *  value unless it is zero.
	 */
	uint64_t min_tmo_ns;

} odp_event_aggr_capability_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
