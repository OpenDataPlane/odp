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
#include <odp/api/queue_stats_types.h>
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
	 * 'event_type' are allowed.
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

	/** Event aggregation support per event source
	 *
	 *  Specifies for each source of events whether events enqueued by the
	 *  source may be aggregated into event vectors by an event aggregator
	 *  of this queue type.
	 *
	 *  A bit set to one indicates a supported event source. When a bit is
	 *  zero, events from the source are never aggregated. Passing an
	 *  aggregator queue handle to the source is still allowed, but has the
	 *  same effect as passing the handle of the underlying queue (see
	 *  odp_queue_aggr()). Sources which are not passed an aggregator queue
	 *  handle, but which use an aggregator implicitly based on queue
	 *  parameters (packet input and classifier), simply enqueue directly to
	 *  the underlying queue. Queue creation does not fail and the aggregator
	 *  remains usable by other sources.
	 */
	union {
		/** Event source flags */
		struct {
			/** Events enqueued by the application (odp_queue_enq(),
			 *  etc.). This is always set when 'max_num' is
			 *  non-zero.
			 */
			uint32_t queue    : 1;

			/** Packets from packet input */
			uint32_t pktin    : 1;

			/** Packet transmit completion events */
			uint32_t tx_compl : 1;

			/** Packets from the classifier */
			uint32_t cls      : 1;

			/** Timeout events */
			uint32_t timer    : 1;

			/** Crypto completion events */
			uint32_t crypto   : 1;

			/** Compression completion events */
			uint32_t comp     : 1;

			/** IPsec result events */
			uint32_t ipsec    : 1;

			/** DMA completion events */
			uint32_t dma      : 1;

			/** ML completion events */
			uint32_t ml       : 1;

		} bit;

		/** All bits of the bit field structure
		 *
		 *  This field can be used to set/clear all bits, or to perform
		 *  bitwise operations over those.
		 */
		uint32_t all_bits;

	} source;

	/** Supported aggregator statistics counters */
	odp_queue_stats_opt_t stats;

} odp_event_aggr_capability_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
