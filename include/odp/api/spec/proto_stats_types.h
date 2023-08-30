/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Marvell
 * Copyright (c) 2021 Nokia
 */

/**
 * @file
 *
 * ODP proto stats types
 */

#ifndef ODP_API_SPEC_PROTO_STATS_TYPES_H_
#define ODP_API_SPEC_PROTO_STATS_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @addtogroup odp_proto_stats
 *  @{
 */

/**
 * @def ODP_PROTO_STATS_INVALID
 * Invalid proto stats handle
 */

/** ODP proto stats counters
 *
 * Statistics that can be enabled in proto stats object. For Tx stats counters,
 * Pktout config `odp_pktout_config_opt_t::bit::proto_stats_ena` needs to be
 * enabled.
 *
 * Tx packet and octet sent/drop statistics might include packets sent/dropped via
 * Traffic Manager or Tx packet Aging or due to any other Tx errors. It is
 * implementation specific as to what all Tx sent/drop events are accounted for.
 */
typedef union odp_proto_stats_counters_t {
	/** Option flags */
	struct {
		/** Tx packet sent count */
		uint64_t tx_pkts : 1;

		/** Tx packet drop count */
		uint64_t tx_pkt_drops : 1;

		/** Tx packet sent Octet counter 0 */
		uint64_t tx_oct_count0 : 1;

		/** Tx packet drop Octet counter 0 */
		uint64_t tx_oct_count0_drops : 1;

		/** Tx packet sent octet counter 1 */
		uint64_t tx_oct_count1 : 1;

		/** Tx packet drop octet counter 1 */
		uint64_t tx_oct_count1_drops : 1;
	} bit;

	/** All bits of the bit field structure
	 *
	 * This field can be used to set/clear all flags, or bitwise
	 * operations over the entire structure.
	 */
	uint64_t all_bits;
} odp_proto_stats_counters_t;

/** ODP proto stats params */
typedef struct odp_proto_stats_param_t {
	/** Stats counters to enable */
	odp_proto_stats_counters_t counters;
} odp_proto_stats_param_t;

/**
 * Proto stats capabilities
 */
typedef struct odp_proto_stats_capability_t {
	/** Tx capabilities */
	struct {
		/** Stats counters supported */
		odp_proto_stats_counters_t counters;

		/** Packet adjust support for Octet counter 0 */
		odp_bool_t oct_count0_adj;

		/** Packet adjust support for Octet counter 1 */
		odp_bool_t oct_count1_adj;
	} tx;
} odp_proto_stats_capability_t;

/** ODP proto stats counters */
typedef struct odp_proto_stats_data_t {
	/** Packet sent count */
	uint64_t tx_pkts;

	/** Packet drop count */
	uint64_t tx_pkt_drops;

	/** Packet sent Octet counter 0 */
	uint64_t tx_oct_count0;

	/** Packet drop Octet counter 0 */
	uint64_t tx_oct_count0_drops;

	/** Packet sent octet counter 1 */
	uint64_t tx_oct_count1;

	/** Packet drop octet counter 1 */
	uint64_t tx_oct_count1_drops;
} odp_proto_stats_data_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
