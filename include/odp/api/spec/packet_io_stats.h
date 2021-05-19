/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Packet IO statistics
 */

#ifndef ODP_API_SPEC_PACKET_IO_STATS_H_
#define ODP_API_SPEC_PACKET_IO_STATS_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/deprecated.h>
#include <odp/api/queue.h>

/** @addtogroup odp_packet_io
 *  @{
 */

/**
 * Packet IO statistics counters
 *
 * In the counter definitions the term successfully refers to packets which were
 * not discarded or detected to contain errors by the packet IO interface. In
 * case of Ethernet, it's implementation specific whether valid pause frames are
 * included in the counters or not.
 */
typedef struct odp_pktio_stats_t {
	/** Number of octets in successfully received packets. In case of
	 *  Ethernet, packet size includes MAC header. */
	uint64_t in_octets;

	/** Number of successfully received packets. */
	uint64_t in_packets;

	/** Number of successfully received Ethernet packets with a unicast
	 *  destination MAC address. */
	uint64_t in_ucast_pkts;

	/** Number of successfully received Ethernet packets with a multicast
	 *  destination MAC address. */
	uint64_t in_mcast_pkts;

	/** Number of successfully received Ethernet packets with a broadcast
	 *  destination MAC address. */
	uint64_t in_bcast_pkts;

	/** Number of inbound packets which were discarded due to a lack of free
	 *  resources (e.g. buffers) or other reasons than packet errors. */
	uint64_t in_discards;

	/** Number of inbound packets with errors. Depending on packet input
	 *  configuration, packets with errors may be dropped or not. */
	uint64_t in_errors;

	/**
	 * For packet-oriented interfaces, the number of packets received via
	 * the interface which were discarded because of an unknown or
	 * unsupported protocol.  For character-oriented or fixed-length
	 * interfaces that support protocol multiplexing the number of
	 * transmission units received via the interface which were discarded
	 * because of an unknown or unsupported protocol.  For any interface
	 * that does not support protocol multiplexing, this counter will always
	 * be 0. See ifInUnknownProtos in RFC 2863, RFC 3635.
	 *
	 * @deprecated This counter has been deprecated.
	 */
	uint64_t ODP_DEPRECATE(in_unknown_protos);

	/** Number of octets in successfully transmitted packets. In case of
	 *  Ethernet, packet size includes MAC header. */
	uint64_t out_octets;

	/** Number of successfully transmitted packets. */
	uint64_t out_packets;

	/** Number of successfully transmitted Ethernet packets with a unicast
	 *  destination MAC address. */
	uint64_t out_ucast_pkts;

	/** Number of successfully transmitted Ethernet packets with a multicast
	 *  destination MAC address. */
	uint64_t out_mcast_pkts;

	/** Number of successfully transmitted Ethernet packets with a broadcast
	 *  destination MAC address. */
	uint64_t out_bcast_pkts;

	/** Number of outbound packets which were discarded due to a lack of
	 *  free resources (e.g. buffers) or other reasons than errors. */
	uint64_t out_discards;

	/** Number of packets with transmission errors. */
	uint64_t out_errors;
} odp_pktio_stats_t;

/**
 * Packet IO input queue specific statistics counters
 *
 * Statistics counters for an individual packet input queue. Refer to packet IO
 * level statistics odp_pktio_stats_t for counter definitions.
 */
typedef struct odp_pktin_queue_stats_t {
	/** @see odp_pktio_stats_t::in_octets */
	uint64_t octets;

	/** @see odp_pktio_stats_t::in_packets */
	uint64_t packets;

	/** @see odp_pktio_stats_t::in_discards */
	uint64_t discards;

	/** @see odp_pktio_stats_t::in_errors */
	uint64_t errors;

} odp_pktin_queue_stats_t;

/**
 * Packet IO output queue specific statistics counters
 *
 * Statistics counters for an individual packet output queue. Refer to packet IO
 * level statistics odp_pktio_stats_t for counter definitions.
 */
typedef struct odp_pktout_queue_stats_t {
	/** @see odp_pktio_stats_t::out_octets */
	uint64_t octets;

	/** @see odp_pktio_stats_t::out_packets */
	uint64_t packets;

	/** @see odp_pktio_stats_t::out_discards */
	uint64_t discards;

	/** @see odp_pktio_stats_t::out_errors */
	uint64_t errors;

} odp_pktout_queue_stats_t;

/**
 * Packet IO statistics capabilities
 */
typedef struct odp_pktio_stats_capability_t {
	/** Interface level capabilities */
	struct {
		/** Supported counters */
		union {
			/** Statistics counters in a bit field structure */
			struct {
				/** @see odp_pktio_stats_t::in_octets */
				uint64_t in_octets          : 1;

				/** @see odp_pktio_stats_t::in_packets */
				uint64_t in_packets         : 1;

				/** @see odp_pktio_stats_t::in_ucast_pkts */
				uint64_t in_ucast_pkts      : 1;

				/** @see odp_pktio_stats_t::in_mcast_pkts */
				uint64_t in_mcast_pkts      : 1;

				/** @see odp_pktio_stats_t::in_bcast_pkts */
				uint64_t in_bcast_pkts      : 1;

				/** @see odp_pktio_stats_t::in_discards */
				uint64_t in_discards        : 1;

				/** @see odp_pktio_stats_t::in_errors */
				uint64_t in_errors          : 1;

				/** @see odp_pktio_stats_t::out_octets */
				uint64_t out_octets         : 1;

				/** @see odp_pktio_stats_t::out_packets */
				uint64_t out_packets        : 1;

				/** @see odp_pktio_stats_t::out_ucast_pkts */
				uint64_t out_ucast_pkts     : 1;

				/** @see odp_pktio_stats_t::out_mcast_pkts */
				uint64_t out_mcast_pkts     : 1;

				/** @see odp_pktio_stats_t::out_bcast_pkts */
				uint64_t out_bcast_pkts     : 1;

				/** @see odp_pktio_stats_t::out_discards */
				uint64_t out_discards       : 1;

				/** @see odp_pktio_stats_t::out_errors */
				uint64_t out_errors         : 1;
			} counter;

			/** All bits of the bit field structure
			 *
			 *  This field can be used to set/clear all flags, or
			 *  for bitwise operations over the entire structure. */
			uint64_t all_counters;
		};
	} pktio;

	/** Input queue level capabilities */
	struct {
		/** Supported counters */
		union {
			/** Statistics counters in a bit field structure */
			struct {
				/** @see odp_pktin_queue_stats_t::octets */
				uint64_t octets             : 1;

				/** @see odp_pktin_queue_stats_t::packets */
				uint64_t packets            : 1;

				/** @see odp_pktin_queue_stats_t::discards */
				uint64_t discards           : 1;

				/** @see odp_pktin_queue_stats_t::errors */
				uint64_t errors             : 1;
			} counter;

			/** All bits of the bit field structure
			 *
			 *  This field can be used to set/clear all flags, or
			 *  for bitwise operations over the entire structure. */
			uint64_t all_counters;
		};
	} pktin_queue;

	/** Output queue level capabilities */
	struct {
		/** Supported counters */
		union {
			/** Statistics counters in a bit field structure */
			struct {
				/** @see odp_pktout_queue_stats_t::octets */
				uint64_t octets             : 1;

				/** @see odp_pktout_queue_stats_t::packets */
				uint64_t packets            : 1;

				/** @see odp_pktout_queue_stats_t::discards */
				uint64_t discards           : 1;

				/** @see odp_pktout_queue_stats_t::errors */
				uint64_t errors             : 1;
			} counter;

			/** All bits of the bit field structure
			 *
			 *  This field can be used to set/clear all flags, or
			 *  for bitwise operations over the entire structure. */
			uint64_t all_counters;
		};
	} pktout_queue;

} odp_pktio_stats_capability_t;

/**
 * Get statistics for pktio handle
 *
 * Counters not supported by the interface are set to zero.
 *
 * @param       pktio	 Packet IO handle
 * @param[out]  stats	 Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_stats(odp_pktio_t pktio, odp_pktio_stats_t *stats);

/**
 * Get statistics for direct packet input queue
 *
 * Packet input queue handles can be requested with odp_pktin_queue(). Counters
 * not supported by the interface are set to zero.
 *
 * @param       queue	 Packet input queue handle
 * @param[out]  stats	 Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktin_queue_stats(odp_pktin_queue_t queue,
			  odp_pktin_queue_stats_t *stats);

/**
 * Get statistics for packet input event queue
 *
 * The queue must be a packet input event queue. Event queue handles can be
 * requested with odp_pktin_event_queue(). Counters not supported by the
 * interface are set to zero.
 *
 * @param       pktio	 Packet IO handle
 * @param       queue	 Packet input event queue handle
 * @param[out]  stats	 Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktin_event_queue_stats(odp_pktio_t pktio, odp_queue_t queue,
				odp_pktin_queue_stats_t *stats);

/**
 * Get statistics for direct packet output queue
 *
 * Packet output queue handles can be requested with odp_pktout_queue().
 * Counters not supported by the interface are set to zero.
 *
 * @param       queue	 Packet output queue handle
 * @param[out]  stats	 Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktout_queue_stats(odp_pktout_queue_t queue,
			   odp_pktout_queue_stats_t *stats);

/**
 * Get statistics for packet output event queue
 *
 * The queue must be a packet output event queue. Event queue handles can be
 * requested with odp_pktout_event_queue(). Counters not supported by the
 * interface are set to zero.
 *
 * @param       pktio	 Packet IO handle
 * @param       queue	 Packet output event queue handle
 * @param[out]  stats	 Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktout_event_queue_stats(odp_pktio_t pktio, odp_queue_t queue,
				 odp_pktout_queue_stats_t *stats);

/**
 * Reset statistics for pktio handle
 *
 * Reset all interface level statistics counters (odp_pktio_stats_t) to zero.
 * It's implementation defined if other packet IO related statistics are
 * affected.
 *
 * @param       pktio	 Packet IO handle
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_stats_reset(odp_pktio_t pktio);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
