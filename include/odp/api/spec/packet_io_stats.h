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

	/** Number of outbound packets which were discarded due to a lack of
	 *  free resources (e.g. buffers) or other reasons than errors. */
	uint64_t out_discards;

	/** Number of packets with transmission errors. */
	uint64_t out_errors;
} odp_pktio_stats_t;

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
 * Reset statistics for pktio handle
 *
 * Reset all statistics counters to zero.
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
