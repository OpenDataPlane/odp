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
 * @def ODP_PKTIO_STATS_EXTRA_NAME_LEN
 * Maximum packet IO extra statistics counter name length in chars including
 * null char
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
	 *  Ethernet, packet size includes MAC header and FCS. */
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
	 *  Ethernet, packet size includes MAC header and FCS. */
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
 * Packet IO extra statistics counter information
 */
typedef struct odp_pktio_extra_stat_info_t {
	/** Name of the counter */
	char name[ODP_PKTIO_STATS_EXTRA_NAME_LEN];

} odp_pktio_extra_stat_info_t;

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
 * Get extra statistics counter information for a packet IO interface
 *
 * Returns the number of implementation specific packet IO extra statistics
 * counters supported by the interface. Outputs up to 'num' extra statistics
 * counter info structures when the 'info' array pointer is not NULL. If the
 * return value is larger than 'num', there are more extra counters than the
 * function was allowed to output. If the return value (N) is less than 'num',
 * only info[0 ... N-1] have been written.
 *
 * The index of a counter in the 'info' array can be used to read the value of
 * the individual counter with odp_pktio_extra_stat_counter(). The order of
 * counters in the output array matches with odp_pktio_extra_stats().
 *
 * @param       pktio    Packet IO handle
 * @param[out]  info     Array of extra statistics info structs for output
 * @param       num      Maximum number of info structs to output
 *
 * @return Number of extra statistics
 * @retval <0 on failure
 */
int odp_pktio_extra_stat_info(odp_pktio_t pktio,
			      odp_pktio_extra_stat_info_t info[], int num);

/**
 * Get extra statistics for a packet IO interface
 *
 * Returns the number of implementation specific packet IO extra statistics
 * counters supported by the interface. Outputs up to 'num' counters when the
 * 'stats' array pointer is not NULL. If the return value is larger than 'num',
 * there are more counters than the function was allowed to output. If the
 * return value (N) is less than 'num', only stats[0 ... N-1] have been written.
 *
 * The index of a counter in the 'stats' array can be used to read the value of
 * the individual counter with odp_pktio_extra_stat_counter(). The order of
 * counters in the output array matches with odp_pktio_extra_stat_info().
 *
 * @param       pktio    Packet IO handle
 * @param[out]  stats    Array of extra statistics for output
 * @param       num      Maximum number of extra statistics to output
 *
 * @return Number of extra statistics
 * @retval <0 on failure
 */
int odp_pktio_extra_stats(odp_pktio_t pktio, uint64_t stats[], int num);

/**
 * Get extra statistic counter value
 *
 * 'id' is the index of the particular counter in the output array of
 * odp_pktio_extra_stat_info() or odp_pktio_extra_stats().
 *
 *
 * @param       pktio    Packet IO handle
 * @param       id       ID of the extra statistics counter
 * @param[out]  stat     Pointer for statistic counter output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_extra_stat_counter(odp_pktio_t pktio, uint32_t id,
				 uint64_t *stat);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
