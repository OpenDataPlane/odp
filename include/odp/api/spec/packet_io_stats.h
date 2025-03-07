/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021-2022 Nokia
 */

/**
 * @file
 *
 * ODP Packet IO statistics
 */

#ifndef ODP_API_SPEC_PACKET_IO_STATS_H_
#define ODP_API_SPEC_PACKET_IO_STATS_H_
#include <odp/visibility_begin.h>

#include <odp/api/queue_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_packet_io
 *  @{
 */

/**
 * @def ODP_PKTIO_STATS_EXTRA_NAME_LEN
 * Maximum packet IO extra statistics counter name length, including the null
 * character
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
	/** See odp_pktio_stats_t::in_octets */
	uint64_t octets;

	/** See odp_pktio_stats_t::in_packets */
	uint64_t packets;

	/** See odp_pktio_stats_t::in_discards */
	uint64_t discards;

	/** See odp_pktio_stats_t::in_errors */
	uint64_t errors;

} odp_pktin_queue_stats_t;

/**
 * Packet IO output queue specific statistics counters
 *
 * Statistics counters for an individual packet output queue. Refer to packet IO
 * level statistics odp_pktio_stats_t for counter definitions.
 */
typedef struct odp_pktout_queue_stats_t {
	/** See odp_pktio_stats_t::out_octets */
	uint64_t octets;

	/** See odp_pktio_stats_t::out_packets */
	uint64_t packets;

	/** See odp_pktio_stats_t::out_discards */
	uint64_t discards;

	/** See odp_pktio_stats_t::out_errors */
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
				/** See odp_pktio_stats_t::in_octets */
				uint64_t in_octets          : 1;

				/** See odp_pktio_stats_t::in_packets */
				uint64_t in_packets         : 1;

				/** See odp_pktio_stats_t::in_ucast_pkts */
				uint64_t in_ucast_pkts      : 1;

				/** See odp_pktio_stats_t::in_mcast_pkts */
				uint64_t in_mcast_pkts      : 1;

				/** See odp_pktio_stats_t::in_bcast_pkts */
				uint64_t in_bcast_pkts      : 1;

				/** See odp_pktio_stats_t::in_discards */
				uint64_t in_discards        : 1;

				/** See odp_pktio_stats_t::in_errors */
				uint64_t in_errors          : 1;

				/** See odp_pktio_stats_t::out_octets */
				uint64_t out_octets         : 1;

				/** See odp_pktio_stats_t::out_packets */
				uint64_t out_packets        : 1;

				/** See odp_pktio_stats_t::out_ucast_pkts */
				uint64_t out_ucast_pkts     : 1;

				/** See odp_pktio_stats_t::out_mcast_pkts */
				uint64_t out_mcast_pkts     : 1;

				/** See odp_pktio_stats_t::out_bcast_pkts */
				uint64_t out_bcast_pkts     : 1;

				/** See odp_pktio_stats_t::out_discards */
				uint64_t out_discards       : 1;

				/** See odp_pktio_stats_t::out_errors */
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
				/** See odp_pktin_queue_stats_t::octets */
				uint64_t octets             : 1;

				/** See odp_pktin_queue_stats_t::packets */
				uint64_t packets            : 1;

				/** See odp_pktin_queue_stats_t::discards */
				uint64_t discards           : 1;

				/** See odp_pktin_queue_stats_t::errors */
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
				/** See odp_pktout_queue_stats_t::octets */
				uint64_t octets             : 1;

				/** See odp_pktout_queue_stats_t::packets */
				uint64_t packets            : 1;

				/** See odp_pktout_queue_stats_t::discards */
				uint64_t discards           : 1;

				/** See odp_pktout_queue_stats_t::errors */
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
 * Print extra statistics for a packet IO interface
 *
 * Print all packet IO device extra statistics to ODP log.
 *
 * @param       pktio    Packet IO handle
 */
void odp_pktio_extra_stats_print(odp_pktio_t pktio);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
