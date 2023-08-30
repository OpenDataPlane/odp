/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Marvell
 */

/**
 * @file
 *
 * ODP REASSEMBLY API
 */

#ifndef ODP_API_SPEC_REASSEMBLY_H_
#define ODP_API_SPEC_REASSEMBLY_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @defgroup odp_reassembly ODP REASSEMBLY
 *  Reassembly
 *  @{
 */

/**
 * Reassembly capabilities
 *
 */
typedef struct odp_reass_capability_t {
	/** Reassembly offload for both IPv4 and IPv6 packets. This capability
	 *  does not allow enabling reassembly for only IPv4 or only IPv6.
	 */
	odp_bool_t ip;

	/** Reassembly offload for IPv4 packets */
	odp_bool_t ipv4;

	/** Reassembly offload for IPv6 packets */
	odp_bool_t ipv6;

	/** Maximum time in ns that a fragment can wait in the reassembly
	 *  offload for the arrival of further fragments.
	 */
	uint64_t max_wait_time;

	/** Maximum number of fragments that can be reassembled */
	uint16_t max_num_frags;

} odp_reass_capability_t;

/**
 * Fragment reassembly configuration
 *
 * Configure inline fragment reassembly offload support. Fragment
 * reassembly offload can be enabled in IPSEC and PKTIN operations.
 *
 * When the offload is enabled, fragments will be delayed for a specified time
 * period to allow reassembly.
 *
 * Reassembly result will be delivered to the application through an ODP packet
 * with reassembly metadata. odp_packet_reass_status() can be used to query if
 * reassembly has been attempted and if reassembly was successfully completed.
 *
 * In case of successful reassembly, the reassembled packet is delivered
 * to the receiver as a regular ODP packet as if the reassembled packet
 * was received as such. When reassembly is enabled in pktio, it will be
 * attempted before other offloads such as packet parsing, inline IPsec and
 * classification.
 *
 * In case of failed reassembly, the result is delivered to the application
 * as a special packet that does not contain valid packet data. Such a
 * packet can be used to get information of the incomplete reassembly
 * so that the application can try to retry or continue the reassembly.
 * See odp_packet_reass_partial_state().
 *
 * Reassembly may not complete if not all fragments were received in time but
 * also for packet parsing difficulty, fragment overlap, resource shortage or
 * other reasons. In such cases, application may receive packets with reassembly
 * status as either ``ODP_PACKET_REASS_NONE`` or ``ODP_PACKET_REASS_INCOMPLETE``.
 *
 * This structure is used only for configuration, not for capability
 * query even though it is indirectly contained in odp_pktio_capability_t.
 * The content of odp_pktio_capability_t.config.reassembly written by
 * odp_pktio_capability() is undefined. Reassembly capabilities of a pktio
 * can be checked through odp_pktio_capability_t.reassembly.
 *
 * @see odp_packet_reass_status(), odp_packet_reass_partial_state()
 */
typedef struct odp_reass_config_t {
	/** Attempt inline reassembly of IPv4 packets. Disabled by default.
	 *  This may be set if the relevant odp_reass_capability_t::ipv4
	 *  capability is present or if odp_reass_capability_t::ip capability
	 *  is present and en_ipv6 is also set.
	 */
	odp_bool_t en_ipv4;

	/** Attempt inline reassembly of IPv6 packets. Disabled by default.
	 *  This may be set if the relevant odp_reass_capability_t::ipv6
	 *  capability is present or if odp_reass_capability_t::ip capability
	 *  is present and en_ipv4 is also set.
	 */
	odp_bool_t en_ipv6;

	/** Maximum time in ns that a fragment may wait in the reassembly
	 *  offload for the arrival of further fragments. The value may
	 *  not exceed the max_wait_time capability. Zero value means
	 *  implementation defined maximum wait time.
	 *
	 *  Default value is 0.
	 */
	uint64_t max_wait_time;

	/** Maximum number of fragments that can be reassembled
	 *
	 *  Minimum allowed value is 2. Default value is 2.
	 */
	uint16_t max_num_frags;
} odp_reass_config_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
