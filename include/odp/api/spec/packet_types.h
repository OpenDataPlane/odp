/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet types
 */

#ifndef ODP_API_SPEC_PACKET_TYPES_H_
#define ODP_API_SPEC_PACKET_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/proto_stats_types.h>
#include <odp/api/queue_types.h>

/** @addtogroup odp_packet
 *  @{
 */

/**
 * @typedef odp_packet_t
 * ODP packet
 */

/**
 * @def ODP_PACKET_INVALID
 * Invalid packet
 */

/**
 * @def ODP_PACKET_OFFSET_INVALID
 * Invalid packet offset
 */

/**
 * @typedef odp_packet_seg_t
 * ODP packet segment
 *
 * A packet segment refers to a contiguous part of packet data (in memory). Segments of a packet
 * can be examined with odp_packet_seg_data(), odp_packet_seg_data_len() and other calls.
 */

/**
 * @def ODP_PACKET_SEG_INVALID
 * Invalid packet segment
 */

/**
 * @typedef odp_packet_buf_t
 * ODP packet buffer
 *
 * Packet buffers are not part of any packet, but they result from a previous
 * odp_packet_disassemble() call. A new packet is formed from packet buffers with
 * a odp_packet_reassemble() call.
 */

/**
 * @def ODP_PACKET_BUF_INVALID
 * Invalid packet buffer
 */

/**
 * @typedef odp_packet_color_t
 * Color of packet for shaper/drop processing
 *
 * @var ODP_PACKET_GREEN
 * Packet is green
 *
 * @var ODP_PACKET_YELLOW
 * Packet is yellow
 *
 * @var ODP_PACKET_RED
 * Packet is red
 */

/**
 * Maximum number of packet colors which accommodates ODP_PACKET_GREEN, ODP_PACKET_YELLOW and
 * ODP_PACKET_RED.
 */
#define ODP_NUM_PACKET_COLORS 3

/**
 * Layer 2 protocol type
 */
typedef uint8_t odp_proto_l2_type_t;

/** Layer 2 protocol type not defined */
#define ODP_PROTO_L2_TYPE_NONE      0

 /** Layer 2 protocol is Ethernet */
#define ODP_PROTO_L2_TYPE_ETH       1

/**
 * Layer 3 protocol type
 */
typedef uint16_t odp_proto_l3_type_t;

/** Layer 3 protocol type not defined */
#define ODP_PROTO_L3_TYPE_NONE      0xFFFF

/* Types from IEEE EtherType assignments list */

/** Layer 3 protocol is ARP */
#define ODP_PROTO_L3_TYPE_ARP       0x0806

/** Layer 3 protocol is RARP */
#define ODP_PROTO_L3_TYPE_RARP      0x8035

/** Layer 3 protocol is MPLS */
#define ODP_PROTO_L3_TYPE_MPLS      0x8847

/** Layer 3 protocol type is IPv4 */
#define ODP_PROTO_L3_TYPE_IPV4      0x0800

/** Layer 3 protocol type is IPv6 */
#define ODP_PROTO_L3_TYPE_IPV6      0x86DD

/**
 * Layer 4 protocol type
 */
typedef uint8_t odp_proto_l4_type_t;

/** Layer 4 protocol type not defined */
 #define ODP_PROTO_L4_TYPE_NONE     255

/* Types from IANA assigned Internet protocol numbers list */

/** Layer 4 protocol type is ICMPv4 */
 #define ODP_PROTO_L4_TYPE_ICMPV4   1

/** Layer 4 protocol type is IGMP */
#define ODP_PROTO_L4_TYPE_IGMP      2

/** Layer 4 protocol type is IPv4 */
#define ODP_PROTO_L4_TYPE_IPV4      4

/** Layer 4 protocol type is TCP */
 #define ODP_PROTO_L4_TYPE_TCP      6

/** Layer 4 protocol type is UDP */
#define ODP_PROTO_L4_TYPE_UDP       17

/** Layer 4 protocol type is IPv6 */
#define ODP_PROTO_L4_TYPE_IPV6      41

/** Layer 4 protocol type is GRE */
#define ODP_PROTO_L4_TYPE_GRE       47

/** Layer 4 protocol type is IPSEC ESP */
#define ODP_PROTO_L4_TYPE_ESP       50

/** Layer 4 protocol type is IPSEC AH */
#define ODP_PROTO_L4_TYPE_AH        51

/** Layer 4 protocol type is ICMPv6 */
#define ODP_PROTO_L4_TYPE_ICMPV6    58

/** Layer 4 protocol type is No Next Header for IPv6 */
#define ODP_PROTO_L4_TYPE_NO_NEXT   59

/** Layer 4 protocol type is IP Payload Compression Protocol */
#define ODP_PROTO_L4_TYPE_IPCOMP    108

/** Layer 4 protocol type is SCTP */
#define ODP_PROTO_L4_TYPE_SCTP      132

/** Layer 4 protocol type is ROHC */
#define ODP_PROTO_L4_TYPE_ROHC      142

/**
 * @typedef odp_packet_chksum_status_t
 * Checksum check status in packet
 *
 * @var ODP_PACKET_CHKSUM_UNKNOWN
 * Checksum was not checked. Checksum check was not
 * attempted or the attempt failed.
 *
 * @var ODP_PACKET_CHKSUM_BAD
 * Checksum was checked and it was not correct.
 *
 * @var ODP_PACKET_CHKSUM_OK
 * Checksum was checked and it was correct.
 */

/**
 * @typedef odp_packet_vector_t
 * ODP packet vector
 */

/**
 * @def ODP_PACKET_VECTOR_INVALID
 * Invalid packet vector
 */

/**
 * @typedef odp_packet_tx_compl_t
 * ODP Packet Tx completion
 */

/**
 * @def ODP_PACKET_TX_COMPL_INVALID
 * Invalid packet Tx completion
 */

/**
 * Protocol
 */
typedef enum odp_proto_t {
	/** No protocol defined */
	ODP_PROTO_NONE = 0,

	/** Ethernet (including VLAN) */
	ODP_PROTO_ETH,

	/** IP version 4 */
	ODP_PROTO_IPV4,

	/** IP version 6 */
	ODP_PROTO_IPV6

} odp_proto_t;

/**
 * Protocol layer
 */
typedef enum odp_proto_layer_t {
	/** No layers */
	ODP_PROTO_LAYER_NONE = 0,

	/** Layer L2 protocols (Ethernet, VLAN, etc) */
	ODP_PROTO_LAYER_L2,

	/** Layer L3 protocols (IPv4, IPv6, ICMP, IPSEC, etc) */
	ODP_PROTO_LAYER_L3,

	/** Layer L4 protocols (UDP, TCP, SCTP) */
	ODP_PROTO_LAYER_L4,

	/** All layers */
	ODP_PROTO_LAYER_ALL

} odp_proto_layer_t;

/**
 * Packet API data range specifier
 */
typedef struct odp_packet_data_range {
	/** Offset from beginning of packet */
	uint32_t offset;

	/** Length of data to operate on */
	uint32_t length;

} odp_packet_data_range_t;

/**
 * Reassembly status of a packet
 */
typedef enum odp_packet_reass_status_t {
	/** Reassembly was not attempted */
	ODP_PACKET_REASS_NONE = 0,

	/** Reassembly was attempted but is incomplete. Partial reassembly
	  * result can be accessed using ``odp_packet_reass_partial_state()``.
	  *
	  * The packet does not contain valid packet data and cannot be used
	  * in normal packet operations.
	  */
	ODP_PACKET_REASS_INCOMPLETE,

	/** Reassembly was successfully done. The packet has been
	 *  reassembled from multiple received fragments. */
	ODP_PACKET_REASS_COMPLETE,
} odp_packet_reass_status_t;

/**
 * Information about a completed reassembly
 */
typedef struct odp_packet_reass_info_t {
	/** Number of fragments reassembled */
	uint16_t num_frags;
} odp_packet_reass_info_t;

/**
 * Result from odp_packet_reass_partial_state()
 */
typedef struct odp_packet_reass_partial_state_t {
	/** Number of fragments returned */
	uint16_t num_frags;

	/** Time, in ns, since the reception of the first received fragment */
	uint64_t elapsed_time;
} odp_packet_reass_partial_state_t;

/**
 * Flags to control packet data checksum checking
 */
typedef union odp_proto_chksums_t {
	/** Individual checksum bits. */
	struct {
		/** IPv4 header checksum */
		uint32_t ipv4   : 1;

		/** UDP checksum */
		uint32_t udp    : 1;

		/** TCP checksum */
		uint32_t tcp    : 1;

		/** SCTP checksum */
		uint32_t sctp   : 1;

	} chksum;

	/** All checksum bits
	 *
	 *  This field can be used to set/clear all flags, or to perform bitwise
	 *  operations over those. */
	uint32_t all_chksum;

} odp_proto_chksums_t;

/**
 * Packet parse parameters
 */
typedef struct odp_packet_parse_param_t {
	/** Protocol header at parse starting point. Valid values for this
	 *  field are: ODP_PROTO_ETH, ODP_PROTO_IPV4, ODP_PROTO_IPV6. */
	odp_proto_t proto;

	/** Continue parsing until this layer. Must be the same or higher
	 *  layer than the layer of 'proto'. */
	odp_proto_layer_t last_layer;

	/** Flags to control payload data checksums checks up to the selected
	 *  parse layer. Checksum checking status can be queried for each packet
	 *  with odp_packet_l3_chksum_status() and
	 *  odp_packet_l4_chksum_status().
	 */
	odp_proto_chksums_t chksums;

} odp_packet_parse_param_t;

/**
 * Packet parse results
 */
typedef struct odp_packet_parse_result_t {
	/** Parse result flags */
	odp_packet_parse_result_flag_t flag;

	/** See odp_packet_len() */
	uint32_t packet_len;

	/** See odp_packet_l2_offset() */
	uint32_t l2_offset;
	/** See odp_packet_l3_offset() */
	uint32_t l3_offset;
	/** See odp_packet_l4_offset() */
	uint32_t l4_offset;

	/** See odp_packet_l3_chksum_status() */
	odp_packet_chksum_status_t l3_chksum_status;
	/** See odp_packet_l4_chksum_status() */
	odp_packet_chksum_status_t l4_chksum_status;

	/** See odp_packet_l2_type() */
	odp_proto_l2_type_t l2_type;
	/** See odp_packet_l3_type() */
	odp_proto_l3_type_t l3_type;
	/** See odp_packet_l4_type() */
	odp_proto_l4_type_t l4_type;

} odp_packet_parse_result_t;

/**
 * LSO options
 */
typedef struct odp_packet_lso_opt_t {
	/** LSO profile handle
	 *
	 * The selected LSO profile specifies details of the segmentation operation to be done.
	 * Depending on LSO profile options, additional metadata (e.g. L3/L4 protocol header
	 * offsets) may need to be set on the packet. See LSO documentation
	 * (e.g. odp_pktout_send_lso() and odp_lso_protocol_t) for additional metadata
	 * requirements.
	 */
	odp_lso_profile_t lso_profile;

	/** LSO payload offset
	 *
	 *  LSO operation considers packet data before 'payload_offset' as
	 *  protocol headers and copies those in front of every created segment. It will modify
	 *  protocol headers according to the LSO profile before segment transmission.
	 *
	 *  When stored into a packet, this offset can be read with odp_packet_payload_offset() and
	 *  modified with odp_packet_payload_offset_set().
	 */
	uint32_t payload_offset;

	/** Maximum payload length in an LSO segment
	 *
	 *  Max_payload_len parameter defines the maximum number of payload bytes in each
	 *  created segment. Depending on the implementation, segments with less payload may be
	 *  created. However, this value is used typically to divide packet payload evenly over
	 *  all segments except the last one, which contains the remaining payload bytes.
	 */
	uint32_t max_payload_len;

} odp_packet_lso_opt_t;

/**
 * Packet Tx completion mode
 */
typedef enum odp_packet_tx_compl_mode_t {
	/** Packet Tx completion event is disabled
	 *
	 * When mode is disabled, all other fields of odp_packet_tx_compl_opt_t are ignored.
	 */
	ODP_PACKET_TX_COMPL_DISABLED,
	/** Packet Tx completion event is sent for all packets (both transmitted and dropped) */
	ODP_PACKET_TX_COMPL_ALL,
} odp_packet_tx_compl_mode_t;

/**
 * Tx completion request options
 */
typedef struct odp_packet_tx_compl_opt_t {
	/** Queue handle
	 *
	 * Tx completion event will be posted to ODP queue identified by this handle.
	 */
	odp_queue_t queue;

	/** Packet Tx completion event mode */
	odp_packet_tx_compl_mode_t mode;

} odp_packet_tx_compl_opt_t;

/**
 * Packet proto stats options
 */
typedef struct odp_packet_proto_stats_opt_t {
	/** Packet proto stats object handle
	 *
	 * Stats in the packet proto stats object will be updated.
	 */
	odp_proto_stats_t stat;

	/** Octet counter 0 adjust */
	int32_t oct_count0_adj;

	/** Octet counter 1 adjust */
	int32_t oct_count1_adj;
} odp_packet_proto_stats_opt_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
