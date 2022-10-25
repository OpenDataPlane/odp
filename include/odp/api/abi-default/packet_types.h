/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_PACKET_TYPES_H_
#define ODP_ABI_PACKET_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_t;

/** @internal Dummy  type for strong typing */
typedef struct { char dummy; /**< *internal Dummy */ } _odp_abi_packet_seg_t;

/** @internal Dummy  type for strong typing */
typedef struct { char dummy; /**< *internal Dummy */ } _odp_abi_packet_buf_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< *internal Dummy */ } _odp_abi_packet_vector_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< *internal Dummy */ } _odp_abi_packet_tx_compl_t;

/** @ingroup odp_packet
 *  @{
 */

typedef _odp_abi_packet_t *odp_packet_t;
typedef _odp_abi_packet_seg_t *odp_packet_seg_t;
typedef _odp_abi_packet_buf_t *odp_packet_buf_t;
typedef _odp_abi_packet_vector_t *odp_packet_vector_t;
typedef _odp_abi_packet_tx_compl_t *odp_packet_tx_compl_t;

#define ODP_PACKET_INVALID        ((odp_packet_t)0)
#define ODP_PACKET_SEG_INVALID    ((odp_packet_seg_t)0)
#define ODP_PACKET_BUF_INVALID    ((odp_packet_buf_t)0)
#define ODP_PACKET_OFFSET_INVALID 0xffff
#define ODP_PACKET_VECTOR_INVALID   ((odp_packet_vector_t)0)
#define ODP_PACKET_TX_COMPL_INVALID ((odp_packet_tx_compl_t)0)

/** Packet Color */
typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

/** Packet Checksum Status */
typedef enum {
	ODP_PACKET_CHKSUM_UNKNOWN = 0,
	ODP_PACKET_CHKSUM_BAD,
	ODP_PACKET_CHKSUM_OK
} odp_packet_chksum_status_t;

/** Parse result flags */
typedef struct odp_packet_parse_result_flag_t {
	/** Flags union */
	union {
		/** All flags as a 64 bit word */
		uint64_t all;

		/** Flags as a bitfield struct */
		struct {
			/** @see odp_packet_has_error() */
			uint64_t has_error    : 1;
			/** @see odp_packet_has_l2_error() */
			uint64_t has_l2_error : 1;
			/** @see odp_packet_has_l3_error() */
			uint64_t has_l3_error : 1;
			/** @see odp_packet_has_l4_error() */
			uint64_t has_l4_error : 1;
			/** @see odp_packet_has_l2() */
			uint64_t has_l2 : 1;
			/** @see odp_packet_has_l3() */
			uint64_t has_l3 : 1;
			/** @see odp_packet_has_l4() */
			uint64_t has_l4 : 1;
			/** @see odp_packet_has_eth() */
			uint64_t has_eth : 1;
			/** @see odp_packet_has_eth_bcast() */
			uint64_t has_eth_bcast : 1;
			/** @see odp_packet_has_eth_mcast() */
			uint64_t has_eth_mcast : 1;
			/** @see odp_packet_has_jumbo() */
			uint64_t has_jumbo : 1;
			/** @see odp_packet_has_vlan() */
			uint64_t has_vlan : 1;
			/** @see odp_packet_has_vlan_qinq() */
			uint64_t has_vlan_qinq : 1;
			/** @see odp_packet_has_arp() */
			uint64_t has_arp : 1;
			/** @see odp_packet_has_ipv4() */
			uint64_t has_ipv4 : 1;
			/** @see odp_packet_has_ipv6() */
			uint64_t has_ipv6 : 1;
			/** @see odp_packet_has_ip_bcast() */
			uint64_t has_ip_bcast : 1;
			/** @see odp_packet_has_ip_mcast() */
			uint64_t has_ip_mcast : 1;
			/** @see odp_packet_has_ipfrag() */
			uint64_t has_ipfrag : 1;
			/** @see odp_packet_has_ipopt() */
			uint64_t has_ipopt : 1;
			/** @see odp_packet_has_ipsec() */
			uint64_t has_ipsec : 1;
			/** @see odp_packet_has_udp() */
			uint64_t has_udp : 1;
			/** @see odp_packet_has_tcp() */
			uint64_t has_tcp : 1;
			/** @see odp_packet_has_sctp() */
			uint64_t has_sctp : 1;
			/** @see odp_packet_has_icmp() */
			uint64_t has_icmp : 1;
		};
	};

} odp_packet_parse_result_flag_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
