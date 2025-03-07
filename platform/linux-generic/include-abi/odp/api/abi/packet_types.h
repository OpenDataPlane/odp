/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2021 Nokia
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_API_ABI_PACKET_TYPES_H_
#define ODP_API_ABI_PACKET_TYPES_H_

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_packet
 *  @{
 */

typedef ODP_HANDLE_T(odp_packet_t);

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, 0)

#define ODP_PACKET_OFFSET_INVALID 0xffff

typedef ODP_HANDLE_T(odp_packet_seg_t);

#define ODP_PACKET_SEG_INVALID _odp_cast_scalar(odp_packet_seg_t, 0)

typedef ODP_HANDLE_T(odp_packet_buf_t);

#define ODP_PACKET_BUF_INVALID _odp_cast_scalar(odp_packet_buf_t, 0)

typedef ODP_HANDLE_T(odp_packet_vector_t);

#define ODP_PACKET_VECTOR_INVALID _odp_cast_scalar(odp_packet_vector_t, 0)

typedef ODP_HANDLE_T(odp_packet_tx_compl_t);

#define ODP_PACKET_TX_COMPL_INVALID _odp_cast_scalar(odp_packet_tx_compl_t, 0)

#define ODP_PACKET_OFFSET_INVALID 0xffff

typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

typedef enum {
	ODP_PACKET_CHKSUM_UNKNOWN = 0,
	ODP_PACKET_CHKSUM_BAD,
	ODP_PACKET_CHKSUM_OK
} odp_packet_chksum_status_t;

typedef struct odp_packet_parse_result_flag_t {
	union {
		uint64_t all;

		struct {
			uint64_t has_error    : 1;
			uint64_t has_l2_error : 1;
			uint64_t has_l3_error : 1;
			uint64_t has_l4_error : 1;
			uint64_t has_l2 : 1;
			uint64_t has_l3 : 1;
			uint64_t has_l4 : 1;
			uint64_t has_eth : 1;
			uint64_t has_eth_bcast : 1;
			uint64_t has_eth_mcast : 1;
			uint64_t has_jumbo : 1;
			uint64_t has_vlan : 1;
			uint64_t has_vlan_qinq : 1;
			uint64_t has_arp : 1;
			uint64_t has_ipv4 : 1;
			uint64_t has_ipv6 : 1;
			uint64_t has_ip_bcast : 1;
			uint64_t has_ip_mcast : 1;
			uint64_t has_ipfrag : 1;
			uint64_t has_ipopt : 1;
			uint64_t has_ipsec : 1;
			uint64_t has_udp : 1;
			uint64_t has_tcp : 1;
			uint64_t has_sctp : 1;
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
