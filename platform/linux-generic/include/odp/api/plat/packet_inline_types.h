/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PACKET_INLINE_TYPES_H_
#define ODP_PACKET_INLINE_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Packet field accessor */
#define _odp_pkt_get(pkt, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)pkt + _odp_packet_inline.field))

#define _odp_pkt_get_ptr(pkt, cast, field) \
	((cast *)(uintptr_t)((uint8_t *)pkt + _odp_packet_inline.field))

/* Packet header field offsets for inline functions */
typedef struct _odp_packet_inline_offset_t {
	uint16_t seg_data;
	uint16_t seg_len;
	uint16_t seg_next;
	uint16_t frame_len;
	uint16_t headroom;
	uint16_t tailroom;
	uint16_t pool;
	uint16_t input;
	uint16_t seg_count;
	uint16_t user_ptr;
	uint16_t user_area;
	uint16_t l2_offset;
	uint16_t l3_offset;
	uint16_t l4_offset;
	uint16_t flow_hash;
	uint16_t timestamp;
	uint16_t input_flags;
	uint16_t flags;
	uint16_t l4_type;
	uint16_t cls_mark;
	uint16_t ipsec_ctx;
	uint16_t crypto_op;

} _odp_packet_inline_offset_t;

extern const _odp_packet_inline_offset_t _odp_packet_inline;

/* Packet input & protocol flags */
typedef union {
	/* All input flags */
	uint64_t all;

	/* Individual input flags */
	struct {
		uint64_t cls_mark: 1; /* Classifier mark value present*/

		uint64_t flow_hash:1; /* Flow hash present */
		uint64_t timestamp:1; /* Timestamp present */

		uint64_t l2:1;        /* known L2 protocol present */
		uint64_t l3:1;        /* known L3 protocol present */
		uint64_t l4:1;        /* known L4 protocol present */

		uint64_t eth:1;       /* Ethernet */
		uint64_t eth_bcast:1; /* Ethernet broadcast */
		uint64_t eth_mcast:1; /* Ethernet multicast */
		uint64_t jumbo:1;     /* Jumbo frame */
		uint64_t vlan:1;      /* VLAN hdr found */
		uint64_t vlan_qinq:1; /* Stacked VLAN found, QinQ */

		uint64_t arp:1;       /* ARP */

		uint64_t ipv4:1;      /* IPv4 */
		uint64_t ipv6:1;      /* IPv6 */
		uint64_t ip_bcast:1;  /* IP broadcast */
		uint64_t ip_mcast:1;  /* IP multicast */
		uint64_t ipfrag:1;    /* IP fragment */
		uint64_t ipopt:1;     /* IP optional headers */

		uint64_t ipsec:1;     /* IPSec packet. Required by the
					   odp_packet_has_ipsec_set() func. */

		uint64_t color:2;     /* Packet color for traffic mgmt */
		uint64_t nodrop:1;    /* Drop eligibility status */

		uint64_t l3_chksum_done:1; /* L3 checksum validation done */
		uint64_t l4_chksum_done:1; /* L4 checksum validation done */
		uint64_t udp_chksum_zero:1; /* UDP header had 0 as chksum */
	};

} _odp_packet_input_flags_t;

/*
 * Additional packet flags
 */
typedef union {
	/* All flags */
	uint32_t all_flags;

	struct {
		uint32_t reserved1:      4;

	/*
	 * Init flags
	 */
		uint32_t user_ptr_set:   1; /* User has set a non-NULL value */
		uint32_t user_flag:      1;

	/*
	 * Packet output flags
	 */
		uint32_t lso:            1; /* LSO requested */
		uint32_t payload_off:    1; /* Payload offset is valid */
		uint32_t l3_chksum_set:  1; /* L3 chksum bit is valid */
		uint32_t l3_chksum:      1; /* L3 chksum override */
		uint32_t l4_chksum_set:  1; /* L4 chksum bit is valid */
		uint32_t l4_chksum:      1; /* L4 chksum override */
		uint32_t ts_set:         1; /* Set Tx timestamp */
		uint32_t tx_compl_ev:    1; /* Tx completion event requested */
		uint32_t tx_compl_poll:  1; /* Tx completion poll requested */
		uint32_t free_ctrl:      1; /* Don't free option */
		uint32_t tx_aging:       1; /* Packet aging at Tx requested */
		uint32_t shaper_len_adj: 8; /* Adjustment for traffic mgr */

	/*
	 * Error flags
	 */
		uint32_t snap_len_err:   1; /* Snap length error */
		uint32_t ip_err:         1; /* IP error */
		uint32_t l3_chksum_err:  1; /* L3 checksum error */
		uint32_t tcp_err:        1; /* TCP error */
		uint32_t udp_err:        1; /* UDP error */
		uint32_t sctp_err:       1; /* SCTP error */
		uint32_t l4_chksum_err:  1; /* L4 checksum error */
	};

	/* Flag groups */
	struct {
		uint32_t reserved2:      4;
		uint32_t other:         21; /* All other flags */
		uint32_t error:          7; /* All error flags */
	} all;

} _odp_packet_flags_t;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
