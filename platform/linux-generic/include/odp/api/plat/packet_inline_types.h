/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PACKET_INLINE_TYPES_H_
#define ODP_PACKET_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Packet field accessor */
#define _odp_pkt_get(pkt, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)pkt + _odp_packet_inline.field))

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
	uint16_t subtype;

} _odp_packet_inline_offset_t;

/* Packet input & protocol flags */
typedef union {
	/* All input flags */
	uint64_t all;

	/* Individual input flags */
	struct {
		uint64_t dst_queue:1; /* Dst queue present */

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

		uint64_t snap:1;      /* SNAP */
		uint64_t arp:1;       /* ARP */

		uint64_t ipv4:1;      /* IPv4 */
		uint64_t ipv6:1;      /* IPv6 */
		uint64_t ip_bcast:1;  /* IP broadcast */
		uint64_t ip_mcast:1;  /* IP multicast */
		uint64_t ipfrag:1;    /* IP fragment */
		uint64_t ipopt:1;     /* IP optional headers */

		uint64_t ipsec:1;     /* IPSec packet. Required by the
					   odp_packet_has_ipsec_set() func. */
		uint64_t ipsec_ah:1;  /* IPSec authentication header */
		uint64_t ipsec_esp:1; /* IPSec encapsulating security
					   payload */
		uint64_t udp:1;       /* UDP */
		uint64_t tcp:1;       /* TCP */
		uint64_t sctp:1;      /* SCTP */
		uint64_t icmp:1;      /* ICMP */
		uint64_t no_next_hdr:1; /* No Next Header */

		uint64_t color:2;     /* Packet color for traffic mgmt */
		uint64_t nodrop:1;    /* Drop eligibility status */

		uint64_t l3_chksum_done:1; /* L3 checksum validation done */
		uint64_t l4_chksum_done:1; /* L4 checksum validation done */
		uint64_t ipsec_udp:1; /* UDP-encapsulated IPsec packet */
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
		uint32_t reserved1:     10;

	/*
	 * Init flags
	 */
		uint32_t user_ptr_set:   1; /* User has set a non-NULL value */

	/*
	 * Packet output flags
	 */
		uint32_t l3_chksum_set:  1; /* L3 chksum bit is valid */
		uint32_t l3_chksum:      1; /* L3 chksum override */
		uint32_t l4_chksum_set:  1; /* L4 chksum bit is valid */
		uint32_t l4_chksum:      1; /* L4 chksum override  */
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
		uint32_t ipsec_err:      1; /* IPsec error */
		uint32_t crypto_err:     1; /* Crypto packet operation error */
	};

	/* Flag groups */
	struct {
		uint32_t reserved2:     10;
		uint32_t other:         13; /* All other flags */
		uint32_t error:          9; /* All error flags */
	} all;

} _odp_packet_flags_t;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
