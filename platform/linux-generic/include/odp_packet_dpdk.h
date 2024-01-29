/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2022 Nokia
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <stdint.h>

#include <odp/api/packet_io.h>

#include <odp_packet_internal.h>
#include <odp_parse_internal.h>

#include <rte_mbuf.h>

#define IP4_CSUM_RESULT(ol_flags) ((ol_flags) & RTE_MBUF_F_RX_IP_CKSUM_MASK)
#define L4_CSUM_RESULT(ol_flags) ((ol_flags) & RTE_MBUF_F_RX_L4_CKSUM_MASK)

/** Packet parser using DPDK interface */
static inline
int _odp_dpdk_packet_parse_common(odp_packet_hdr_t *pkt_hdr, const uint8_t *ptr,
				  uint32_t frame_len, uint32_t seg_len,
				  struct rte_mbuf *mbuf, int layer,
				  odp_pktin_config_opt_t pktin_cfg)
{
	packet_parser_t *prs = &pkt_hdr->p;
	uint64_t mbuf_ol = mbuf->ol_flags;

	if (odp_unlikely(layer == ODP_PROTO_LAYER_NONE))
		return 0;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	prs->l2_offset = 0;

	if (layer >= ODP_PROTO_LAYER_L3) {
		int ip_chksum = IP4_CSUM_RESULT(mbuf_ol);

		if (ip_chksum == RTE_MBUF_F_RX_IP_CKSUM_GOOD) {
			prs->input_flags.l3_chksum_done = 1;
		} else if (ip_chksum != RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN) {
			prs->input_flags.l3_chksum_done = 1;
			prs->flags.l3_chksum_err = 1;
		}
	}

	if (layer >= ODP_PROTO_LAYER_L4) {
		int l4_chksum = L4_CSUM_RESULT(mbuf_ol);

		if (l4_chksum == RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
			prs->input_flags.l4_chksum_done = 1;
		} else if (l4_chksum != RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN) {
			prs->input_flags.l4_chksum_done = 1;
			prs->flags.l4_chksum_err = 1;
		}
	}

	pktin_cfg.bit.ipv4_chksum = 0;
	pktin_cfg.bit.udp_chksum = 0;
	pktin_cfg.bit.tcp_chksum = 0;
	pktin_cfg.bit.sctp_chksum = 0;

	return _odp_packet_parse_common(pkt_hdr, ptr, frame_len, seg_len, layer,
					pktin_cfg);
}

#endif
