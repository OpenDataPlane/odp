/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <odp/api/packet_io.h>

struct rte_mbuf;

/** Cache for storing packets */
/** Packet parser using DPDK interface */
int dpdk_packet_parse_common(packet_parser_t *pkt_hdr,
			     const uint8_t *ptr,
			     uint32_t pkt_len,
			     uint32_t seg_len,
			     struct rte_mbuf *mbuf,
			     int layer,
			     odp_pktin_config_opt_t pktin_cfg);

static inline int dpdk_packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
					  struct rte_mbuf *mbuf,
					  odp_pktio_parser_layer_t layer,
					  odp_pktin_config_opt_t pktin_cfg)
{
	uint32_t seg_len = pkt_hdr->buf_hdr.seg[0].len;
	void *base = pkt_hdr->buf_hdr.seg[0].data;

	return dpdk_packet_parse_common(&pkt_hdr->p, base, pkt_hdr->frame_len,
					seg_len, mbuf, layer, pktin_cfg);
}
#endif
