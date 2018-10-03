/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <stdint.h>

#include <odp/api/packet_io.h>

#include <odp_packet_internal.h>
#include <odp_pool_internal.h>

struct rte_mbuf;

/**
 * Calculate size of zero-copy DPDK packet pool object
 */
uint32_t _odp_dpdk_pool_obj_size(pool_t *pool, uint32_t block_size);

/**
 * Create zero-copy DPDK packet pool
 */
int _odp_dpdk_pool_create(pool_t *pool);

/** Packet parser using DPDK interface */
int _odp_dpdk_packet_parse_common(packet_parser_t *pkt_hdr,
				  const uint8_t *ptr,
				  uint32_t pkt_len,
				  uint32_t seg_len,
				  struct rte_mbuf *mbuf,
				  int layer,
				  odp_pktin_config_opt_t pktin_cfg);

static inline int _odp_dpdk_packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
					       struct rte_mbuf *mbuf,
					       odp_pktio_parser_layer_t layer,
					       odp_pktin_config_opt_t pktin_cfg)
{
	uint32_t seg_len = pkt_hdr->buf_hdr.seg[0].len;
	void *base = pkt_hdr->buf_hdr.seg[0].data;

	return _odp_dpdk_packet_parse_common(&pkt_hdr->p, base,
					     pkt_hdr->frame_len, seg_len, mbuf,
					     layer, pktin_cfg);
}
#endif
