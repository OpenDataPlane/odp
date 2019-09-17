/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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

/* Flags for pkt_dpdk_t.supported_ptypes */
#define PTYPE_VLAN      0x01
#define PTYPE_VLAN_QINQ 0x02
#define PTYPE_ARP       0x04
#define PTYPE_IPV4      0x08
#define PTYPE_IPV6      0x10
#define PTYPE_UDP       0x20
#define PTYPE_TCP       0x40

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
				  uint32_t supported_ptypes,
				  odp_pktin_config_opt_t pktin_cfg);

static inline int _odp_dpdk_packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
					       struct rte_mbuf *mbuf,
					       odp_pktio_parser_layer_t layer,
					       uint32_t supported_ptypes,
					       odp_pktin_config_opt_t pktin_cfg)
{
	uint32_t seg_len = pkt_hdr->seg_len;
	void *base = pkt_hdr->seg_data;

	return _odp_dpdk_packet_parse_common(&pkt_hdr->p, base,
					     pkt_hdr->frame_len, seg_len, mbuf,
					     layer, supported_ptypes,
					     pktin_cfg);
}
#endif
