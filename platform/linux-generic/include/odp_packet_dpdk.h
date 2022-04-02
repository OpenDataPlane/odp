/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
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

/** Packet parser using DPDK interface */
int _odp_dpdk_packet_parse_common(packet_parser_t *pkt_hdr,
				  const uint8_t *ptr,
				  uint32_t pkt_len,
				  uint32_t seg_len,
				  struct rte_mbuf *mbuf,
				  int layer,
				  uint32_t supported_ptypes,
				  odp_pktin_config_opt_t pktin_cfg);

#endif
