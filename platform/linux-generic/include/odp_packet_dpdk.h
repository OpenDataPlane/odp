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

/** Packet parser using DPDK interface */
int _odp_dpdk_packet_parse_common(odp_packet_hdr_t *pkt_hdr,
				  const uint8_t *ptr,
				  uint32_t pkt_len,
				  uint32_t seg_len,
				  struct rte_mbuf *mbuf,
				  int layer,
				  odp_pktin_config_opt_t pktin_cfg);

#endif
