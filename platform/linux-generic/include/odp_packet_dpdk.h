/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <odp/api/packet_io.h>
#include <odp/api/pool.h>

#include <net/if.h>

#ifdef ODP_PKTIO_DPDK
#include <rte_config.h>
#include <rte_mbuf.h>

#define DPDK_MEMORY_MB 512
#define DPDK_NB_MBUF 16384
#define DPDK_MBUF_BUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define DPDK_MEMPOOL_CACHE_SIZE 32
#define DPDK_NM_RX_DESC  128
#define DPDK_NM_TX_DESC  512

_ODP_STATIC_ASSERT(DPDK_NB_MBUF % DPDK_MEMPOOL_CACHE_SIZE == 0 &&
		   DPDK_MEMPOOL_CACHE_SIZE <= RTE_MEMPOOL_CACHE_MAX_SIZE &&
		   DPDK_MEMPOOL_CACHE_SIZE <= DPDK_MBUF_BUF_SIZE / 1.5
		   , "DPDK mempool cache size failure");
#endif

/** Packet IO using DPDK interface */
typedef struct {
	odp_pool_t pool;		  /**< pool to alloc packets from */
	struct rte_mempool *pkt_pool;	  /**< DPDK packet pool */
	odp_pktio_capability_t	capa;	  /**< interface capabilities */
	uint32_t data_room;		  /**< maximum packet length */
	/** DPDK packet pool name (pktpool_<ifname>) */
	char pool_name[IF_NAMESIZE + 8];
	uint8_t port_id;		  /**< DPDK port identifier */
} pkt_dpdk_t;

#endif
