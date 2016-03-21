/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <odp/api/packet_io.h>
#include <odp/api/pool.h>
#include <odp/api/ticketlock.h>

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

_ODP_STATIC_ASSERT((DPDK_NB_MBUF % DPDK_MEMPOOL_CACHE_SIZE == 0) &&
		   (DPDK_MEMPOOL_CACHE_SIZE <= RTE_MEMPOOL_CACHE_MAX_SIZE) &&
		   (DPDK_MEMPOOL_CACHE_SIZE <= DPDK_MBUF_BUF_SIZE * 10 / 15)
		   , "DPDK mempool cache size failure");
#endif

#define DPDK_IXGBE_MIN_RX_BURST 4

/** Cache for storing packets */
struct pkt_cache_t {
	/** array for storing extra RX packets */
	struct rte_mbuf *pkt[DPDK_IXGBE_MIN_RX_BURST];
	unsigned idx;			  /**< head of cache */
	unsigned count;			  /**< packets in cache */
};

typedef union {
	struct pkt_cache_t s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pkt_cache_t))];
} pkt_cache_t ODP_ALIGNED_CACHE;

/** Packet IO using DPDK interface */
typedef struct {
	odp_pool_t pool;		  /**< pool to alloc packets from */
	struct rte_mempool *pkt_pool;	  /**< DPDK packet pool */
	odp_pktio_capability_t	capa;	  /**< interface capabilities */
	uint32_t data_room;		  /**< maximum packet length */
	uint16_t mtu;			  /**< maximum transmission unit */
	/** DPDK packet pool name (pktpool_<ifname>) */
	char pool_name[IF_NAMESIZE + 8];
	odp_bool_t started;		  /**< DPDK device has been started */
	uint8_t port_id;		  /**< DPDK port identifier */
	unsigned min_rx_burst;		  /**< minimum RX burst size */
	odp_pktin_hash_proto_t hash;	  /**< Packet input hash protocol */
	odp_bool_t lockless_rx;		  /**< no locking for rx */
	odp_bool_t lockless_tx;		  /**< no locking for tx */
	odp_ticketlock_t rx_lock[PKTIO_MAX_QUEUES];  /**< RX queue locks */
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES];  /**< TX queue locks */
	/** cache for storing extra RX packets */
	pkt_cache_t rx_cache[PKTIO_MAX_QUEUES];
} pkt_dpdk_t;

#endif
