/* Copyright (c) 2016-2018, Linaro Limited
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
#define DPDK_MEMPOOL_CACHE_SIZE 64

ODP_STATIC_ASSERT((DPDK_NB_MBUF % DPDK_MEMPOOL_CACHE_SIZE == 0) &&
		  (DPDK_MEMPOOL_CACHE_SIZE <= RTE_MEMPOOL_CACHE_MAX_SIZE) &&
		  (DPDK_MEMPOOL_CACHE_SIZE <= DPDK_MBUF_BUF_SIZE * 10 / 15)
		  , "DPDK mempool cache size failure");
#endif

/* Minimum RX burst size */
#define DPDK_MIN_RX_BURST 4

/** DPDK runtime configuration options */
typedef struct {
	int num_rx_desc;
	int num_tx_desc;
	int rx_drop_en;
} dpdk_opt_t;

/** Cache for storing packets */
struct pkt_cache_t {
	/** array for storing extra RX packets */
	struct rte_mbuf *pkt[DPDK_MIN_RX_BURST];
	unsigned idx;			  /**< head of cache */
	unsigned count;			  /**< packets in cache */
};

typedef union ODP_ALIGNED_CACHE {
	struct pkt_cache_t s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct pkt_cache_t))];
} pkt_cache_t;

/** Packet IO using DPDK interface */
typedef struct ODP_ALIGNED_CACHE {
	odp_pool_t pool;		  /**< pool to alloc packets from */
	struct rte_mempool *pkt_pool;	  /**< DPDK packet pool */
	uint32_t data_room;		  /**< maximum packet length */
	unsigned min_rx_burst;		  /**< minimum RX burst size */
	odp_pktin_hash_proto_t hash;	  /**< Packet input hash protocol */
	uint16_t mtu;			  /**< maximum transmission unit */
	uint16_t port_id;		  /**< DPDK port identifier */
	/** Use system call to get/set vdev promisc mode */
	uint8_t vdev_sysc_promisc;
	uint8_t lockless_rx;		  /**< no locking for rx */
	uint8_t lockless_tx;		  /**< no locking for tx */
	  /** RX queue locks */
	odp_ticketlock_t ODP_ALIGNED_CACHE rx_lock[PKTIO_MAX_QUEUES];
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES];  /**< TX queue locks */
	/** cache for storing extra RX packets */
	pkt_cache_t rx_cache[PKTIO_MAX_QUEUES];
	dpdk_opt_t opt;
} pkt_dpdk_t;

/** Packet parser using DPDK interface */
int dpdk_packet_parse_common(packet_parser_t *pkt_hdr,
			     const uint8_t *ptr,
			     uint32_t pkt_len,
			     uint32_t seg_len,
			     struct rte_mbuf *mbuf,
			     int layer);

static inline int dpdk_packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
					  struct rte_mbuf *mbuf,
					  odp_pktio_parser_layer_t layer)
{
	uint32_t seg_len = pkt_hdr->buf_hdr.seg[0].len;
	void *base = pkt_hdr->buf_hdr.seg[0].data;

	return dpdk_packet_parse_common(&pkt_hdr->p, base, pkt_hdr->frame_len,
					seg_len, mbuf, layer);
}
#endif
