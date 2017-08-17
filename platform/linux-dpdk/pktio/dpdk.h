/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_OPS_DPDK_H_
#define ODP_PKTIO_OPS_DPDK_H_

#include <stdint.h>
#include <net/if.h>

#include <protocols/eth.h>
#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp/api/std_types.h>

#include <rte_config.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>

#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

/** Packet socket using dpdk mmaped rings for both Rx and Tx */
typedef struct {
	odp_pktio_capability_t capa;	/**< interface capabilities */

	/********************************/
	char ifname[32];
	uint8_t min_rx_burst;
	uint8_t portid;
	odp_bool_t vdev_sysc_promisc;	/**< promiscuous mode defined with
					     system call */
	odp_pktin_hash_proto_t hash;	/**< Packet input hash protocol */
	odp_bool_t lockless_rx;		/**< no locking for rx */
	odp_bool_t lockless_tx;		/**< no locking for tx */
	odp_ticketlock_t rx_lock[PKTIO_MAX_QUEUES]; /**< RX queue locks */
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES]; /**< TX queue locks */
} pktio_ops_dpdk_data_t;

#endif
