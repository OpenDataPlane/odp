/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

#include <stdint.h>
#include <net/if.h>

#include <helper/odp_eth.h>
#include <helper/odp_packet_helper.h>
#include <odp_align.h>
#include <odp_debug.h>
#include <odp_packet.h>
#include <odp_packet_internal.h>
#include <odp_buffer_pool.h>
#include <odp_buffer_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_std_types.h>

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


#define ODP_DPDK_MODE_HW	0
#define ODP_DPDK_MODE_SW	1

#define DPDK_BLOCKING_IO

/** Packet socket using dpdk mmaped rings for both Rx and Tx */
typedef struct {
	odp_buffer_pool_t pool;

	/********************************/
	char ifname[32];
	uint8_t portid;
	uint16_t queueid;
} pkt_dpdk_t;

/**
 * Configure an interface to work in dpdk mode
 */
int setup_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, const char *netdev,
		   odp_buffer_pool_t pool);

/**
 * Switch interface from dpdk mode to normal mode
 */
int close_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk);

/**
 * Receive packets using dpdk
 */
int recv_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, odp_packet_t pkt_table[],
		  unsigned len);

/**
 * Send packets using dpdk
 */
int send_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, odp_packet_t pkt_table[],
		  unsigned len);

int odp_init_dpdk(void);
#endif
