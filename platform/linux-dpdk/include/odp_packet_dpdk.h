/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H
#define ODP_PACKET_DPDK_H

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

#endif
