/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <odp_hints.h>
#include <odp_thread.h>

#include <odp_packet_dpdk.h>
#include <net/if.h>

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_PKT_BURST 16
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	/*
	 * As the example won't handle mult-segments and offload cases,
	 * set the flag by default.
	 */
	.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

int setup_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, const char *netdev,
		odp_buffer_pool_t pool)
{
	ODP_DBG("setup_pkt_dpdk\n");

	static struct ether_addr eth_addr[RTE_MAX_ETHPORTS];
	uint8_t portid = 0;
	uint16_t queueid = 0;
	int ret;
	printf("dpdk netdev: %s\n", netdev);
	printf("dpdk pool: %lx\n", pool);

	portid = atoi(netdev);
	pkt_dpdk->portid = portid;
	pkt_dpdk->queueid = queueid;
	pkt_dpdk->pool = pool;
	printf("dpdk portid: %u\n", portid);

	fflush(stdout);
	ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
	if (ret < 0)
		ODP_ERR("Cannot configure device: err=%d, port=%u\n",
			ret, (unsigned) portid);

	rte_eth_macaddr_get(portid, &eth_addr[portid]);
	ODP_DBG("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
		(unsigned) portid,
		eth_addr[portid].addr_bytes[0],
		eth_addr[portid].addr_bytes[1],
		eth_addr[portid].addr_bytes[2],
		eth_addr[portid].addr_bytes[3],
		eth_addr[portid].addr_bytes[4],
		eth_addr[portid].addr_bytes[5]);

	/* init one RX queue on each port */
	fflush(stdout);
	ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
				     rte_eth_dev_socket_id(portid), &rx_conf,
				     (struct rte_mempool *)pool);
	if (ret < 0)
		ODP_ERR("rte_eth_rx_queue_setup:err=%d, port=%u\n",
			ret, (unsigned) portid);
	ODP_DBG("dpdk rx queue setup done\n");

	/* init one TX queue on each port */
	fflush(stdout);
	ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
			rte_eth_dev_socket_id(portid), &tx_conf);
	if (ret < 0)
		ODP_ERR("rte_eth_tx_queue_setup:err=%d, port=%u\n",
			ret, (unsigned) portid);
	ODP_DBG("dpdk tx queue setup done\n");

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		ODP_ERR("rte_eth_dev_start:err=%d, port=%u\n",
			ret, (unsigned) portid);
	ODP_DBG("dpdk setup done\n\n");


	return 0;
}

int close_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk)
{
	ODP_DBG("close pkt_dpdk, %u\n", pkt_dpdk->portid);

	return 0;
}

int recv_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, odp_packet_t pkt_table[],
		unsigned len)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx, i = 0;

	memset(pkts_burst, 0 , sizeof(pkts_burst));
	nb_rx = rte_eth_rx_burst((uint8_t)pkt_dpdk->portid,
				 (uint16_t)pkt_dpdk->queueid,
				 (struct rte_mbuf **)pkts_burst, (uint16_t)len);
	for (i = 0; i < nb_rx; i++)
		pkt_table[i] = (odp_packet_t)pkts_burst[i];
	return nb_rx;
}

int send_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, odp_packet_t pkt_table[],
		unsigned len)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t i;

	for (i = 0; i < len; i++)
		pkts_burst[i] = (struct rte_mbuf *)pkt_table[i];
	return rte_eth_tx_burst((uint8_t)pkt_dpdk->portid,
				(uint16_t)pkt_dpdk->queueid,
				(struct rte_mbuf **)pkts_burst, (uint16_t)len);
}
