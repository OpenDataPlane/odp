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

#include <odp/api/cpu.h>
#include <odp/hints.h>
#include <odp/thread.h>

#include <odp/system_info.h>
#include <odp_debug_internal.h>
#include <odp_packet_dpdk.h>
#include <net/if.h>
#include <math.h>

/* Test if s has only digits or not. Dpdk pktio uses only digits.*/
static int _dpdk_netdev_is_valid(const char *s)
{
	while (*s) {
		if (!isdigit(*s))
			return 0;
		s++;
	}

	return 1;
}

static void _dpdk_print_port_mac(uint8_t portid)
{
	struct ether_addr eth_addr;

	memset(&eth_addr, 0, sizeof(eth_addr));
	rte_eth_macaddr_get(portid, &eth_addr);
	ODP_DBG("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
		(unsigned)portid,
		eth_addr.addr_bytes[0],
		eth_addr.addr_bytes[1],
		eth_addr.addr_bytes[2],
		eth_addr.addr_bytes[3],
		eth_addr.addr_bytes[4],
		eth_addr.addr_bytes[5]);
}

int setup_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, const char *netdev,
		   odp_pool_t pool)
{
	uint8_t portid = 0;
	uint16_t nbrxq, nbtxq;
	int ret, i;
	pool_entry_t *pool_entry = get_pool_entry(_odp_typeval(pool));
	int sid = rte_eth_dev_socket_id(portid);
	int socket_id =  sid < 0 ? 0 : sid;
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	struct rte_eth_dev_info dev_info;

	struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
			.pthresh = RX_PTHRESH,
			.hthresh = RX_HTHRESH,
			.wthresh = RX_WTHRESH,
		},
	};

	struct rte_eth_txconf tx_conf = {
		.tx_thresh = {
			.pthresh = TX_PTHRESH,
			.hthresh = TX_HTHRESH,
			.wthresh = TX_WTHRESH,
		},
		.tx_free_thresh = 256, /* Start flushing when the ring
					  is half full */
		.tx_rs_thresh = 0, /* Use PMD default values */
		/*
		 * As the example won't handle mult-segments and offload cases,
		 * set the flag by default.
		 */
		.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS |
			     ETH_TXQ_FLAGS_NOOFFLOADS,
	};

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS,
			.split_hdr_size = 0,
			.header_split   = 0, /**< Header Split */
			.hw_ip_checksum = 0, /**< IP checksum offload */
			.hw_vlan_filter = 0, /**< VLAN filtering */
			.jumbo_frame    = 1, /**< Jumbo Frame Support */
			.hw_strip_crc   = 0, /**< CRC stripp by hardware */
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = ETH_RSS_NONFRAG_IPV4_TCP |
				ETH_RSS_IPV4 |
				ETH_RSS_IPV6 |
				ETH_RSS_NONFRAG_IPV4_UDP |
				ETH_RSS_NONFRAG_IPV6_TCP |
				ETH_RSS_NONFRAG_IPV6_UDP,
			},
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};

	/* rx packet len same size as pool segment */
	port_conf.rxmode.max_rx_pkt_len = pool_entry->s.params.pkt.seg_len;

	if (!_dpdk_netdev_is_valid(netdev))
		return -1;

	portid = atoi(netdev);
	pkt_dpdk->portid = portid;
	pkt_dpdk->pool = pool;
	pkt_dpdk->queueid = 0;
	rte_eth_dev_info_get(portid, &dev_info);
	if (!strcmp(dev_info.driver_name, "rte_ixgbe_pmd"))
		pkt_dpdk->min_rx_burst = 32;
	else
		pkt_dpdk->min_rx_burst = 0;

	/* On init set it up only to 1 rx and tx queue.*/
	nbtxq = nbrxq = 1;

	ret = rte_eth_dev_configure(portid, nbrxq, nbtxq, &port_conf);
	if (ret < 0) {
		ODP_ERR("Cannot configure device: err=%d, port=%u\n",
			ret, (unsigned)portid);
		return -1;
	}

	_dpdk_print_port_mac(portid);

	if (nb_rxd + nb_txd > pool_entry->s.params.pkt.num / 4) {
		double downrate = (double)(pool_entry->s.params.pkt.num / 4) /
				  (double)(nb_rxd + nb_txd);
		nb_rxd >>= (int)ceil(downrate);
		nb_txd >>= (int)ceil(downrate);
		ODP_DBG("downrate %f\n", downrate);
		ODP_DBG("Descriptors scaled down. RX: %u TX: %u pool: %u\n",
			nb_rxd, nb_txd, pool_entry->s.params.pkt.num);
	}
	/* init one RX queue on each port */
	for (i = 0; i < nbrxq; i++) {
		ret = rte_eth_rx_queue_setup(portid, i, nb_rxd, socket_id,
					     &rx_conf,
					     pool_entry->s.rte_mempool);
		if (ret < 0) {
			ODP_ERR("rxq:err=%d, port=%u\n", ret, (unsigned)portid);
			return -1;
		}
	}

	/* init one TX queue on each port */
	for (i = 0; i < nbtxq; i++) {
		ret = rte_eth_tx_queue_setup(portid, i, nb_txd, socket_id,
					     &tx_conf);
		if (ret < 0) {
			ODP_ERR("txq:err=%d, port=%u\n", ret, (unsigned)portid);
			return -1;
		}
	}

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0) {
		ODP_ERR("rte_eth_dev_start:err=%d, port=%u\n",
			ret, (unsigned)portid);
		return -1;
	}

	rte_eth_promiscuous_enable(portid);
	/* Some DPDK PMD vdev like pcap do not support promisc mode change. Use
	 * system call for them. */
	if (!rte_eth_promiscuous_get(portid))
		pkt_dpdk->vdev_sysc_promisc = 1;
	else
		pkt_dpdk->vdev_sysc_promisc = 0;

	rte_eth_allmulticast_enable(portid);
	return 0;
}

int close_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk)
{
	rte_eth_dev_close(pkt_dpdk->portid);
	return 0;
}

int recv_pkt_dpdk(pkt_dpdk_t * const pkt_dpdk, odp_packet_t pkt_table[],
		  unsigned len)
{
	uint16_t nb_rx, i = 0;
	odp_packet_t *saved_pkt_table;
	uint8_t min = pkt_dpdk->min_rx_burst;

	if (odp_unlikely(min > len)) {
		ODP_DBG("PMD requires >%d buffers burst. "
			"Current %d, dropped %d\n", min, len, min - len);
		saved_pkt_table = pkt_table;
		pkt_table = malloc(min * sizeof(odp_packet_t*));
	}

	nb_rx = rte_eth_rx_burst((uint8_t)pkt_dpdk->portid,
				 (uint16_t)pkt_dpdk->queueid,
				 (struct rte_mbuf **)pkt_table,
				 (uint16_t)RTE_MAX(len, min));
	for (i = 0; i < nb_rx; i++)
		_odp_packet_reset_parse(pkt_table[i]);

	if (odp_unlikely(min > len)) {
		memcpy(saved_pkt_table, pkt_table,
		       len * sizeof(odp_packet_t));
		for (i = len; i < nb_rx; i++)
			odp_packet_free(pkt_table[i]);
		nb_rx = RTE_MIN(len, nb_rx);
		free(pkt_table);
	}

	return nb_rx;
}
