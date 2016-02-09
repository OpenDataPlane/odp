/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
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
#include <odp_packet_io_internal.h>
#include <odp_packet_dpdk.h>
#include <net/if.h>
#include <math.h>

/* Ops for all implementation of pktio.
 * Order matters. The first implementation to setup successfully
 * will be picked.
 * Array must be NULL terminated */
const pktio_if_ops_t * const pktio_if_ops[]  = {
	&loopback_pktio_ops,
	&dpdk_pktio_ops,
	NULL
};

extern pktio_table_t *pktio_tbl;

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

static int setup_pkt_dpdk(odp_pktio_t pktio ODP_UNUSED, pktio_entry_t *pktio_entry,
		   const char *netdev, odp_pool_t pool)
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
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;

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
				.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
			},
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};

	/* rx packet len same size as pool segment */
	port_conf.rxmode.max_rx_pkt_len = pool_entry->s.rte_mempool->elt_size;

	if (!_dpdk_netdev_is_valid(netdev))
		return -1;

	portid = atoi(netdev);
	pkt_dpdk->portid = portid;
	pkt_dpdk->pool = pool;
	pkt_dpdk->queueid = 0;
	rte_eth_dev_info_get(portid, &dev_info);
	if (!strcmp(dev_info.driver_name, "rte_ixgbe_pmd"))
		pkt_dpdk->min_rx_burst = 4;
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
					     NULL,
					     pool_entry->s.rte_mempool);
		if (ret < 0) {
			ODP_ERR("rxq:err=%d, port=%u\n", ret, (unsigned)portid);
			return -1;
		}
	}

	/* init one TX queue on each port */
	for (i = 0; i < nbtxq; i++) {
		ret = rte_eth_tx_queue_setup(portid, i, nb_txd, socket_id,
					     NULL);
		if (ret < 0) {
			ODP_ERR("txq:err=%d, port=%u\n", ret, (unsigned)portid);
			return -1;
		}
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

static int close_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	rte_eth_dev_close(pkt_dpdk->portid);
	return 0;
}

static int start_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	int ret;

	ret = rte_eth_dev_start(pktio_entry->s.pkt_dpdk.portid);
	if (ret < 0) {
		ODP_ERR("rte_eth_dev_start:err=%d, port=%u\n",
			ret, pktio_entry->s.pkt_dpdk.portid);
		return ret;
	}
	return 0;
}

static int stop_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	rte_eth_dev_stop(pktio_entry->s.pkt_dpdk.portid);
	return 0;
}

static unsigned rte_mempool_available(const struct rte_mempool *mp)
{
#if RTE_MEMPOOL_CACHE_MAX_SIZE > 0
	return rte_ring_count(mp->ring) + mp->local_cache[rte_lcore_id()].len;
#else
	return rte_ring_count(mp->ring);
#endif
}

static void _odp_pktio_send_completion(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	int i;
	struct rte_mbuf* dummy;
	pool_entry_t *pool_entry =
		get_pool_entry(_odp_typeval(pktio_entry->s.pkt_dpdk.pool));
	struct rte_mempool *rte_mempool = pool_entry->s.rte_mempool;
	pkt_dpdk_t * pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	rte_eth_tx_burst(pkt_dpdk->portid, pkt_dpdk->queueid, &dummy, 0);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry_t *entry = &pktio_tbl->entries[i];

		if (rte_mempool_available(rte_mempool) != 0)
			return;

		if (entry == pktio_entry)
			continue;

		if (odp_ticketlock_trylock(&entry->s.txl)) {
			if (!is_free(entry) &&
			    entry->s.ops == &dpdk_pktio_ops) {
				pkt_dpdk = &entry->s.pkt_dpdk;
				rte_eth_tx_burst(pkt_dpdk->portid,
						 pkt_dpdk->queueid, &dummy, 0);
			}
			odp_ticketlock_unlock(&entry->s.txl);
		}
	}

	return;
}

static int recv_pkt_dpdk(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[],
		  unsigned len)
{
	uint16_t nb_rx, i = 0;
	odp_packet_t *saved_pkt_table;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint8_t min = pkt_dpdk->min_rx_burst;

	if (odp_unlikely(min > len)) {
		ODP_DBG("PMD requires >%d buffers burst. "
			"Current %d, dropped %d\n", min, len, min - len);
		saved_pkt_table = pkt_table;
		pkt_table = malloc(min * sizeof(odp_packet_t));
	}

	nb_rx = rte_eth_rx_burst((uint8_t)pkt_dpdk->portid,
				 (uint16_t)pkt_dpdk->queueid,
				 (struct rte_mbuf **)pkt_table,
				 (uint16_t)RTE_MAX(len, min));

	if (nb_rx == 0) {
		pool_entry_t *pool_entry =
			get_pool_entry(_odp_typeval(pkt_dpdk->pool));
		struct rte_mempool *rte_mempool =
			pool_entry->s.rte_mempool;
		if (rte_mempool_available(rte_mempool) == 0)
			_odp_pktio_send_completion(pktio_entry);
	}
	for (i = 0; i < nb_rx; ++i)
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

static int send_pkt_dpdk(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[],
		  unsigned len)
{
	int pkts;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	pkts = rte_eth_tx_burst(pkt_dpdk->portid, pkt_dpdk->queueid,
				(struct rte_mbuf **)pkt_table, len);
	if (pkts) {
		return pkts;
	} else {
		if (!rte_errno)
			rte_errno = -1;
		return -1;
	}
}

static int _dpdk_vdev_mtu(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	close(sockfd);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}

	return ifr.ifr_mtu;
}

static int mtu_get_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	uint16_t mtu;
	int ret;

	ret = rte_eth_dev_get_mtu(pktio_entry->s.pkt_dpdk.portid,
			&mtu);
	if (ret < 0)
		return -2;

	/* some dpdk PMD vdev does not support getting mtu size,
	 * try to use system call if dpdk cannot get mtu value.
	 */
	if (mtu == 0)
		mtu = _dpdk_vdev_mtu(pktio_entry->s.pkt_dpdk.portid);
	return mtu;
}

static int _dpdk_vdev_promisc_mode_set(uint8_t port_id, int enable)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCSIFFLAGS error\n");
		return -1;
	}

	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}

	ODP_DBG("vdev promisc set to %d\n", enable);
	close(sockfd);
	return 0;
}

static int promisc_mode_set_pkt_dpdk(pktio_entry_t *pktio_entry,  int enable)
{
	uint8_t portid = pktio_entry->s.pkt_dpdk.portid;
	if (enable)
		rte_eth_promiscuous_enable(portid);
	else
		rte_eth_promiscuous_disable(portid);

	if (pktio_entry->s.pkt_dpdk.vdev_sysc_promisc) {
		int ret = _dpdk_vdev_promisc_mode_set(portid, enable);
		if (ret < 0)
			ODP_DBG("vdev promisc mode fail\n");
	}

	return 0;
}

static int _dpdk_vdev_promisc_mode(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	close(sockfd);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (ifr.ifr_flags & IFF_PROMISC) {
		ODP_DBG("promisc is 1\n");
		return 1;
	} else
		return 0;
}

static int promisc_mode_get_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	uint8_t portid = pktio_entry->s.pkt_dpdk.portid;
	if (pktio_entry->s.pkt_dpdk.vdev_sysc_promisc)
		return _dpdk_vdev_promisc_mode(portid);
	else
		return rte_eth_promiscuous_get(portid);

}

static int mac_get_pkt_dpdk(pktio_entry_t *pktio_entry, void *mac_addr)
{
	rte_eth_macaddr_get(pktio_entry->s.pkt_dpdk.portid,
			    (struct ether_addr *)mac_addr);
	return ETH_ALEN;
}


const pktio_if_ops_t dpdk_pktio_ops = {
	.init = NULL,
	.term = NULL,
	.open = setup_pkt_dpdk,
	.close = close_pkt_dpdk,
	.start = start_pkt_dpdk,
	.stop = stop_pkt_dpdk,
	.recv = recv_pkt_dpdk,
	.send = send_pkt_dpdk,
	.mtu_get = mtu_get_pkt_dpdk,
	.promisc_mode_set = promisc_mode_set_pkt_dpdk,
	.promisc_mode_get = promisc_mode_get_pkt_dpdk,
	.mac_get = mac_get_pkt_dpdk,
	.capability = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
	.in_queues = NULL,
	.pktin_queues = NULL,
	.pktout_queues = NULL,
	.recv_queue = NULL,
	.send_queue = NULL
};
