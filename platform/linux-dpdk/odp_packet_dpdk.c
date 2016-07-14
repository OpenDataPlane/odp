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
#include <odp/api/hints.h>
#include <odp/api/thread.h>

#include <odp/api/system_info.h>
#include <odp_debug_internal.h>
#include <odp_classification_internal.h>
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

static void rss_conf_to_hash_proto(struct rte_eth_rss_conf *rss_conf,
				   const odp_pktin_hash_proto_t *hash_proto)
{
	memset(rss_conf, 0, sizeof(struct rte_eth_rss_conf));

	if (hash_proto->proto.ipv4_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_UDP;
	if (hash_proto->proto.ipv4_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_TCP;
	if (hash_proto->proto.ipv4)
		rss_conf->rss_hf |= ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
				    ETH_RSS_NONFRAG_IPV4_OTHER;
	if (hash_proto->proto.ipv6_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_UDP |
				    ETH_RSS_IPV6_UDP_EX;
	if (hash_proto->proto.ipv6_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_TCP |
				    ETH_RSS_IPV6_TCP_EX;
	if (hash_proto->proto.ipv6)
		rss_conf->rss_hf |= ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
				    ETH_RSS_NONFRAG_IPV6_OTHER |
				    ETH_RSS_IPV6_EX;
	rss_conf->rss_key = NULL;
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

static int input_queues_config_pkt_dpdk(pktio_entry_t *pktio_entry,
					const odp_pktin_queue_param_t *p)
{
	odp_pktin_mode_t mode = pktio_entry->s.param.in_mode;

	/**
	 * Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED ||
	    p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pktio_entry->s.pkt_dpdk.lockless_rx = 1;
	else
		pktio_entry->s.pkt_dpdk.lockless_rx = 0;

	if (p->hash_enable && p->num_queues > 1) {
		pktio_entry->s.pkt_dpdk.hash = p->hash_proto;
	} else {
		pktio_entry->s.pkt_dpdk.hash.proto.ipv4_udp = 1;
		pktio_entry->s.pkt_dpdk.hash.proto.ipv4_tcp = 1;
		pktio_entry->s.pkt_dpdk.hash.proto.ipv4 = 1;
		pktio_entry->s.pkt_dpdk.hash.proto.ipv6_udp = 1;
		pktio_entry->s.pkt_dpdk.hash.proto.ipv6_tcp = 1;
		pktio_entry->s.pkt_dpdk.hash.proto.ipv6 = 1;
	}

	return 0;
}

static int output_queues_config_pkt_dpdk(pktio_entry_t *pktio_entry,
					 const odp_pktout_queue_param_t *p)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_dpdk->lockless_tx = 1;
	else
		pkt_dpdk->lockless_tx = 0;

	return 0;
}

static int setup_pkt_dpdk(odp_pktio_t pktio ODP_UNUSED, pktio_entry_t *pktio_entry,
		   const char *netdev, odp_pool_t pool ODP_UNUSED)
{
	uint8_t portid = 0;
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	int i;

	if (!_dpdk_netdev_is_valid(netdev)) {
		ODP_DBG("Interface name should only contain numbers!: %s\n",
			netdev);
		return -1;
	}

	portid = atoi(netdev);
	pkt_dpdk->portid = portid;
	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
	rte_eth_dev_info_get(portid, &dev_info);
	if (dev_info.driver_name == NULL) {
		ODP_DBG("No driver found for interface: %s\n", netdev);
		return -1;
	}
	if (!strcmp(dev_info.driver_name, "rte_ixgbe_pmd"))
		pkt_dpdk->min_rx_burst = 4;
	else
		pkt_dpdk->min_rx_burst = 0;

	_dpdk_print_port_mac(portid);

	pkt_dpdk->capa.max_input_queues = RTE_MIN(dev_info.max_rx_queues,
						  PKTIO_MAX_QUEUES);
	pkt_dpdk->capa.max_output_queues = RTE_MIN(dev_info.max_tx_queues,
						   PKTIO_MAX_QUEUES);

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		odp_ticketlock_init(&pkt_dpdk->rx_lock[i]);
		odp_ticketlock_init(&pkt_dpdk->tx_lock[i]);
	}
	return 0;
}

static int close_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	if (pktio_entry->s.state == PKTIO_STATE_STOPPED)
		rte_eth_dev_close(pkt_dpdk->portid);
	return 0;
}

static int start_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	int ret, i;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint8_t portid = pkt_dpdk->portid;
	int sid = rte_eth_dev_socket_id(pkt_dpdk->portid);
	int socket_id =  sid < 0 ? 0 : sid;
	uint16_t nbrxq, nbtxq;
	pool_entry_t *pool_entry =
			get_pool_entry(_odp_typeval(pktio_entry->s.pool));
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	struct rte_eth_rss_conf rss_conf;

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->s.num_in_queue)
		pktio_entry->s.num_in_queue = 1;
	if (!pktio_entry->s.num_out_queue)
		pktio_entry->s.num_out_queue = 1;

	rss_conf_to_hash_proto(&rss_conf, &pkt_dpdk->hash);

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
			.rss_conf = rss_conf,
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};

	/* rx packet len same size as pool segment minus headroom and double
	 * VLAN tag
	 */
	port_conf.rxmode.max_rx_pkt_len =
		rte_pktmbuf_data_room_size(pool_entry->s.rte_mempool) -
		2 * 4 - RTE_PKTMBUF_HEADROOM;

	nbtxq = pktio_entry->s.num_out_queue;
	nbrxq = pktio_entry->s.num_in_queue;

	ret = rte_eth_dev_configure(portid, nbrxq, nbtxq, &port_conf);
	if (ret < 0) {
		ODP_ERR("Cannot configure device: err=%d, port=%u\n",
			ret, (unsigned)portid);
		return -1;
	}

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

	ret = rte_eth_dev_start(portid);
	if (ret < 0) {
		ODP_ERR("rte_eth_dev_start:err=%d, port=%u\n",
			ret, portid);
		return ret;
	}

	return 0;
}

static int stop_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	rte_eth_dev_stop(pktio_entry->s.pkt_dpdk.portid);
	return 0;
}

/* Forward declaration */
static int send_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 const odp_packet_t pkt_table[], int len);

/* This function can't be called if pkt_dpdk->lockless_tx is true */
static void _odp_pktio_send_completion(pktio_entry_t *pktio_entry)
{
	int i;
	unsigned j;
	odp_packet_t dummy;
	pool_entry_t *pool_entry =
		get_pool_entry(_odp_typeval(pktio_entry->s.pool));
	struct rte_mempool *rte_mempool = pool_entry->s.rte_mempool;

	for (j = 0; j < pktio_entry->s.num_out_queue; j++)
		send_pkt_dpdk(pktio_entry, j, &dummy, 0);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry_t *entry = &pktio_tbl->entries[i];

		if (rte_mempool_avail_count(rte_mempool) != 0)
			return;

		if (entry == pktio_entry)
			continue;

		if (odp_ticketlock_trylock(&entry->s.txl)) {
			if (entry->s.state != PKTIO_STATE_FREE &&
			    entry->s.ops == &dpdk_pktio_ops) {
				for (j = 0; j < pktio_entry->s.num_out_queue;
				     j++)
					send_pkt_dpdk(pktio_entry, j,
						      &dummy, 0);
			}
			odp_ticketlock_unlock(&entry->s.txl);
		}
	}

	return;
}

static int recv_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 odp_packet_t pkt_table[], int len)
{
	uint16_t nb_rx, i;
	odp_packet_t *saved_pkt_table;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint8_t min = pkt_dpdk->min_rx_burst;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;

	if (odp_unlikely(min > len)) {
		ODP_DBG("PMD requires >%d buffers burst. "
			"Current %d, dropped %d\n", min, len, min - len);
		saved_pkt_table = pkt_table;
		pkt_table = malloc(min * sizeof(odp_packet_t));
	}

	if (!pkt_dpdk->lockless_rx)
		odp_ticketlock_lock(&pkt_dpdk->rx_lock[index]);

	nb_rx = rte_eth_rx_burst((uint8_t)pkt_dpdk->portid,
				 (uint16_t)index,
				 (struct rte_mbuf **)pkt_table,
				 (uint16_t)RTE_MAX(len, min));

	if (nb_rx == 0 && !pkt_dpdk->lockless_tx) {
		pool_entry_t *pool_entry =
			get_pool_entry(_odp_typeval(pktio_entry->s.pool));
		struct rte_mempool *rte_mempool =
			pool_entry->s.rte_mempool;
		if (rte_mempool_avail_count(rte_mempool) == 0)
			_odp_pktio_send_completion(pktio_entry);
	}

	if (!pkt_dpdk->lockless_rx)
		odp_ticketlock_unlock(&pkt_dpdk->rx_lock[index]);

	for (i = 0; i < nb_rx; ++i) {
		_odp_packet_reset_parse(pkt_table[i]);
		odp_packet_hdr(pkt_table[i])->input = pktio_entry->s.handle;
	}

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	if (odp_unlikely(min > len)) {
		memcpy(saved_pkt_table, pkt_table,
		       len * sizeof(odp_packet_t));
		for (i = len; i < nb_rx; i++)
			odp_packet_free(pkt_table[i]);
		nb_rx = RTE_MIN(len, nb_rx);
		free(pkt_table);
		pktio_entry->s.stats.in_discards += min - len;
		pkt_table = saved_pkt_table;
	}

	if (pktio_cls_enabled(pktio_entry)) {
		int failed = 0, success = 0;

		for (i = 0; i < nb_rx; i++) {
			odp_packet_t new_pkt;
			odp_pool_t new_pool;
			uint8_t *pkt_addr;
			odp_packet_hdr_t parsed_hdr;
			int ret;
			odp_packet_hdr_t *pkt_hdr =
					odp_packet_hdr(pkt_table[i]);

			pkt_addr = odp_packet_data(pkt_table[i]);
			ret = cls_classify_packet(pktio_entry, pkt_addr,
						  odp_packet_len(pkt_table[i]),
						  odp_packet_len(pkt_table[i]),
						  &new_pool, &parsed_hdr);
			if (ret) {
				failed++;
				odp_packet_free(pkt_table[i]);
				continue;
			}
			if (new_pool != odp_packet_pool(pkt_table[i])) {
				new_pkt = odp_packet_copy(pkt_table[i],
							  new_pool);

				odp_packet_free(pkt_table[i]);
				if (new_pkt == ODP_PACKET_INVALID) {
					failed++;
					continue;
				}
				pkt_table[i] = new_pkt;
			}
			packet_set_ts(pkt_hdr, ts);
			pktio_entry->s.stats.in_octets +=
					odp_packet_len(pkt_table[i]);
			copy_packet_cls_metadata(&parsed_hdr, pkt_hdr);
			if (success != i)
				pkt_table[success] = pkt_table[i];
			++success;
		}
		pktio_entry->s.stats.in_errors += failed;
		pktio_entry->s.stats.in_ucast_pkts += nb_rx - failed;
		nb_rx = success;
	}

	return nb_rx;
}

static int send_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 const odp_packet_t pkt_table[], int len)
{
	int pkts;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_lock(&pkt_dpdk->tx_lock[index]);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	pkts = rte_eth_tx_burst(pkt_dpdk->portid, index,
				(struct rte_mbuf **)pkt_table, len);
#pragma GCC diagnostic pop

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_unlock(&pkt_dpdk->tx_lock[index]);

	if (odp_unlikely(pkts == 0 && rte_errno != 0)) {
		return -1;
	} else {
		rte_errno = 0;
		return pkts;
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

static uint32_t mtu_get_pkt_dpdk(pktio_entry_t *pktio_entry)
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


static int capability_pkt_dpdk(pktio_entry_t *pktio_entry,
			       odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.pkt_dpdk.capa;
	return 0;
}
static int link_status_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	struct rte_eth_link link;

	rte_eth_link_get(pktio_entry->s.pkt_dpdk.portid, &link);
	return link.link_status;
}

static void stats_convert(struct rte_eth_stats *rte_stats,
			  odp_pktio_stats_t *stats)
{
	stats->in_octets = rte_stats->ibytes;
	stats->in_ucast_pkts = 0;
	stats->in_discards = rte_stats->imissed;
	stats->in_errors = rte_stats->ierrors;
	stats->in_unknown_protos = 0;
	stats->out_octets = rte_stats->obytes;
	stats->out_ucast_pkts = 0;
	stats->out_discards = 0;
	stats->out_errors = rte_stats->oerrors;
}

static int stats_pkt_dpdk(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats)
{
	int ret;
	struct rte_eth_stats rte_stats;

	ret = rte_eth_stats_get(pktio_entry->s.pkt_dpdk.portid, &rte_stats);

	if (ret == 0) {
		stats_convert(&rte_stats, stats);
		return 0;
	} else {
		if (ret > 0)
			return -ret;
		else
			return ret;
	}
}

static int stats_reset_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	rte_eth_stats_reset(pktio_entry->s.pkt_dpdk.portid);
	return 0;
}

const pktio_if_ops_t dpdk_pktio_ops = {
	.name = "odp-dpdk",
	.print = NULL,
	.init_global = NULL,
	.init_local = NULL,
	.term = NULL,
	.open = setup_pkt_dpdk,
	.close = close_pkt_dpdk,
	.start = start_pkt_dpdk,
	.stop = stop_pkt_dpdk,
	.stats = stats_pkt_dpdk,
	.stats_reset = stats_reset_pkt_dpdk,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.mtu_get = mtu_get_pkt_dpdk,
	.promisc_mode_set = promisc_mode_set_pkt_dpdk,
	.promisc_mode_get = promisc_mode_get_pkt_dpdk,
	.mac_get = mac_get_pkt_dpdk,
	.link_status = link_status_pkt_dpdk,
	.capability = capability_pkt_dpdk,
	.config = NULL,
	.input_queues_config = input_queues_config_pkt_dpdk,
	.output_queues_config = output_queues_config_pkt_dpdk,
	.recv = recv_pkt_dpdk,
	.send = send_pkt_dpdk
};
