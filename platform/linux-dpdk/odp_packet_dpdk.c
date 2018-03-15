/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

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
#include <inttypes.h>

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

/* DPDK poll mode drivers requiring minimum RX burst size DPDK_MIN_RX_BURST */
#define IXGBE_DRV_NAME "net_ixgbe"
#define I40E_DRV_NAME "net_i40e"

/* Minimum RX burst size */
#define DPDK_MIN_RX_BURST 4

/* Ops for all implementation of pktio.
 * Order matters. The first implementation to setup successfully
 * will be picked.
 * Array must be NULL terminated */
const pktio_if_ops_t * const pktio_if_ops[]  = {
	&loopback_pktio_ops,
	&dpdk_pktio_ops,
	NULL
};

extern void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

static uint32_t mtu_get_pkt_dpdk(pktio_entry_t *pktio_entry);

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

static void _dpdk_print_port_mac(uint16_t port_id)
{
	struct ether_addr eth_addr;

	memset(&eth_addr, 0, sizeof(eth_addr));
	rte_eth_macaddr_get(port_id, &eth_addr);
	ODP_DBG("Port %" PRIu16 ", "
		"MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
		port_id,
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

static int term_pkt_dpdk(void)
{
	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_close(port_id);
	}

	return 0;
}

static int dpdk_init_capability(pktio_entry_t *pktio_entry,
				struct rte_eth_dev_info *dev_info)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	odp_pktio_capability_t *capa = &pktio_entry->s.capa;
	unsigned max_rx_queues;
	struct ether_addr mac_addr;
	int ret;
	int ptype_cnt;
	int ptype_l3_ipv4 = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	memset(dev_info, 0, sizeof(struct rte_eth_dev_info));
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	rte_eth_dev_info_get(pkt_dpdk->port_id, dev_info);
	if (dev_info->driver_name == NULL) {
		ODP_DBG("No driver found for interface: %d\n",
			pkt_dpdk->port_id);
		return -1;
	}

	/* Set maximum input/output queues number*/
	max_rx_queues = RTE_MIN(dev_info->max_rx_queues, PKTIO_MAX_QUEUES);
	/* ixgbe devices support only 16 RX queues in RSS mode */
	if (!strncmp(dev_info->driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)))
		max_rx_queues = RTE_MIN((unsigned)16, max_rx_queues);
	capa->max_input_queues = max_rx_queues;
	capa->max_output_queues = RTE_MIN(dev_info->max_tx_queues,
					  PKTIO_MAX_QUEUES);

	/* Check if setting default MAC address is supporter */
	rte_eth_macaddr_get(pkt_dpdk->port_id, &mac_addr);
	ret = rte_eth_dev_default_mac_addr_set(pkt_dpdk->port_id, &mac_addr);
	if (ret == 0) {
		capa->set_op.op.mac_addr = 1;
	} else if (ret != -ENOTSUP) {
		ODP_ERR("Failed to set interface default MAC\n");
		return -1;
	}

	/* Check supported pktio configuration options */
	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;

	/* CSUM RX capabilities*/
	ptype_cnt = rte_eth_dev_get_supported_ptypes(pkt_dpdk->port_id,
						     ptype_mask, NULL, 0);
	if (ptype_cnt > 0) {
		uint32_t ptypes[ptype_cnt];
		int i;

		ptype_cnt = rte_eth_dev_get_supported_ptypes(pkt_dpdk->port_id,
							     ptype_mask, ptypes,
							     ptype_cnt);
		for (i = 0; i < ptype_cnt; i++)
			switch (ptypes[i]) {
			case RTE_PTYPE_L3_IPV4:
			/* Fall through */
			case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
			/* Fall through */
			case RTE_PTYPE_L3_IPV4_EXT:
				ptype_l3_ipv4 = 1;
				break;
			case RTE_PTYPE_L4_TCP:
				ptype_l4_tcp = 1;
				break;
			case RTE_PTYPE_L4_UDP:
				ptype_l4_udp = 1;
				break;
			}
	}

	capa->config.pktin.bit.ipv4_chksum = ptype_l3_ipv4 &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.ipv4_chksum)
		capa->config.pktin.bit.drop_ipv4_err = 1;

	capa->config.pktin.bit.udp_chksum = ptype_l4_udp &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.udp_chksum)
		capa->config.pktin.bit.drop_udp_err = 1;

	capa->config.pktin.bit.tcp_chksum = ptype_l4_tcp &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.tcp_chksum)
		capa->config.pktin.bit.drop_tcp_err = 1;

	/* CSUM TX capabilities*/
	capa->config.pktout.bit.ipv4_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
	capa->config.pktout.bit.udp_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) ? 1 : 0;
	capa->config.pktout.bit.tcp_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) ? 1 : 0;

	capa->config.pktout.bit.ipv4_chksum_ena =
		capa->config.pktout.bit.ipv4_chksum;
	capa->config.pktout.bit.udp_chksum_ena =
		capa->config.pktout.bit.udp_chksum;
	capa->config.pktout.bit.tcp_chksum_ena =
		capa->config.pktout.bit.tcp_chksum;

	return 0;
}

static int setup_pkt_dpdk(odp_pktio_t pktio ODP_UNUSED, pktio_entry_t *pktio_entry,
		   const char *netdev, odp_pool_t pool ODP_UNUSED)
{
	uint32_t mtu;
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	int i;

	if (!_dpdk_netdev_is_valid(netdev)) {
		ODP_DBG("Interface name should only contain numbers!: %s\n",
			netdev);
		return -1;
	}
	pkt_dpdk->port_id = atoi(netdev);

	if (dpdk_init_capability(pktio_entry, &dev_info)) {
		ODP_DBG("Failed to initialize capabilities for interface: %s\n",
			netdev);
		return -1;
	}

	/* Drivers requiring minimum burst size. Supports also *_vf versions
	 * of the drivers. */
	if (!strncmp(dev_info.driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)) ||
	    !strncmp(dev_info.driver_name, I40E_DRV_NAME,
		     strlen(I40E_DRV_NAME)))
		pkt_dpdk->min_rx_burst = DPDK_MIN_RX_BURST;
	else
		pkt_dpdk->min_rx_burst = 0;

	_dpdk_print_port_mac(pkt_dpdk->port_id);

	mtu = mtu_get_pkt_dpdk(pktio_entry);
	if (mtu == 0) {
		ODP_ERR("Failed to read interface MTU\n");
		return -1;
	}
	pkt_dpdk->mtu = mtu + _ODP_ETHHDR_LEN;

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		odp_ticketlock_init(&pkt_dpdk->rx_lock[i]);
		odp_ticketlock_init(&pkt_dpdk->tx_lock[i]);
	}
	return 0;
}

static int close_pkt_dpdk(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static odp_bool_t tx_checksum(pktio_entry_t *pktio_entry, uint32_t *txq_flags)
{
	unsigned ip_ena  = pktio_entry->s.config.pktout.bit.ipv4_chksum_ena;
	unsigned udp_ena = pktio_entry->s.config.pktout.bit.udp_chksum_ena;
	unsigned tcp_ena = pktio_entry->s.config.pktout.bit.tcp_chksum_ena;
	unsigned sctp_ena = pktio_entry->s.config.pktout.bit.sctp_chksum_ena;

	*txq_flags = 0;

	if (!(ip_ena | udp_ena | tcp_ena | sctp_ena))
		return false;

	if (udp_ena == 0)
		*txq_flags |= ETH_TXQ_FLAGS_NOXSUMUDP;

	if (tcp_ena == 0)
		*txq_flags |= ETH_TXQ_FLAGS_NOXSUMTCP;

	if (sctp_ena == 0)
		*txq_flags |= ETH_TXQ_FLAGS_NOXSUMSCTP;

	/* When IP checksum is requested alone, enable UDP
	 * offload. DPDK IP checksum offload is enabled only
	 * when one of the L4 checksum offloads is requested.*/
	if ((udp_ena == 0) && (tcp_ena == 0) && (sctp_ena == 0))
		*txq_flags = ETH_TXQ_FLAGS_NOXSUMTCP | ETH_TXQ_FLAGS_NOXSUMSCTP;

	*txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS |
			ETH_TXQ_FLAGS_NOREFCOUNT |
			ETH_TXQ_FLAGS_NOMULTMEMP |
			ETH_TXQ_FLAGS_NOVLANOFFL;

	return true;
}

static int start_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	int ret, i;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint16_t port_id = pkt_dpdk->port_id;
	int sid = rte_eth_dev_socket_id(pkt_dpdk->port_id);
	int socket_id =  sid < 0 ? 0 : sid;
	uint16_t nbrxq, nbtxq;
	pool_t *pool = pool_entry_from_hdl(pktio_entry->s.pool);
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	struct rte_eth_rss_conf rss_conf;
	uint16_t hw_ip_checksum = 0;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf *rxconf = NULL;
	struct rte_eth_txconf *txconf = NULL;
	uint32_t txq_flags = 0;

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->s.num_in_queue)
		pktio_entry->s.num_in_queue = 1;
	if (!pktio_entry->s.num_out_queue)
		pktio_entry->s.num_out_queue = 1;

	rss_conf_to_hash_proto(&rss_conf, &pkt_dpdk->hash);

	if (pktio_entry->s.config.pktin.bit.ipv4_chksum ||
	    pktio_entry->s.config.pktin.bit.udp_chksum ||
	    pktio_entry->s.config.pktin.bit.tcp_chksum)
		hw_ip_checksum = 1;

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS,
			.split_hdr_size = 0,
			.header_split   = 0, /**< Header Split */
			.hw_ip_checksum = hw_ip_checksum, /**< IP checksum offload */
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
		rte_pktmbuf_data_room_size(pool->rte_mempool) -
		2 * 4 - RTE_PKTMBUF_HEADROOM;

	nbtxq = pktio_entry->s.num_out_queue;
	nbrxq = pktio_entry->s.num_in_queue;

	ret = rte_eth_dev_configure(port_id, nbrxq, nbtxq, &port_conf);
	if (ret < 0) {
		ODP_ERR("Cannot configure device: err=%d, port=%" PRIu16 "\n",
			ret, port_id);
		return -1;
	}

	if (nb_rxd + nb_txd > pool->params.pkt.num / 4) {
		double downrate = (double)(pool->params.pkt.num / 4) /
				  (double)(nb_rxd + nb_txd);
		nb_rxd >>= (int)ceil(downrate);
		nb_txd >>= (int)ceil(downrate);
		ODP_DBG("downrate %f\n", downrate);
		ODP_DBG("Descriptors scaled down. RX: %u TX: %u pool: %u\n",
			nb_rxd, nb_txd, pool->params.pkt.num);
	}
	/* init RX queues */
	rte_eth_dev_info_get(port_id, &dev_info);
	rxconf = &dev_info.default_rxconf;
	rxconf->rx_drop_en = 1;
	for (i = 0; i < nbrxq; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, nb_rxd, socket_id,
					     rxconf, pool->rte_mempool);
		if (ret < 0) {
			ODP_ERR("rxq:err=%d, port=%" PRIu16 "\n", ret, port_id);
			return -1;
		}
	}

	/* init TX queues */
	txconf = NULL;
	pktio_entry->s.chksum_insert_ena = 0;

	if (tx_checksum(pktio_entry, &txq_flags)) {
		txconf = &dev_info.default_txconf;
		txconf->txq_flags = txq_flags;
		pktio_entry->s.chksum_insert_ena = 1;
	}
	/* else - use the default tx queue settings*/

	for (i = 0; i < nbtxq; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, nb_txd, socket_id,
					     txconf);
		if (ret < 0) {
			ODP_ERR("txq:err=%d, port=%" PRIu16 "\n", ret, port_id);
			return -1;
		}
	}

	rte_eth_promiscuous_enable(port_id);
	/* Some DPDK PMD vdev like pcap do not support promisc mode change. Use
	 * system call for them. */
	if (!rte_eth_promiscuous_get(port_id))
		pkt_dpdk->vdev_sysc_promisc = 1;
	else
		pkt_dpdk->vdev_sysc_promisc = 0;

	rte_eth_allmulticast_enable(port_id);

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		ODP_ERR("rte_eth_dev_start:err=%d, port=%" PRIu16 "\n",
			ret, port_id);
		return ret;
	}

	return 0;
}

static int stop_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	rte_eth_dev_stop(pktio_entry->s.pkt_dpdk.port_id);
	return 0;
}

/* This function can't be called if pkt_dpdk->lockless_tx is true */
static void _odp_pktio_send_completion(pktio_entry_t *pktio_entry)
{
	int i;
	unsigned j;
	pool_t *pool = pool_entry_from_hdl(pktio_entry->s.pool);
	struct rte_mempool *rte_mempool = pool->rte_mempool;
	uint16_t port_id = pktio_entry->s.pkt_dpdk.port_id;

	for (j = 0; j < pktio_entry->s.num_out_queue; j++)
		rte_eth_tx_done_cleanup(port_id, j, 0);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry_t *entry = pktio_entry_ptr[i];

		port_id = entry->s.pkt_dpdk.port_id;

		if (rte_mempool_avail_count(rte_mempool) != 0)
			return;

		if (entry == pktio_entry)
			continue;

		if (odp_ticketlock_trylock(&entry->s.txl)) {
			if (entry->s.state != PKTIO_STATE_FREE &&
			    entry->s.ops == &dpdk_pktio_ops) {
				for (j = 0; j < pktio_entry->s.num_out_queue;
				     j++)
					rte_eth_tx_done_cleanup(port_id, j, 0);
			}
			odp_ticketlock_unlock(&entry->s.txl);
		}
	}

	return;
}

#define IP4_CSUM_RESULT(m) (m->ol_flags & PKT_RX_IP_CKSUM_MASK)
#define L4_CSUM_RESULT(m) (m->ol_flags & PKT_RX_L4_CKSUM_MASK)
#define HAS_L4_PROTO(m, proto) ((m->packet_type & RTE_PTYPE_L4_MASK) == proto)

#define PKTIN_CSUM_BITS 0x1C

static inline int pkt_set_ol_rx(odp_pktin_config_opt_t *pktin_cfg,
				odp_packet_hdr_t *pkt_hdr,
				struct rte_mbuf *mbuf)
{
	uint64_t packet_csum_result;

	if (pktin_cfg->bit.ipv4_chksum &&
	    RTE_ETH_IS_IPV4_HDR(mbuf->packet_type)) {
		packet_csum_result = IP4_CSUM_RESULT(mbuf);

		if (packet_csum_result == PKT_RX_IP_CKSUM_GOOD) {
			pkt_hdr->p.input_flags.l3_chksum_done = 1;
		} else if (packet_csum_result != PKT_RX_IP_CKSUM_UNKNOWN) {
			if (pktin_cfg->bit.drop_ipv4_err)
				return -1;

			pkt_hdr->p.input_flags.l3_chksum_done = 1;
			pkt_hdr->p.error_flags.ip_err = 1;
			pkt_hdr->p.error_flags.l3_chksum = 1;
		}
	}

	if (pktin_cfg->bit.udp_chksum &&
	    HAS_L4_PROTO(mbuf, RTE_PTYPE_L4_UDP)) {
		packet_csum_result = L4_CSUM_RESULT(mbuf);

		if (packet_csum_result == PKT_RX_L4_CKSUM_GOOD) {
			pkt_hdr->p.input_flags.l4_chksum_done = 1;
		} else if (packet_csum_result != PKT_RX_L4_CKSUM_UNKNOWN) {
			if (pktin_cfg->bit.drop_udp_err)
				return -1;

			pkt_hdr->p.input_flags.l4_chksum_done = 1;
			pkt_hdr->p.error_flags.udp_err = 1;
			pkt_hdr->p.error_flags.l4_chksum = 1;
		}
	} else if (pktin_cfg->bit.tcp_chksum &&
		   HAS_L4_PROTO(mbuf, RTE_PTYPE_L4_TCP)) {
		packet_csum_result = L4_CSUM_RESULT(mbuf);

		if (packet_csum_result == PKT_RX_L4_CKSUM_GOOD) {
			pkt_hdr->p.input_flags.l4_chksum_done = 1;
		} else if (packet_csum_result != PKT_RX_L4_CKSUM_UNKNOWN) {
			if (pktin_cfg->bit.drop_tcp_err)
				return -1;

			pkt_hdr->p.input_flags.l4_chksum_done = 1;
			pkt_hdr->p.error_flags.tcp_err = 1;
			pkt_hdr->p.error_flags.l4_chksum = 1;
		}
	}

	return 0;
}

static int recv_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 odp_packet_t pkt_table[], int len)
{
	uint16_t nb_rx, i;
	odp_packet_t *saved_pkt_table;
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	odp_pktin_config_opt_t *pktin_cfg = &pktio_entry->s.config.pktin;
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

	nb_rx = rte_eth_rx_burst(pkt_dpdk->port_id,
				 (uint16_t)index,
				 (struct rte_mbuf **)pkt_table,
				 (uint16_t)RTE_MAX(len, min));

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	if (nb_rx == 0 && !pkt_dpdk->lockless_tx) {
		pool_t *pool = pool_entry_from_hdl(pktio_entry->s.pool);
		struct rte_mempool *rte_mempool = pool->rte_mempool;
		if (rte_mempool_avail_count(rte_mempool) == 0)
			_odp_pktio_send_completion(pktio_entry);
	}

	if (!pkt_dpdk->lockless_rx)
		odp_ticketlock_unlock(&pkt_dpdk->rx_lock[index]);

	for (i = 0; i < nb_rx; ++i) {
		odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt_table[i]);

		packet_init(pkt_hdr);
		pkt_hdr->input = pktio_entry->s.handle;

		if (!pktio_cls_enabled(pktio_entry) &&
		    pktio_entry->s.config.parser.layer)
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer);
		packet_set_ts(pkt_hdr, ts);
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

	if (pktin_cfg->all_bits & PKTIN_CSUM_BITS) {
		int j;
		odp_packet_t pkt;

		for (i = 0, j = 0; i < nb_rx; i++) {
			pkt = pkt_table[i];

			if (pkt_set_ol_rx(pktin_cfg,
					  odp_packet_hdr(pkt),
					  pkt_to_mbuf(pkt))) {
				rte_pktmbuf_free(pkt_to_mbuf(pkt));
				continue;
			}
			if (i != j)
				pkt_table[j] = pkt;
			j++;
		}

		nb_rx = j;
	}
	return nb_rx;
}

static inline int check_proto(void *l3_hdr, odp_bool_t *l3_proto_v4,
			      uint8_t *l4_proto)
{
	uint8_t l3_proto_ver = _ODP_IPV4HDR_VER(*(uint8_t *)l3_hdr);

	if (l3_proto_ver == _ODP_IPV4) {
		struct ipv4_hdr *ip = (struct ipv4_hdr *)l3_hdr;

		*l3_proto_v4 = 1;
		if (!rte_ipv4_frag_pkt_is_fragmented(ip))
			*l4_proto = ip->next_proto_id;
		else
			*l4_proto = 0;

		return 0;
	} else if (l3_proto_ver == _ODP_IPV6) {
		struct ipv6_hdr *ipv6 = (struct ipv6_hdr *)l3_hdr;

		*l3_proto_v4 = 0;
		*l4_proto = ipv6->proto;
		return 0;
	}

	return -1;
}

static inline uint16_t phdr_csum(odp_bool_t ipv4, void *l3_hdr,
				 uint64_t ol_flags)
{
	if (ipv4)
		return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
	else /*ipv6*/
		return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}

#define OL_TX_CHKSUM_PKT(_cfg, _capa, _proto, _ovr_set, _ovr) \
	(_capa && _proto && (_ovr_set ? _ovr : _cfg))

static inline void pkt_set_ol_tx(odp_pktout_config_opt_t *pktout_cfg,
				 odp_pktout_config_opt_t *pktout_capa,
				 odp_packet_hdr_t *pkt_hdr,
				 struct rte_mbuf *mbuf,
				 char *mbuf_data)
{
	void *l3_hdr, *l4_hdr;
	uint8_t l4_proto;
	odp_bool_t l3_proto_v4;
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt;
	packet_parser_t *pkt_p = &pkt_hdr->p;

	if (pkt_p->l3_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	l3_hdr = (void *)(mbuf_data + pkt_p->l3_offset);

	if (check_proto(l3_hdr, &l3_proto_v4, &l4_proto))
		return;

	ipv4_chksum_pkt = OL_TX_CHKSUM_PKT(pktout_cfg->bit.ipv4_chksum,
					   pktout_capa->bit.ipv4_chksum,
					   l3_proto_v4,
					   pkt_p->output_flags.l3_chksum_set,
					   pkt_p->output_flags.l3_chksum);
	udp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.udp_chksum,
					   pktout_capa->bit.udp_chksum,
					   (l4_proto == _ODP_IPPROTO_UDP),
					   pkt_p->output_flags.l4_chksum_set,
					   pkt_p->output_flags.l4_chksum);
	tcp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.tcp_chksum,
					   pktout_capa->bit.tcp_chksum,
					   (l4_proto == _ODP_IPPROTO_TCP),
					   pkt_p->output_flags.l4_chksum_set,
					   pkt_p->output_flags.l4_chksum);

	if (!ipv4_chksum_pkt && !udp_chksum_pkt && !tcp_chksum_pkt)
		return;

	if (pkt_p->l4_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	mbuf->l2_len = pkt_p->l3_offset - pkt_p->l2_offset;
	mbuf->l3_len = pkt_p->l4_offset - pkt_p->l3_offset;

	if (l3_proto_v4)
		mbuf->ol_flags = PKT_TX_IPV4;
	else
		mbuf->ol_flags = PKT_TX_IPV6;

	if (ipv4_chksum_pkt) {
		mbuf->ol_flags |=  PKT_TX_IP_CKSUM;

		((struct ipv4_hdr *)l3_hdr)->hdr_checksum = 0;
	}

	l4_hdr = (void *)(mbuf_data + pkt_p->l4_offset);

	if (udp_chksum_pkt) {
		mbuf->ol_flags |= PKT_TX_UDP_CKSUM;

		((struct udp_hdr *)l4_hdr)->dgram_cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	} else if (tcp_chksum_pkt) {
		mbuf->ol_flags |= PKT_TX_TCP_CKSUM;

		((struct tcp_hdr *)l4_hdr)->cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	}
}

static int send_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 const odp_packet_t pkt_table[], int len)
{
	pkt_dpdk_t * const pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint8_t chksum_insert_ena = pktio_entry->s.chksum_insert_ena;
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->s.config.pktout;
	odp_pktout_config_opt_t *pktout_capa =
		&pktio_entry->s.capa.config.pktout;
	int pkts;
	int i;
	uint32_t mtu = pkt_dpdk->mtu;
	uint16_t num_tx = 0;

	for (i = 0; i < len; i++) {
		struct rte_mbuf *mbuf = pkt_to_mbuf(pkt_table[i]);

		if (odp_unlikely(mbuf->pkt_len > mtu))
			break;

		mbuf->ol_flags = 0;
		if (chksum_insert_ena)
			pkt_set_ol_tx(pktout_cfg, pktout_capa,
				      odp_packet_hdr(pkt_table[i]), mbuf,
				      rte_pktmbuf_mtod(mbuf, char *));

		num_tx++;
	}

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_lock(&pkt_dpdk->tx_lock[index]);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	pkts = rte_eth_tx_burst(pkt_dpdk->port_id, index,
				(struct rte_mbuf **)pkt_table, num_tx);
#pragma GCC diagnostic pop

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_unlock(&pkt_dpdk->tx_lock[index]);

	if (pkts == 0) {
		struct rte_mbuf *mbuf = pkt_to_mbuf(pkt_table[0]);

		if (odp_unlikely(rte_errno != 0))
			return -1;

		if (odp_unlikely(mbuf->pkt_len > mtu)) {
			__odp_errno = EMSGSIZE;
			return -1;
		}
	}
	rte_errno = 0;
	return pkts;
}

static uint32_t _dpdk_vdev_mtu(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
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
		return 0;
	}

	return ifr.ifr_mtu;
}

static uint32_t mtu_get_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	uint16_t mtu = 0;
	int ret;

	ret = rte_eth_dev_get_mtu(pktio_entry->s.pkt_dpdk.port_id, &mtu);
	if (ret < 0)
		return 0;

	/* some dpdk PMD vdev does not support getting mtu size,
	 * try to use system call if dpdk cannot get mtu value.
	 */
	if (mtu == 0)
		mtu = _dpdk_vdev_mtu(pktio_entry->s.pkt_dpdk.port_id);
	return mtu;
}

static uint32_t dpdk_frame_maxlen(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;

	return pkt_dpdk->mtu;
}

static int _dpdk_vdev_promisc_mode_set(uint16_t port_id, int enable)
{
	struct rte_eth_dev_info dev_info;
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
	uint16_t port_id = pktio_entry->s.pkt_dpdk.port_id;

	if (enable)
		rte_eth_promiscuous_enable(port_id);
	else
		rte_eth_promiscuous_disable(port_id);

	if (pktio_entry->s.pkt_dpdk.vdev_sysc_promisc) {
		int ret = _dpdk_vdev_promisc_mode_set(port_id, enable);
		if (ret < 0)
			ODP_DBG("vdev promisc mode fail\n");
	}

	return 0;
}

static int _dpdk_vdev_promisc_mode(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
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
	uint16_t port_id = pktio_entry->s.pkt_dpdk.port_id;
	if (pktio_entry->s.pkt_dpdk.vdev_sysc_promisc)
		return _dpdk_vdev_promisc_mode(port_id);
	else
		return rte_eth_promiscuous_get(port_id);

}

static int mac_get_pkt_dpdk(pktio_entry_t *pktio_entry, void *mac_addr)
{
	rte_eth_macaddr_get(pktio_entry->s.pkt_dpdk.port_id,
			    (struct ether_addr *)mac_addr);
	return ETH_ALEN;
}

static int mac_set_pkt_dpdk(pktio_entry_t *pktio_entry, const void *mac_addr)
{
	struct ether_addr addr = *(const struct ether_addr *)mac_addr;

	return rte_eth_dev_default_mac_addr_set(pktio_entry->s.pkt_dpdk.port_id,
						&addr);
}

static int capability_pkt_dpdk(pktio_entry_t *pktio_entry,
			       odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.capa;
	return 0;
}
static int link_status_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	struct rte_eth_link link;

	rte_eth_link_get(pktio_entry->s.pkt_dpdk.port_id, &link);
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

	ret = rte_eth_stats_get(pktio_entry->s.pkt_dpdk.port_id, &rte_stats);

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
	rte_eth_stats_reset(pktio_entry->s.pkt_dpdk.port_id);
	return 0;
}

const pktio_if_ops_t dpdk_pktio_ops = {
	.name = "odp-dpdk",
	.print = NULL,
	.init_global = NULL,
	.init_local = NULL,
	.term = term_pkt_dpdk,
	.open = setup_pkt_dpdk,
	.close = close_pkt_dpdk,
	.start = start_pkt_dpdk,
	.stop = stop_pkt_dpdk,
	.stats = stats_pkt_dpdk,
	.stats_reset = stats_reset_pkt_dpdk,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.mtu_get = dpdk_frame_maxlen,
	.promisc_mode_set = promisc_mode_set_pkt_dpdk,
	.promisc_mode_get = promisc_mode_get_pkt_dpdk,
	.mac_get = mac_get_pkt_dpdk,
	.mac_set = mac_set_pkt_dpdk,
	.link_status = link_status_pkt_dpdk,
	.capability = capability_pkt_dpdk,
	.config = NULL,
	.input_queues_config = input_queues_config_pkt_dpdk,
	.output_queues_config = output_queues_config_pkt_dpdk,
	.recv = recv_pkt_dpdk,
	.send = send_pkt_dpdk
};
