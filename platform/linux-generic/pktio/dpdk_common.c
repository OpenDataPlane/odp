/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2026 Nokia
 */

#include <odp/autoheader_internal.h>

#ifdef _ODP_PKTIO_DPDK

#include <odp_posix_extensions.h>

#include <odp/api/hints.h>
#include <odp/api/packet_io.h>

#include <odp_debug_internal.h>
#include <odp_dpdk_common.h>
#include <odp_string_internal.h>

#include <rte_ethdev.h>
#include <rte_version.h>

#include <ctype.h>
#include <errno.h>

int _odp_dpdk_netdev_is_valid(const char *s)
{
	while (*s) {
		if (!isdigit(*s))
			return 0;
		s++;
	}
	return 1;
}

static void hash_proto_to_rss_conf(struct rte_eth_rss_conf *rss_conf,
				   const odp_pktin_hash_proto_t *hash_proto)
{
	if (hash_proto->proto.ipv4_udp)
		rss_conf->rss_hf |= RTE_ETH_RSS_NONFRAG_IPV4_UDP;
	if (hash_proto->proto.ipv4_tcp)
		rss_conf->rss_hf |= RTE_ETH_RSS_NONFRAG_IPV4_TCP;
	if (hash_proto->proto.ipv4)
		rss_conf->rss_hf |= RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 |
				    RTE_ETH_RSS_NONFRAG_IPV4_OTHER;
	if (hash_proto->proto.ipv6_udp)
		rss_conf->rss_hf |= RTE_ETH_RSS_NONFRAG_IPV6_UDP |
				    RTE_ETH_RSS_IPV6_UDP_EX;
	if (hash_proto->proto.ipv6_tcp)
		rss_conf->rss_hf |= RTE_ETH_RSS_NONFRAG_IPV6_TCP |
				    RTE_ETH_RSS_IPV6_TCP_EX;
	if (hash_proto->proto.ipv6)
		rss_conf->rss_hf |= RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6 |
				    RTE_ETH_RSS_NONFRAG_IPV6_OTHER |
				    RTE_ETH_RSS_IPV6_EX;
	rss_conf->rss_key = NULL;
}

int _odp_dpdk_prepare_rss_conf(uint16_t port_id, struct rte_eth_rss_conf *rss_conf,
			       const odp_pktin_queue_param_t *p)
{
	struct rte_eth_dev_info dev_info;
	uint64_t rss_hf_capa;
	int ret;

	memset(rss_conf, 0, sizeof(struct rte_eth_rss_conf));

	/* Flow hashing not enabled */
	if (!p->hash_enable)
		return 0;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret) {
		_ODP_ERR("rte_eth_dev_info_get() failed: %d\n", ret);
		return -1;
	}

	rss_hf_capa = dev_info.flow_type_rss_offloads;

	/* Flow hashing is enabled but device does not support RSS */
	if (rss_hf_capa == 0) {
		_ODP_WARN("DPDK: flow hashing is enabled but not supported by the device\n");
		return 0;
	}

	/* Print debug info about unsupported hash protocols */
	if (p->hash_proto.proto.ipv4 &&
	    ((rss_hf_capa & RTE_ETH_RSS_IPV4) == 0))
		_ODP_WARN("DPDK: hash_proto.ipv4 not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv4_udp &&
	    ((rss_hf_capa & RTE_ETH_RSS_NONFRAG_IPV4_UDP) == 0))
		_ODP_WARN("DPDK: hash_proto.ipv4_udp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv4_tcp &&
	    ((rss_hf_capa & RTE_ETH_RSS_NONFRAG_IPV4_TCP) == 0))
		_ODP_WARN("DPDK: hash_proto.ipv4_tcp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6 &&
	    ((rss_hf_capa & RTE_ETH_RSS_IPV6) == 0))
		_ODP_WARN("DPDK: hash_proto.ipv6 not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6_udp &&
	    ((rss_hf_capa & RTE_ETH_RSS_NONFRAG_IPV6_UDP) == 0))
		_ODP_WARN("DPDK: hash_proto.ipv6_udp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6_tcp &&
	    ((rss_hf_capa & RTE_ETH_RSS_NONFRAG_IPV6_TCP) == 0))
		_ODP_WARN("DPDK: hash_proto.ipv6_tcp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	hash_proto_to_rss_conf(rss_conf, &p->hash_proto);

	/* Filter out unsupported hash functions */
	rss_conf->rss_hf &= rss_hf_capa;

	return 0;
}

int _odp_dpdk_stats_common(uint16_t port_id, odp_pktio_stats_t *stats)
{
	int ret;
	struct rte_eth_stats rte_stats;

	ret = rte_eth_stats_get(port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		_ODP_ERR("rte_eth_stats_get() failed: %d\n", ret);
		return -1;
	}

	stats->in_octets = rte_stats.ibytes;
	stats->in_packets = rte_stats.ipackets;
	stats->in_ucast_pkts = 0;
	stats->in_mcast_pkts = 0;
	stats->in_bcast_pkts = 0;
	stats->in_discards = rte_stats.imissed + rte_stats.rx_nombuf;
	stats->in_errors = rte_stats.ierrors;
	stats->out_octets = rte_stats.obytes;
	stats->out_packets = rte_stats.opackets;
	stats->out_ucast_pkts = 0;
	stats->out_mcast_pkts = 0;
	stats->out_bcast_pkts = 0;
	stats->out_discards = 0;
	stats->out_errors = rte_stats.oerrors;

	return 0;
}

int _odp_dpdk_stats_reset_common(uint16_t port_id)
{
	int ret;

	ret = rte_eth_stats_reset(port_id);
	if (ret) {
		if (ret == -ENOTSUP) {
			_ODP_DBG("rte_eth_stats_reset() not supported\n");
		} else {
			_ODP_ERR("rte_eth_stats_reset() failed: %d\n", ret);
			return -1;
		}
	}

	ret = rte_eth_xstats_reset(port_id);
	if (ret) {
		if (ret == -ENOTSUP) {
			_ODP_DBG("rte_eth_xstats_reset() not supported\n");
		} else {
			_ODP_ERR("rte_eth_xstats_reset() failed: %d\n", ret);
			return -1;
		}
	}
	return 0;
}

int _odp_dpdk_extra_stat_info_common(uint16_t port_id, odp_pktio_extra_stat_info_t info[], int num)
{
	int num_stats, ret, i;

	num_stats = rte_eth_xstats_get_names(port_id, NULL, 0);
	if (num_stats < 0) {
		_ODP_ERR("rte_eth_xstats_get_names() failed: %d\n", num_stats);
		return num_stats;
	} else if (info == NULL || num == 0 || num_stats == 0) {
		return num_stats;
	}

	struct rte_eth_xstat_name xstats_names[num_stats];

	ret = rte_eth_xstats_get_names(port_id, xstats_names, num_stats);
	if (ret < 0 || ret > num_stats) {
		_ODP_ERR("rte_eth_xstats_get_names() failed: %d\n", ret);
		return -1;
	}
	num_stats = ret;

	for (i = 0; i < num && i < num_stats; i++)
		_odp_strcpy(info[i].name, xstats_names[i].name, ODP_PKTIO_STATS_EXTRA_NAME_LEN);

	return num_stats;
}

int _odp_dpdk_extra_stats_common(uint16_t port_id, uint64_t stats[], int num)
{
	int num_stats, ret, i;

	num_stats = rte_eth_xstats_get(port_id, NULL, 0);
	if (num_stats < 0) {
		_ODP_ERR("rte_eth_xstats_get() failed: %d\n", num_stats);
		return num_stats;
	} else if (stats == NULL || num == 0 || num_stats == 0) {
		return num_stats;
	}

	struct rte_eth_xstat xstats[num_stats];

	ret = rte_eth_xstats_get(port_id, xstats, num_stats);
	if (ret < 0 || ret > num_stats) {
		_ODP_ERR("rte_eth_xstats_get() failed: %d\n", ret);
		return -1;
	}
	num_stats = ret;

	for (i = 0; i < num && i < num_stats; i++)
		stats[i] = xstats[i].value;

	return num_stats;
}

int _odp_dpdk_extra_stat_counter_common(uint16_t port_id, uint32_t id, uint64_t *stat)
{
	uint64_t xstat_id = id;
	int ret;

	ret = rte_eth_xstats_get_by_id(port_id, &xstat_id, stat, 1);
	if (ret != 1) {
		_ODP_ERR("rte_eth_xstats_get_by_id() failed: %d\n", ret);
		return -1;
	}

	return 0;
}

#if RTE_VERSION < RTE_VERSION_NUM(25, 11, 0, 0)
int _odp_dpdk_pktin_stats_common(uint16_t port_id, uint32_t index,
				 odp_pktin_queue_stats_t *pktin_stats)
{
	struct rte_eth_stats rte_stats;
	int ret;

	if (odp_unlikely(index > RTE_ETHDEV_QUEUE_STAT_CNTRS - 1)) {
		_ODP_ERR("DPDK supports max %d per queue counters\n", RTE_ETHDEV_QUEUE_STAT_CNTRS);
		return -1;
	}

	ret = rte_eth_stats_get(port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		_ODP_ERR("rte_eth_stats_get() failed: %d\n", ret);
		return -1;
	}

	memset(pktin_stats, 0, sizeof(odp_pktin_queue_stats_t));

	pktin_stats->packets = rte_stats.q_ipackets[index];
	pktin_stats->octets = rte_stats.q_ibytes[index];
	pktin_stats->errors = rte_stats.q_errors[index];

	return 0;
}
#else
int _odp_dpdk_pktin_stats_common(uint16_t port_id ODP_UNUSED, uint32_t index ODP_UNUSED,
				 odp_pktin_queue_stats_t *pktin_stats)
{
	memset(pktin_stats, 0, sizeof(*pktin_stats));
	return 0;
}
#endif

#if RTE_VERSION < RTE_VERSION_NUM(25, 11, 0, 0)
int _odp_dpdk_pktout_stats_common(uint16_t port_id, uint32_t index,
				  odp_pktout_queue_stats_t *pktout_stats)
{
	struct rte_eth_stats rte_stats;
	int ret;

	if (odp_unlikely(index > RTE_ETHDEV_QUEUE_STAT_CNTRS - 1)) {
		_ODP_ERR("DPDK supports max %d per queue counters\n", RTE_ETHDEV_QUEUE_STAT_CNTRS);
		return -1;
	}

	ret = rte_eth_stats_get(port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		_ODP_ERR("rte_eth_stats_get() failed: %d\n", ret);
		return -1;
	}

	memset(pktout_stats, 0, sizeof(odp_pktout_queue_stats_t));

	pktout_stats->packets = rte_stats.q_opackets[index];
	pktout_stats->octets = rte_stats.q_obytes[index];

	return 0;
}
#else
int _odp_dpdk_pktout_stats_common(uint16_t port_id ODP_UNUSED, uint32_t index ODP_UNUSED,
				  odp_pktout_queue_stats_t *pktout_stats)
{
	memset(pktout_stats, 0, sizeof(*pktout_stats));
	return 0;
}
#endif

int _odp_dpdk_link_status_common(uint16_t port_id)
{
	struct rte_eth_link link;
	int ret;

	ret = rte_eth_link_get_nowait(port_id, &link);
	if (odp_unlikely(ret)) {
		if (ret == -ENOTSUP)
			_ODP_DBG("rte_eth_link_get_nowait() not supported\n");
		else
			_ODP_ERR("rte_eth_link_get_nowait() failed: %d\n", ret);
		return ODP_PKTIO_LINK_STATUS_UNKNOWN;
	}

	return link.link_status ? ODP_PKTIO_LINK_STATUS_UP : ODP_PKTIO_LINK_STATUS_DOWN;
}

int _odp_dpdk_link_info_common(uint16_t port_id, odp_pktio_link_info_t *info)
{
	struct rte_eth_link link;
	struct rte_eth_fc_conf fc_conf;
	odp_pktio_link_info_t link_info;
	int ret;

	memset(&link_info, 0, sizeof(odp_pktio_link_info_t));

	ret = rte_eth_dev_flow_ctrl_get(port_id, &fc_conf);
	if (ret) {
		if (ret != -ENOTSUP) {
			_ODP_ERR("rte_eth_dev_flow_ctrl_get() failed: %d\n", ret);
			return -1;
		}
		_ODP_DBG("rte_eth_dev_flow_ctrl_get() not supported\n");
		link_info.pause_rx = ODP_PKTIO_LINK_PAUSE_UNKNOWN;
		link_info.pause_tx = ODP_PKTIO_LINK_PAUSE_UNKNOWN;
	} else {
		link_info.pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
		link_info.pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
		if (fc_conf.mode == RTE_ETH_FC_RX_PAUSE) {
			link_info.pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
		} else if (fc_conf.mode == RTE_ETH_FC_TX_PAUSE) {
			link_info.pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
		} else if (fc_conf.mode == RTE_ETH_FC_FULL) {
			link_info.pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
			link_info.pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
		}
	}

	ret = rte_eth_link_get_nowait(port_id, &link);
	if (ret) {
		if (ret != -ENOTSUP) {
			_ODP_ERR("rte_eth_link_get_nowait() failed: %d\n", ret);
			return -1;
		}
		_ODP_DBG("rte_eth_link_get_nowait() not supported\n");
		link_info.autoneg = ODP_PKTIO_LINK_AUTONEG_UNKNOWN;
		link_info.duplex = ODP_PKTIO_LINK_DUPLEX_UNKNOWN;
		link_info.speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
		link_info.status = ODP_PKTIO_LINK_STATUS_UNKNOWN;
		link_info.media = "unknown";
	} else {
		if (link.link_autoneg == RTE_ETH_LINK_AUTONEG)
			link_info.autoneg = ODP_PKTIO_LINK_AUTONEG_ON;
		else
			link_info.autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;

		if (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX)
			link_info.duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
		else
			link_info.duplex = ODP_PKTIO_LINK_DUPLEX_HALF;

		if (link.link_speed == RTE_ETH_SPEED_NUM_NONE)
			link_info.speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
		else
			link_info.speed = link.link_speed;

		if (link.link_status == RTE_ETH_LINK_UP)
			link_info.status = ODP_PKTIO_LINK_STATUS_UP;
		else
			link_info.status = ODP_PKTIO_LINK_STATUS_DOWN;

#if RTE_VERSION >= RTE_VERSION_NUM(25, 11, 0, 0)
		if (link.link_connector == RTE_ETH_LINK_CONNECTOR_NONE)
			link_info.media = "unknown";
		else
			link_info.media = rte_eth_link_connector_to_str(link.link_connector);
#else
		link_info.media = "unknown";
#endif
	}

	*info = link_info;
	return 0;
}

#else
/* Avoid warning about empty translation unit */
typedef int _odp_dummy;
#endif /* _ODP_PKTIO_DPDK */
