/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2026 Nokia
 */

#include <odp/autoheader_internal.h>

#ifdef _ODP_PKTIO_DPDK

#include <odp_posix_extensions.h>

#include <odp/api/packet_io.h>

#include <odp_dpdk_common.h>

#include <rte_ethdev.h>

#include <ctype.h>

int _odp_dpdk_netdev_is_valid(const char *s)
{
	while (*s) {
		if (!isdigit(*s))
			return 0;
		s++;
	}
	return 1;
}

void _odp_dpdk_hash_proto_to_rss_conf(struct rte_eth_rss_conf *rss_conf,
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

#else
/* Avoid warning about empty translation unit */
typedef int _odp_dummy;
#endif /* _ODP_PKTIO_DPDK */
