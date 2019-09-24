/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <odp_ethtool_rss.h>
#include <odp_debug_internal.h>

/**
 * Get enabled hash options of a packet socket
 *
 * @param fd              Socket file descriptor
 * @param name            Interface name
 * @param flow_type       Packet flow type
 * @param options[out]    Enabled hash options
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
static inline int get_rss_hash_options(int fd, const char *name,
				       uint32_t flow_type, uint64_t *options)
{
	struct ifreq ifr;
	struct ethtool_rxnfc rsscmd;

	memset(&ifr, 0, sizeof(ifr));
	memset(&rsscmd, 0, sizeof(rsscmd));
	*options = 0;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);

	rsscmd.cmd = ETHTOOL_GRXFH;
	rsscmd.flow_type = flow_type;

	ifr.ifr_data = (caddr_t)&rsscmd;

	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
		return -1;

	*options = rsscmd.data;
	return 0;
}

int rss_conf_get_fd(int fd, const char *name,
		    odp_pktin_hash_proto_t *hash_proto)
{
	uint64_t options;
	int rss_enabled = 0;

	memset(hash_proto, 0, sizeof(odp_pktin_hash_proto_t));

	get_rss_hash_options(fd, name, IPV4_FLOW, &options);
	if ((options & RXH_IP_SRC) && (options & RXH_IP_DST)) {
		hash_proto->proto.ipv4 = 1;
		rss_enabled++;
	}
	get_rss_hash_options(fd, name, TCP_V4_FLOW, &options);
	if ((options & RXH_IP_SRC) && (options & RXH_IP_DST) &&
	    (options & RXH_L4_B_0_1) && (options & RXH_L4_B_2_3)) {
		hash_proto->proto.ipv4_tcp = 1;
		rss_enabled++;
	}
	get_rss_hash_options(fd, name, UDP_V4_FLOW, &options);
	if ((options & RXH_IP_SRC) && (options & RXH_IP_DST) &&
	    (options & RXH_L4_B_0_1) && (options & RXH_L4_B_2_3)) {
		hash_proto->proto.ipv4_udp = 1;
		rss_enabled++;
	}
	get_rss_hash_options(fd, name, IPV6_FLOW, &options);
	if ((options & RXH_IP_SRC) && (options & RXH_IP_DST)) {
		hash_proto->proto.ipv6 = 1;
		rss_enabled++;
	}
	get_rss_hash_options(fd, name, TCP_V6_FLOW, &options);
	if ((options & RXH_IP_SRC) && (options & RXH_IP_DST) &&
	    (options & RXH_L4_B_0_1) && (options & RXH_L4_B_2_3)) {
		hash_proto->proto.ipv6_tcp = 1;
		rss_enabled++;
	}
	get_rss_hash_options(fd, name, UDP_V6_FLOW, &options);
	if ((options & RXH_IP_SRC) && (options & RXH_IP_DST) &&
	    (options & RXH_L4_B_0_1) && (options & RXH_L4_B_2_3)) {
		hash_proto->proto.ipv6_udp = 1;
		rss_enabled++;
	}
	return rss_enabled;
}

/**
 * Set hash options of a packet socket
 *
 * @param fd              Socket file descriptor
 * @param name            Interface name
 * @param flow_type       Packet flow type
 * @param options         Hash options
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
static inline int set_rss_hash(int fd, const char *name,
			       uint32_t flow_type, uint64_t options)
{
	struct ifreq ifr;
	struct ethtool_rxnfc rsscmd;

	memset(&rsscmd, 0, sizeof(rsscmd));

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);

	rsscmd.cmd = ETHTOOL_SRXFH;
	rsscmd.flow_type = flow_type;
	rsscmd.data = options;

	ifr.ifr_data = (caddr_t)&rsscmd;

	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
		return -1;

	return 0;
}

int rss_conf_set_fd(int fd, const char *name,
		    const odp_pktin_hash_proto_t *hash_proto)
{
	uint64_t options;
	odp_pktin_hash_proto_t cur_hash;

	/* Compare to currently set hash protocols */
	rss_conf_get_fd(fd, name, &cur_hash);

	if (hash_proto->proto.ipv4_udp && !cur_hash.proto.ipv4_udp) {
		options = RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3;
		if (set_rss_hash(fd, name, UDP_V4_FLOW, options))
			return -1;
	}
	if (hash_proto->proto.ipv4_tcp && !cur_hash.proto.ipv4_tcp) {
		options = RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3;
		if (set_rss_hash(fd, name, TCP_V4_FLOW, options))
			return -1;
	}
	if (hash_proto->proto.ipv6_udp && !cur_hash.proto.ipv6_udp) {
		options = RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3;
		if (set_rss_hash(fd, name, UDP_V6_FLOW, options))
			return -1;
	}
	if (hash_proto->proto.ipv6_tcp && !cur_hash.proto.ipv6_tcp) {
		options = RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3;
		if (set_rss_hash(fd, name, TCP_V6_FLOW, options))
			return -1;
	}
	if (hash_proto->proto.ipv4 && !cur_hash.proto.ipv4) {
		options = RXH_IP_SRC | RXH_IP_DST;
		if (set_rss_hash(fd, name, IPV4_FLOW, options))
			return -1;
	}
	if (hash_proto->proto.ipv6 && !cur_hash.proto.ipv6) {
		options = RXH_IP_SRC | RXH_IP_DST;
		if (set_rss_hash(fd, name, IPV6_FLOW, options))
			return -1;
	}
	return 0;
}

int rss_conf_get_supported_fd(int fd, const char *name,
			      odp_pktin_hash_proto_t *hash_proto)
{
	uint64_t options;
	int rss_supported = 0;

	memset(hash_proto, 0, sizeof(odp_pktin_hash_proto_t));

	if (!get_rss_hash_options(fd, name, IPV4_FLOW, &options)) {
		if (!set_rss_hash(fd, name, IPV4_FLOW, options)) {
			hash_proto->proto.ipv4 = 1;
			rss_supported++;
		}
	}
	if (!get_rss_hash_options(fd, name, TCP_V4_FLOW, &options)) {
		if (!set_rss_hash(fd, name, TCP_V4_FLOW, options)) {
			hash_proto->proto.ipv4_tcp = 1;
			rss_supported++;
		}
	}
	if (!get_rss_hash_options(fd, name, UDP_V4_FLOW, &options)) {
		if (!set_rss_hash(fd, name, UDP_V4_FLOW, options)) {
			hash_proto->proto.ipv4_udp = 1;
			rss_supported++;
		}
	}
	if (!get_rss_hash_options(fd, name, IPV6_FLOW, &options)) {
		if (!set_rss_hash(fd, name, IPV6_FLOW, options)) {
			hash_proto->proto.ipv6 = 1;
			rss_supported++;
		}
	}
	if (!get_rss_hash_options(fd, name, TCP_V6_FLOW, &options)) {
		if (!set_rss_hash(fd, name, TCP_V6_FLOW, options)) {
			hash_proto->proto.ipv6_tcp = 1;
			rss_supported++;
		}
	}
	if (!get_rss_hash_options(fd, name, UDP_V6_FLOW, &options)) {
		if (!set_rss_hash(fd, name, UDP_V6_FLOW, options)) {
			hash_proto->proto.ipv6_udp = 1;
			rss_supported++;
		}
	}
	return rss_supported;
}

void rss_conf_print(const odp_pktin_hash_proto_t *hash_proto)
{	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;

	len += snprintf(&str[len], n - len, " rss conf\n");

	if (hash_proto->proto.ipv4)
		len += snprintf(&str[len], n - len,
				"    IPV4\n");
	if (hash_proto->proto.ipv4_tcp)
		len += snprintf(&str[len], n - len,
				"    IPV4 TCP\n");
	if (hash_proto->proto.ipv4_udp)
		len += snprintf(&str[len], n - len,
				"    IPV4 UDP\n");
	if (hash_proto->proto.ipv6)
		len += snprintf(&str[len], n - len,
				"    IPV6\n");
	if (hash_proto->proto.ipv6_tcp)
		len += snprintf(&str[len], n - len,
				"    IPV6 TCP\n");
	if (hash_proto->proto.ipv6_udp)
		len += snprintf(&str[len], n - len,
				"    IPV6 UDP\n");
	str[len] = '\0';

	ODP_PRINT("%s\n", str);
}

