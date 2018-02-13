/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>
#include <protocols/eth.h>
#include <pktio/ethtool.h>
#include <pktio/common.h>
#include <pktio/sysfs.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd)
{
	int err = 0;
	odp_pktio_stats_t cur_stats;

	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(&pktio_entry->s.stats, 0,
		       sizeof(odp_pktio_stats_t));
		return 0;
	}

	memset(&cur_stats, 0, sizeof(odp_pktio_stats_t));

	if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		(void)ethtool_stats_get_fd(fd,
					   pktio_entry->s.name,
					   &cur_stats);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		err = sysfs_netif_stats(pktio_entry->s.name, &cur_stats);
		if (err != 0)
			ODP_ERR("stats error\n");
	}

	if (err == 0)
		memcpy(&pktio_entry->s.stats, &cur_stats,
		       sizeof(odp_pktio_stats_t));

	return err;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int sock_stats_fd(pktio_entry_t *pktio_entry,
		  odp_pktio_stats_t *stats,
		  int fd)
{
	odp_pktio_stats_t cur_stats;
	int ret = 0;

	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		return 0;

	memset(&cur_stats, 0, sizeof(odp_pktio_stats_t));
	if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		(void)ethtool_stats_get_fd(fd,
					   pktio_entry->s.name,
					   &cur_stats);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		sysfs_netif_stats(pktio_entry->s.name, &cur_stats);
	}

	stats->in_octets = cur_stats.in_octets -
				pktio_entry->s.stats.in_octets;
	stats->in_ucast_pkts = cur_stats.in_ucast_pkts -
				pktio_entry->s.stats.in_ucast_pkts;
	stats->in_discards = cur_stats.in_discards -
				pktio_entry->s.stats.in_discards;
	stats->in_errors = cur_stats.in_errors -
				pktio_entry->s.stats.in_errors;
	stats->in_unknown_protos = cur_stats.in_unknown_protos -
				pktio_entry->s.stats.in_unknown_protos;

	stats->out_octets = cur_stats.out_octets -
				pktio_entry->s.stats.out_octets;
	stats->out_ucast_pkts = cur_stats.out_ucast_pkts -
				pktio_entry->s.stats.out_ucast_pkts;
	stats->out_discards = cur_stats.out_discards -
				pktio_entry->s.stats.out_discards;
	stats->out_errors = cur_stats.out_errors -
				pktio_entry->s.stats.out_errors;

	return ret;
}

/**
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int mac_addr_get_fd(int fd, const char *name, unsigned char mac_dst[])
{
	struct ifreq ethreq;
	int ret;

	memset(&ethreq, 0, sizeof(ethreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFHWADDR, &ethreq);
	if (ret != 0) {
		__odp_errno = errno;
		ODP_ERR("ioctl(SIOCGIFHWADDR): %s: \"%s\".\n", strerror(errno),
			ethreq.ifr_name);
		return -1;
	}

	memcpy(mac_dst, (unsigned char *)ethreq.ifr_ifru.ifru_hwaddr.sa_data,
	       ETH_ALEN);
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
uint32_t mtu_get_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		__odp_errno = errno;
		ODP_DBG("ioctl(SIOCGIFMTU): %s: \"%s\".\n", strerror(errno),
			ifr.ifr_name);
		return 0;
	}
	return ifr.ifr_mtu + _ODP_ETHHDR_LEN;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int promisc_mode_set_fd(int fd, const char *name, int enable)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		__odp_errno = errno;
		ODP_DBG("ioctl(SIOCGIFFLAGS): %s: \"%s\".\n", strerror(errno),
			ifr.ifr_name);
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		__odp_errno = errno;
		ODP_DBG("ioctl(SIOCSIFFLAGS): %s: \"%s\".\n", strerror(errno),
			ifr.ifr_name);
		return -1;
	}
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int promisc_mode_get_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		__odp_errno = errno;
		ODP_DBG("ioctl(SIOCGIFFLAGS): %s: \"%s\".\n", strerror(errno),
			ifr.ifr_name);
		return -1;
	}

	return !!(ifr.ifr_flags & IFF_PROMISC);
}

int link_status_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		__odp_errno = errno;
		ODP_DBG("ioctl(SIOCGIFFLAGS): %s: \"%s\".\n", strerror(errno),
			ifr.ifr_name);
		return -1;
	}

	return !!(ifr.ifr_flags & IFF_RUNNING);
}

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

	ifr.ifr_data = (void *)&rsscmd;

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

	ifr.ifr_data = (void *)&rsscmd;

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

static int sock_recv_mq_tmo_select(pktio_entry_t * const *entry,
				   const int index[],
				   unsigned num_q, unsigned *from,
				   odp_packet_t packets[], int num,
				   uint64_t usecs, fd_set *readfds,
				   int maxfd)
{
	struct timeval timeout;
	unsigned i;
	int ret;

	for (i = 0; i < num_q; i++) {
		ret = entry[i]->s.ops->recv(entry[i], index[i], packets, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	if (select(maxfd + 1, readfds, NULL, NULL,
		   usecs == ODP_PKTIN_WAIT ? NULL : &timeout) == 0)
		return 0;

	for (i = 0; i < num_q; i++) {
		ret = entry[i]->s.ops->recv(entry[i], index[i], packets, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	return 0;
}

int sock_recv_mq_tmo_try_int_driven(const struct odp_pktin_queue_t queues[],
				    unsigned num_q, unsigned *from,
				    odp_packet_t packets[], int num,
				    uint64_t usecs, int *trial_successful)
{
	unsigned i;
	pktio_entry_t *entry[num_q];
	int index[num_q];
	fd_set readfds;
	int maxfd = -1;
	int (*impl)(pktio_entry_t *entry[], int index[], int num_q,
		    odp_packet_t packets[], int num, unsigned *from,
		    uint64_t wait_usecs) = NULL;
	int impl_set = 0;

	/* First, we get pktio entries and queue indices. We then see if the
	   implementation function pointers are the same. If they are the
	   same, impl will be set to non-NULL; otherwise it will be NULL. */

	for (i = 0; i < num_q; i++) {
		entry[i] = get_pktio_entry(queues[i].pktio);
		index[i] = queues[i].index;
		if (entry[i] == NULL) {
			ODP_DBG("pktio entry %d does not exist\n",
				queues[i].pktio);
			*trial_successful = 0;
			return -1;
		}
		if (entry[i]->s.ops->recv_mq_tmo == NULL &&
		    entry[i]->s.ops->fd_set == NULL) {
			*trial_successful = 0;
			return 0;
		}
		if (!impl_set) {
			impl = entry[i]->s.ops->recv_mq_tmo;
			impl_set = 1;
		} else {
			if (impl != entry[i]->s.ops->recv_mq_tmo) {
				impl = NULL;
				break;
			}
		}
	}

	/* Check whether we can call the compatible implementation */
	if (impl != NULL) {
		*trial_successful = 1;
		return impl(entry, index, num_q, packets, num, from, usecs);
	}

	/* Get file descriptor sets of devices. maxfd will be -1 if this
	   fails. */
	FD_ZERO(&readfds);
	for (i = 0; i < num_q; i++) {
		if (entry[i]->s.ops->fd_set) {
			int maxfd2;

			maxfd2 = entry[i]->s.ops->fd_set(
				entry[i], queues[i].index, &readfds);
			if (maxfd2 < 0) {
				maxfd = -1;
				break;
			}
			if (maxfd2 > maxfd)
				maxfd = maxfd2;
		} else {
			maxfd = -1;
		}
	}

	/* Check whether we can call the select() implementation */
	if (maxfd >= 0) {
		*trial_successful = 1;
		return sock_recv_mq_tmo_select(entry, index, num_q, from,
					       packets, num, usecs,
					       &readfds, maxfd);
	}

	/* No mechanism worked. Set trial_successful to 0 so that polling will
	   be used by the main implementation. */
	*trial_successful = 0;
	return 0;
}
