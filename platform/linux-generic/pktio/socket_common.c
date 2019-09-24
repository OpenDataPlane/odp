/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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
#include <net/if.h>
#include <linux/if_packet.h>
#include <errno.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp_socket_common.h>
#include <protocols/eth.h>

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
 * ODP_PACKET_NETMAP:
 */
int mtu_set_fd(int fd, const char *name, int mtu)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ifr.ifr_mtu = mtu;

	ret = ioctl(fd, SIOCSIFMTU, &ifr);
	if (ret < 0) {
		__odp_errno = errno;
		ODP_DBG("ioctl(SIOCSIFMTU): %s: \"%s\".\n", strerror(errno),
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
