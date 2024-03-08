/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2019-2020 Nokia
 */

#include <odp_posix_extensions.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <errno.h>
#include <odp_debug_internal.h>
#include <odp_socket_common.h>
#include <protocols/eth.h>

/* Fallback for old kernels (< v4.6) */
#ifndef ETHTOOL_GLINKSETTINGS
#define ETHTOOL_GLINKSETTINGS 0x0000004c

struct ethtool_link_settings {
	uint32_t cmd;
	uint32_t speed;
	uint8_t  duplex;
	uint8_t  port;
	uint8_t  phy_address;
	uint8_t  autoneg;
	uint8_t  mdio_support;
	uint8_t  eth_tp_mdix;
	uint8_t  eth_tp_mdix_ctrl;
	int8_t   link_mode_masks_nwords;
	uint32_t reserved[8];
	uint32_t link_mode_masks[0];
};
#endif

/**
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 */
int _odp_mac_addr_get_fd(int fd, const char *name, unsigned char mac_dst[])
{
	struct ifreq ethreq;
	int ret;

	memset(&ethreq, 0, sizeof(ethreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFHWADDR, &ethreq);
	if (ret != 0) {
		_ODP_ERR("ioctl(SIOCGIFHWADDR): %s: \"%s\".\n", strerror(errno), ethreq.ifr_name);
		return -1;
	}

	memcpy(mac_dst, (unsigned char *)ethreq.ifr_ifru.ifru_hwaddr.sa_data,
	       ETH_ALEN);
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_TAP:
 */
uint32_t _odp_mtu_get_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		_ODP_ERR("ioctl(SIOCGIFMTU): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return 0;
	}
	return ifr.ifr_mtu + _ODP_ETHHDR_LEN;
}

/*
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_TAP:
 */
int _odp_mtu_set_fd(int fd, const char *name, int mtu)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ifr.ifr_mtu = mtu - _ODP_ETHHDR_LEN;

	ret = ioctl(fd, SIOCSIFMTU, &ifr);
	if (ret < 0) {
		_ODP_ERR("ioctl(SIOCSIFMTU): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return -1;
	}
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 */
int _odp_promisc_mode_set_fd(int fd, const char *name, int enable)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		_ODP_DBG("ioctl(SIOCGIFFLAGS): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		_ODP_DBG("ioctl(SIOCSIFFLAGS): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return -1;
	}
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 */
int _odp_promisc_mode_get_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		_ODP_DBG("ioctl(SIOCGIFFLAGS): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return -1;
	}

	return !!(ifr.ifr_flags & IFF_PROMISC);
}

int _odp_link_status_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		_ODP_DBG("ioctl(SIOCGIFFLAGS): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return ODP_PKTIO_LINK_STATUS_UNKNOWN;
	}

	if (ifr.ifr_flags & IFF_RUNNING)
		return ODP_PKTIO_LINK_STATUS_UP;
	return ODP_PKTIO_LINK_STATUS_DOWN;
}

int _odp_link_info_fd(int fd, const char *name, odp_pktio_link_info_t *info)
{
	struct ethtool_link_settings hcmd = {.cmd = ETHTOOL_GLINKSETTINGS};
	struct ethtool_link_settings *ecmd;
	struct ethtool_pauseparam pcmd = {.cmd = ETHTOOL_GPAUSEPARAM};
	struct ifreq ifr;
	int status;

	status = _odp_link_status_fd(fd, name);
	if (status < 0)
		return -1;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);

	/* Link pause status */
	ifr.ifr_data = (void *)&pcmd;
	if (ioctl(fd, SIOCETHTOOL, &ifr) && errno != EOPNOTSUPP) {
		_ODP_ERR("ioctl(SIOCETHTOOL): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return -1;
	}

	/* Try to perform handshake and fall back to old API if failed */
	ifr.ifr_data = (void *)&hcmd;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
		struct ethtool_cmd ecmd_old = {.cmd = ETHTOOL_GSET};

		ifr.ifr_data = (void *)&ecmd_old;
		if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
			_ODP_ERR("ioctl(SIOCETHTOOL): %s: \"%s\".\n", strerror(errno),
				 ifr.ifr_name);
			return -1;
		}

		memset(info, 0, sizeof(odp_pktio_link_info_t));
		info->speed = ethtool_cmd_speed(&ecmd_old);
		if (info->speed == (uint32_t)SPEED_UNKNOWN)
			info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;

		if (ecmd_old.autoneg == AUTONEG_ENABLE)
			info->autoneg = ODP_PKTIO_LINK_AUTONEG_ON;
		else if (ecmd_old.autoneg == AUTONEG_DISABLE)
			info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;
		else
			info->autoneg = ODP_PKTIO_LINK_AUTONEG_UNKNOWN;

		if (ecmd_old.duplex == DUPLEX_HALF)
			info->duplex = ODP_PKTIO_LINK_DUPLEX_HALF;
		else if (ecmd_old.duplex == DUPLEX_FULL)
			info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
		else
			info->duplex = ODP_PKTIO_LINK_DUPLEX_UNKNOWN;

		info->pause_rx = pcmd.rx_pause ? ODP_PKTIO_LINK_PAUSE_ON : ODP_PKTIO_LINK_PAUSE_OFF;
		info->pause_tx = pcmd.tx_pause ? ODP_PKTIO_LINK_PAUSE_ON : ODP_PKTIO_LINK_PAUSE_OFF;

		if (ecmd_old.port == PORT_TP)
			info->media = "copper";
		else if (ecmd_old.port == PORT_FIBRE)
			info->media = "fiber";
		else if (ecmd_old.port == PORT_OTHER)
			info->media = "other";
		else
			info->media = "unknown";

		info->status = status;

		return 0;
	}

	if (hcmd.link_mode_masks_nwords >= 0 || hcmd.cmd != ETHTOOL_GLINKSETTINGS) {
		_ODP_ERR("ETHTOOL_GLINKSETTINGS handshake failed\n");
		return -1;
	}
	/* Absolute value indicates kernel recommended 'link_mode_masks_nwords' value. */
	hcmd.link_mode_masks_nwords = -hcmd.link_mode_masks_nwords;

	/* Reserve space for the three bitmasks (map_supported, map_advertising, map_lp_advertising)
	 * at the end of struct ethtool_link_settings. 'link_mode_masks_nwords' defines the bitmask
	 * length in 32-bit words. */
	uint8_t data[offsetof(struct ethtool_link_settings, link_mode_masks) +
		     (3 * sizeof(uint32_t) * hcmd.link_mode_masks_nwords)] ODP_ALIGNED_CACHE;

	ecmd = (void *)data;
	*ecmd = hcmd;
	ifr.ifr_data = (void *)ecmd;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
		_ODP_ERR("ioctl(SIOCETHTOOL): %s: \"%s\".\n", strerror(errno), ifr.ifr_name);
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_link_info_t));
	if (ecmd->speed == (uint32_t)SPEED_UNKNOWN)
		info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
	else
		info->speed = ecmd->speed;

	if (ecmd->autoneg == AUTONEG_ENABLE)
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_ON;
	else if (ecmd->autoneg == AUTONEG_DISABLE)
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;
	else
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_UNKNOWN;

	if (ecmd->duplex == DUPLEX_HALF)
		info->duplex = ODP_PKTIO_LINK_DUPLEX_HALF;
	else if (ecmd->duplex == DUPLEX_FULL)
		info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
	else
		info->duplex = ODP_PKTIO_LINK_DUPLEX_UNKNOWN;

	info->pause_rx = pcmd.rx_pause ? ODP_PKTIO_LINK_PAUSE_ON : ODP_PKTIO_LINK_PAUSE_OFF;
	info->pause_tx = pcmd.tx_pause ? ODP_PKTIO_LINK_PAUSE_ON : ODP_PKTIO_LINK_PAUSE_OFF;

	if (ecmd->port == PORT_TP)
		info->media = "copper";
	else if (ecmd->port == PORT_FIBRE)
		info->media = "fiber";
	else if (ecmd->port == PORT_OTHER)
		info->media = "other";
	else
		info->media = "unknown";

	info->status = status;

	return 0;
}
