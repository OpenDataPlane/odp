/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2019 Nokia
 */

#ifndef ODP_SOCKET_COMMON_H_
#define ODP_SOCKET_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet_io.h>
#include <protocols/eth.h>

#include <string.h>

#define _ODP_SOCKET_MTU_MIN (68 + _ODP_ETHHDR_LEN)
#define _ODP_SOCKET_MTU_MAX (9000 + _ODP_ETHHDR_LEN)

static inline void
ethaddr_copy(unsigned char mac_dst[], unsigned char mac_src[])
{
	memcpy(mac_dst, mac_src, _ODP_ETHADDR_LEN);
}

static inline int
ethaddrs_equal(unsigned char mac_a[], unsigned char mac_b[])
{
	return !memcmp(mac_a, mac_b, _ODP_ETHADDR_LEN);
}

/**
 * Read the MAC address from a packet socket
 */
int _odp_mac_addr_get_fd(int fd, const char *name, unsigned char mac_dst[]);

/**
 * Read the MTU from a packet socket
 */
uint32_t _odp_mtu_get_fd(int fd, const char *name);

/**
 * Set a packet socket MTU
 */
int _odp_mtu_set_fd(int fd, const char *name, int mtu);

/**
 * Enable/Disable promisc mode for a packet socket
 */
int _odp_promisc_mode_set_fd(int fd, const char *name, int enable);

/**
 * Return promisc mode of a packet socket
 */
int _odp_promisc_mode_get_fd(int fd, const char *name);

/**
 * Return link status of a packet socket (up/down)
 */
int _odp_link_status_fd(int fd, const char *name);

/**
 * Read link information from a packet socket
 */
int _odp_link_info_fd(int fd, const char *name, odp_pktio_link_info_t *info);

#ifdef __cplusplus
}
#endif
#endif /* ODP_SOCKET_COMMON_H_ */
