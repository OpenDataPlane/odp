/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SOCKET_COMMON_H_
#define ODP_SOCKET_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <linux/if_ether.h>

static inline void
ethaddr_copy(unsigned char mac_dst[], unsigned char mac_src[])
{
	memcpy(mac_dst, mac_src, ETH_ALEN);
}

static inline int
ethaddrs_equal(unsigned char mac_a[], unsigned char mac_b[])
{
	return !memcmp(mac_a, mac_b, ETH_ALEN);
}

/**
 * Read the MAC address from a packet socket
 */
int mac_addr_get_fd(int fd, const char *name, unsigned char mac_dst[]);

/**
 * Read the MTU from a packet socket
 */
uint32_t mtu_get_fd(int fd, const char *name);

/**
 * Set a packet socket MTU
 */
int mtu_set_fd(int fd, const char *name, int mtu);

/**
 * Enable/Disable promisc mode for a packet socket
 */
int promisc_mode_set_fd(int fd, const char *name, int enable);

/**
 * Return promisc mode of a packet socket
 */
int promisc_mode_get_fd(int fd, const char *name);

/**
 * Return link status of a packet socket (up/down)
 */
int link_status_fd(int fd, const char *name);

#ifdef __cplusplus
}
#endif
#endif /* ODP_SOCKET_COMMON_H_ */
