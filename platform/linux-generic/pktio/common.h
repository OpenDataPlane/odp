/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_COMMON_H_
#define ODP_PKTIO_COMMON_H_

#include <string.h>
#include <errno.h>

/** Determine if a socket read/write error should be reported. Transient errors
 *  that simply require the caller to retry are ignored, the _send/_recv APIs
 *  are non-blocking and it is the caller's responsibility to retry if the
 *  requested number of packets were not handled. */
#define SOCK_ERR_REPORT(e) (e != EAGAIN && e != EWOULDBLOCK && e != EINTR)

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

/**
 * Get enabled RSS hash protocols of a packet socket
 *
 * @param fd              Socket file descriptor
 * @param name            Interface name
 * @param hash_proto[out] Hash protocols
 *
 * @returns Number enabled hash protocols
 */
int rss_conf_get_fd(int fd, const char *name,
		    odp_pktin_hash_proto_t *hash_proto);

/**
 * Get supported RSS hash protocols of a packet socket
 *
 * Can be both read and modified.
 *
 * @param fd              Socket file descriptor
 * @param name            Interface name
 * @param hash_proto[out] Hash protocols
 *
 * @returns Number of supported hash protocols
 */
int rss_conf_get_supported_fd(int fd, const char *name,
			      odp_pktin_hash_proto_t *hash_proto);

/**
 * Set RSS hash protocols of a packet socket
 *
 * @param fd              Socket file descriptor
 * @param name            Interface name
 * @param hash_proto      Hash protocols
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int rss_conf_set_fd(int fd, const char *name,
		    const odp_pktin_hash_proto_t *proto);

/**
 * Print enabled RSS hash protocols
 *
 * @param hash_proto      Hash protocols
 */
void rss_conf_print(const odp_pktin_hash_proto_t *hash_proto);

/**
 * Get statistics for pktio entry
 *
 * @param pktio_entry     Packet IO entry
 * @param stats[out]	   Output buffer for counters
 * @param fd              Socket file descriptor
 *
 * @retval 0 on success
 * @retval != 0 on failure
 */
int sock_stats_fd(pktio_entry_t *pktio_entry,
		  odp_pktio_stats_t *stats,
		  int fd);

/**
 * Reset statistics for pktio entry
 *
 * @param pktio_entry     Packet IO entry
 * @param fd              Socket file descriptor
 *
 * @retval  0 on success
 * @retval != 0 on failure
 */
int sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd);

#endif /*ODP_PKTIO_COMMON_H_*/
