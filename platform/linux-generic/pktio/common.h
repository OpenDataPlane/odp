/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_COMMON_H_
#define ODP_PKTIO_COMMON_H_

/**
 * Read the MTU from a packet socket
 */
uint32_t mtu_get_fd(int fd, const char *name);

/**
 * Read the MAC address from a packet socket
 */
int mac_addr_get_fd(int fd, const char *name, unsigned char mac_dst[]);

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

#endif /*ODP_PKTIO_COMMON_H_*/
