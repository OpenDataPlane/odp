/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_ETHTOOL_RSS_H_
#define ODP_ETHTOOL_RSS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet_io.h>

/**
 * Get enabled RSS hash protocols of a packet socket
 *
 * @param fd              Socket file descriptor
 * @param name            Interface name
 * @param hash_proto[out] Hash protocols
 *
 * @returns Number enabled hash protocols
 */
int _odp_rss_conf_get_fd(int fd, const char *name,
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
int _odp_rss_conf_get_supported_fd(int fd, const char *name,
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
int _odp_rss_conf_set_fd(int fd, const char *name,
			 const odp_pktin_hash_proto_t *proto);

/**
 * Print enabled RSS hash protocols
 *
 * @param hash_proto      Hash protocols
 */
void _odp_rss_conf_print(const odp_pktin_hash_proto_t *hash_proto);

#ifdef __cplusplus
}
#endif
#endif /* ODP_ETHTOOL_RSS_H_ */
