/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_ETHTOOL_H_
#define ODP_PKTIO_ETHTOOL_H_

#include <linux/ethtool.h>

/**
 * Get statistics for a network interface
 *
 * @param fd		Arbitrary socket file descriptor
 * @param netif_name    Network interface name
 * @param stats[out]    Output buffer for counters
 *
 * @retval 0 on success
 * @retval != 0 on failure
 */
int ethtool_stats_get_fd(int fd, const char *netif_name,
			 odp_pktio_stats_t *stats);

/**
 * Get RX/TX queue parameters for a network interface
 *
 * @param fd		Arbitrary socket file descriptor
 * @param netif_name	Network interface name
 * @param param[out]	Output buffer for parameters
 *
 * @retval 0 on success
 * @retval != 0 on failure
 */
int ethtool_ringparam_get_fd(int fd, const char *netif_name,
			     struct ethtool_ringparam *param);

#endif /*ODP_PKTIO_ETHTOOL_H_*/
