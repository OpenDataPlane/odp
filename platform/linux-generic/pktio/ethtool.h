/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_ETHTOOL_H_
#define ODP_PKTIO_ETHTOOL_H_

/**
 * Get ethtool statistics of a packet socket
 */
int ethtool_stats_get_fd(int fd, const char *name, odp_pktio_stats_t *stats);

#endif /*ODP_PKTIO_ETHTOOL_H_*/
