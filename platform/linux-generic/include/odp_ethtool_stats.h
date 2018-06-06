/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ETHTOOL_H_
#define ODP_ETHTOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <odp/api/packet_io_stats.h>

/**
 * Get ethtool statistics of a packet socket
 */
int ethtool_stats_get_fd(int fd, const char *name, odp_pktio_stats_t *stats);

#ifdef __cplusplus
}
#endif
#endif /* ODP_ETHTOOL_H_ */
