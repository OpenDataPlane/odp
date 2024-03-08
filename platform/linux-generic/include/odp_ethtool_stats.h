/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
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
int _odp_ethtool_stats_get_fd(int fd, const char *name, odp_pktio_stats_t *stats);

int _odp_ethtool_extra_stat_info(int fd, const char *name, odp_pktio_extra_stat_info_t info[],
				 int num);
int _odp_ethtool_extra_stats(int fd, const char *name, uint64_t stats[], int num);
int _odp_ethtool_extra_stat_counter(int fd, const char *name, uint32_t id, uint64_t *stat);

#ifdef __cplusplus
}
#endif
#endif /* ODP_ETHTOOL_H_ */
