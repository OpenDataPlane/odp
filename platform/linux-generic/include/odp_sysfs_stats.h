/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_SYSFS_STATS_H_
#define ODP_SYSFS_STATS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet_io_stats.h>
#include <odp_packet_io_internal.h>

int _odp_sysfs_stats(pktio_entry_t *pktio_entry,
		     odp_pktio_stats_t *stats);

int _odp_sysfs_extra_stat_info(pktio_entry_t *pktio_entry,
			       odp_pktio_extra_stat_info_t info[], int num);
int _odp_sysfs_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[],
			   int num);
int _odp_sysfs_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				  uint64_t *stat);

#ifdef __cplusplus
}
#endif
#endif /* ODP_SYSFS_STATS_H_ */
