/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SYSFS_STATS_H_
#define ODP_SYSFS_STATS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet_io_stats.h>
#include <odp_packet_io_internal.h>

int sysfs_stats(pktio_entry_t *pktio_entry,
		odp_pktio_stats_t *stats);

#ifdef __cplusplus
}
#endif
#endif /* ODP_SYSFS_STATS_H_ */
