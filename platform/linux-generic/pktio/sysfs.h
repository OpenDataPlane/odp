/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_SYSFS_H_
#define ODP_PKTIO_SYSFS_H_

/**
 * Get statistics for a pktio entry
 *
 * @param pktio_entry     Packet IO entry
 * @param stats[out]	   Output buffer for counters
 *
 * @retval 0 on success
 * @retval != 0 on failure
 */

int sysfs_stats(odp_pktio_entry_t *pktio_entry,
		odp_pktio_stats_t *stats);

#endif /* ODP_PKTIO_SYSFS_H_ */
