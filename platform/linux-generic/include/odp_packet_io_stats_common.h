/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_PACKET_IO_STATS_COMMON_H_
#define ODP_PACKET_IO_STATS_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	STATS_SYSFS = 0,
	STATS_ETHTOOL,
	STATS_UNSUPPORTED
} pktio_stats_type_t;

#ifdef __cplusplus
}
#endif
#endif /* ODP_PACKET_IO_STATS_COMMON_H_ */
