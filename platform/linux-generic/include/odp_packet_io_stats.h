/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_IO_STATS_H_
#define ODP_PACKET_IO_STATS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/packet_io.h>
#include <odp/api/packet_io_stats.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_stats_common.h>

int sock_stats_fd(pktio_entry_t *pktio_entry,
		  odp_pktio_stats_t *stats,
		  int fd);
int sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd);

pktio_stats_type_t sock_stats_type_fd(pktio_entry_t *pktio_entry, int fd);

#ifdef __cplusplus
}
#endif
#endif /* ODP_PACKET_IO_STATS_H_ */
