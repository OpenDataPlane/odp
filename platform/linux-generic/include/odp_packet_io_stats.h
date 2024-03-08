/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
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

int _odp_sock_stats_fd(pktio_entry_t *pktio_entry,
		       odp_pktio_stats_t *stats,
		       int fd);
int _odp_sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd);

void _odp_sock_stats_capa(pktio_entry_t *pktio_entry,
			  odp_pktio_capability_t *capa);

int _odp_sock_extra_stat_info(pktio_entry_t *pktio_entry,
			      odp_pktio_extra_stat_info_t info[], int num,
			      int fd);
int _odp_sock_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[], int num,
			  int fd);
int _odp_sock_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				 uint64_t *stat, int fd);

pktio_stats_type_t _odp_sock_stats_type_fd(pktio_entry_t *pktio_entry, int fd);

#ifdef __cplusplus
}
#endif
#endif /* ODP_PACKET_IO_STATS_H_ */
