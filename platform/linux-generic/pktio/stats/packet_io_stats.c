/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/deprecated.h>
#include <odp_packet_io_stats.h>
#include <odp_ethtool_stats.h>
#include <odp_sysfs_stats.h>

#include <string.h>

int _odp_sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd)
{
	int err = 0;
	odp_pktio_stats_t cur_stats;

	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(&pktio_entry->s.stats, 0,
		       sizeof(odp_pktio_stats_t));
		return 0;
	}

	memset(&cur_stats, 0, sizeof(odp_pktio_stats_t));

	if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		(void)_odp_ethtool_stats_get_fd(fd,
						pktio_entry->s.name,
						&cur_stats);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		err = _odp_sysfs_stats(pktio_entry, &cur_stats);
		if (err != 0)
			ODP_ERR("stats error\n");
	}

	if (err == 0)
		memcpy(&pktio_entry->s.stats, &cur_stats,
		       sizeof(odp_pktio_stats_t));

	return err;
}

int _odp_sock_stats_fd(pktio_entry_t *pktio_entry,
		       odp_pktio_stats_t *stats,
		       int fd)
{
	odp_pktio_stats_t cur_stats;
	int ret = 0;

	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

	memset(&cur_stats, 0, sizeof(odp_pktio_stats_t));
	if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		(void)_odp_ethtool_stats_get_fd(fd,
						pktio_entry->s.name,
						&cur_stats);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		_odp_sysfs_stats(pktio_entry, &cur_stats);
	}

	stats->in_octets = cur_stats.in_octets -
				pktio_entry->s.stats.in_octets;
	stats->in_packets = cur_stats.in_packets -
				pktio_entry->s.stats.in_packets;
	stats->in_ucast_pkts = cur_stats.in_ucast_pkts -
				pktio_entry->s.stats.in_ucast_pkts;
	stats->in_bcast_pkts = cur_stats.in_bcast_pkts -
				pktio_entry->s.stats.in_bcast_pkts;
	stats->in_mcast_pkts = cur_stats.in_mcast_pkts -
				pktio_entry->s.stats.in_mcast_pkts;
	stats->in_discards = cur_stats.in_discards -
				pktio_entry->s.stats.in_discards;
	stats->in_errors = cur_stats.in_errors -
				pktio_entry->s.stats.in_errors;
#if ODP_DEPRECATED_API
	stats->in_unknown_protos = cur_stats.in_unknown_protos -
				pktio_entry->s.stats.in_unknown_protos;
#endif
	stats->out_octets = cur_stats.out_octets -
				pktio_entry->s.stats.out_octets;
	stats->out_packets = cur_stats.out_packets -
				pktio_entry->s.stats.out_packets;
	stats->out_ucast_pkts = cur_stats.out_ucast_pkts -
				pktio_entry->s.stats.out_ucast_pkts;
	stats->out_bcast_pkts = cur_stats.out_bcast_pkts -
				pktio_entry->s.stats.out_bcast_pkts;
	stats->out_mcast_pkts = cur_stats.out_mcast_pkts -
				pktio_entry->s.stats.out_mcast_pkts;
	stats->out_discards = cur_stats.out_discards -
				pktio_entry->s.stats.out_discards;
	stats->out_errors = cur_stats.out_errors -
				pktio_entry->s.stats.out_errors;

	return ret;
}

int _odp_sock_extra_stat_info(pktio_entry_t *pktio_entry,
			      odp_pktio_extra_stat_info_t info[], int num,
			      int fd)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		return 0;

	if (pktio_entry->s.stats_type == STATS_ETHTOOL)
		return _odp_ethtool_extra_stat_info(fd, pktio_entry->s.name,
						    info, num);
	else if (pktio_entry->s.stats_type == STATS_SYSFS)
		return _odp_sysfs_extra_stat_info(pktio_entry, info, num);

	return 0;
}

int _odp_sock_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[], int num,
			  int fd)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		return 0;

	if (pktio_entry->s.stats_type == STATS_ETHTOOL)
		return _odp_ethtool_extra_stats(fd, pktio_entry->s.name,
						stats, num);
	else if (pktio_entry->s.stats_type == STATS_SYSFS)
		return _odp_sysfs_extra_stats(pktio_entry, stats, num);

	return 0;
}

int _odp_sock_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				 uint64_t *stat, int fd)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		return -1;

	if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		return _odp_ethtool_extra_stat_counter(fd, pktio_entry->s.name,
						       id, stat);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		return _odp_sysfs_extra_stat_counter(pktio_entry, id, stat);
	}

	return 0;
}

pktio_stats_type_t _odp_sock_stats_type_fd(pktio_entry_t *pktio_entry, int fd)
{
	odp_pktio_stats_t cur_stats;

	if (!_odp_ethtool_stats_get_fd(fd, pktio_entry->s.name, &cur_stats))
		return STATS_ETHTOOL;

	if (!_odp_sysfs_stats(pktio_entry, &cur_stats))
		return STATS_SYSFS;

	return STATS_UNSUPPORTED;
}

void _odp_sock_stats_capa(pktio_entry_t *pktio_entry,
			  odp_pktio_capability_t *capa)
{
	capa->stats.pktio.all_counters = 0;
	capa->stats.pktin_queue.all_counters = 0;
	capa->stats.pktout_queue.all_counters = 0;

	if (pktio_entry->s.stats_type == STATS_SYSFS) {
		capa->stats.pktio.counter.in_octets = 1;
		capa->stats.pktio.counter.in_packets = 1;
		capa->stats.pktio.counter.in_ucast_pkts = 1;
		capa->stats.pktio.counter.in_mcast_pkts = 1;
		capa->stats.pktio.counter.in_discards = 1;
		capa->stats.pktio.counter.in_errors = 1;
		capa->stats.pktio.counter.out_octets = 1;
		capa->stats.pktio.counter.out_packets = 1;
		capa->stats.pktio.counter.out_ucast_pkts = 1;
		capa->stats.pktio.counter.out_discards = 1;
		capa->stats.pktio.counter.out_errors = 1;
	} else if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		capa->stats.pktio.counter.in_octets = 1;
		capa->stats.pktio.counter.in_packets = 1;
		capa->stats.pktio.counter.in_ucast_pkts = 1;
		capa->stats.pktio.counter.in_bcast_pkts = 1;
		capa->stats.pktio.counter.in_mcast_pkts = 1;
		capa->stats.pktio.counter.in_discards = 1;
		capa->stats.pktio.counter.in_errors = 1;
		capa->stats.pktio.counter.out_octets = 1;
		capa->stats.pktio.counter.out_packets = 1;
		capa->stats.pktio.counter.out_ucast_pkts = 1;
		capa->stats.pktio.counter.out_bcast_pkts = 1;
		capa->stats.pktio.counter.out_mcast_pkts = 1;
		capa->stats.pktio.counter.out_discards = 1;
		capa->stats.pktio.counter.out_errors = 1;
	}
}
