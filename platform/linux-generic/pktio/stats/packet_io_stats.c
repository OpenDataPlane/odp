/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#include <odp_packet_io_stats.h>
#include <odp_ethtool_stats.h>
#include <odp_sysfs_stats.h>

#include <string.h>

static int sock_stats_get(pktio_entry_t *e, odp_pktio_stats_t *stats, int fd)
{
	int ret = 0;

	memset(stats, 0, sizeof(*stats));

	if (e->stats_type == STATS_ETHTOOL)
		ret = _odp_ethtool_stats_get_fd(fd, e->name, stats);
	else if (e->stats_type == STATS_SYSFS)
		ret = _odp_sysfs_stats(e, stats);

	if (ret)
		_ODP_ERR("Failed to get pktio statistics.\n");

	return ret;
}

int _odp_sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd)
{
	odp_pktio_stats_t cur_stats;
	int ret;

	if (pktio_entry->stats_type == STATS_UNSUPPORTED) {
		memset(&pktio_entry->stats, 0,
		       sizeof(odp_pktio_stats_t));
		return 0;
	}

	ret = sock_stats_get(pktio_entry, &cur_stats, fd);

	if (!ret)
		memcpy(&pktio_entry->stats, &cur_stats,
		       sizeof(odp_pktio_stats_t));

	return ret;
}

int _odp_sock_stats_fd(pktio_entry_t *pktio_entry,
		       odp_pktio_stats_t *stats,
		       int fd)
{
	odp_pktio_stats_t cur_stats;

	if (pktio_entry->stats_type == STATS_UNSUPPORTED) {
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

	if (sock_stats_get(pktio_entry, &cur_stats, fd))
		return -1;

	stats->in_octets = cur_stats.in_octets -
				pktio_entry->stats.in_octets;
	stats->in_packets = cur_stats.in_packets -
				pktio_entry->stats.in_packets;
	stats->in_ucast_pkts = cur_stats.in_ucast_pkts -
				pktio_entry->stats.in_ucast_pkts;
	stats->in_bcast_pkts = cur_stats.in_bcast_pkts -
				pktio_entry->stats.in_bcast_pkts;
	stats->in_mcast_pkts = cur_stats.in_mcast_pkts -
				pktio_entry->stats.in_mcast_pkts;
	stats->in_discards = cur_stats.in_discards -
				pktio_entry->stats.in_discards;
	stats->in_errors = cur_stats.in_errors -
				pktio_entry->stats.in_errors;
	stats->out_octets = cur_stats.out_octets -
				pktio_entry->stats.out_octets;
	stats->out_packets = cur_stats.out_packets -
				pktio_entry->stats.out_packets;
	stats->out_ucast_pkts = cur_stats.out_ucast_pkts -
				pktio_entry->stats.out_ucast_pkts;
	stats->out_bcast_pkts = cur_stats.out_bcast_pkts -
				pktio_entry->stats.out_bcast_pkts;
	stats->out_mcast_pkts = cur_stats.out_mcast_pkts -
				pktio_entry->stats.out_mcast_pkts;
	stats->out_discards = cur_stats.out_discards -
				pktio_entry->stats.out_discards;
	stats->out_errors = cur_stats.out_errors -
				pktio_entry->stats.out_errors;

	return 0;
}

int _odp_sock_extra_stat_info(pktio_entry_t *pktio_entry,
			      odp_pktio_extra_stat_info_t info[], int num,
			      int fd)
{
	if (pktio_entry->stats_type == STATS_UNSUPPORTED)
		return 0;

	if (pktio_entry->stats_type == STATS_ETHTOOL)
		return _odp_ethtool_extra_stat_info(fd, pktio_entry->name,
						    info, num);
	else if (pktio_entry->stats_type == STATS_SYSFS)
		return _odp_sysfs_extra_stat_info(pktio_entry, info, num);

	return 0;
}

int _odp_sock_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[], int num,
			  int fd)
{
	if (pktio_entry->stats_type == STATS_UNSUPPORTED)
		return 0;

	if (pktio_entry->stats_type == STATS_ETHTOOL)
		return _odp_ethtool_extra_stats(fd, pktio_entry->name,
						stats, num);
	else if (pktio_entry->stats_type == STATS_SYSFS)
		return _odp_sysfs_extra_stats(pktio_entry, stats, num);

	return 0;
}

int _odp_sock_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				 uint64_t *stat, int fd)
{
	if (pktio_entry->stats_type == STATS_UNSUPPORTED)
		return -1;

	if (pktio_entry->stats_type == STATS_ETHTOOL) {
		return _odp_ethtool_extra_stat_counter(fd, pktio_entry->name,
						       id, stat);
	} else if (pktio_entry->stats_type == STATS_SYSFS) {
		return _odp_sysfs_extra_stat_counter(pktio_entry, id, stat);
	}

	return 0;
}

pktio_stats_type_t _odp_sock_stats_type_fd(pktio_entry_t *pktio_entry, int fd)
{
	odp_pktio_stats_t cur_stats;

	if (!_odp_ethtool_stats_get_fd(fd, pktio_entry->name, &cur_stats))
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

	if (pktio_entry->stats_type == STATS_SYSFS) {
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
	} else if (pktio_entry->stats_type == STATS_ETHTOOL) {
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
