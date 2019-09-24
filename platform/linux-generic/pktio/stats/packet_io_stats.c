/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet_io_stats.h>
#include <odp_ethtool_stats.h>
#include <odp_sysfs_stats.h>

#include <string.h>

int sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd)
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
		(void)ethtool_stats_get_fd(fd,
					   pktio_entry->s.name,
					   &cur_stats);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		err = sysfs_stats(pktio_entry, &cur_stats);
		if (err != 0)
			ODP_ERR("stats error\n");
	}

	if (err == 0)
		memcpy(&pktio_entry->s.stats, &cur_stats,
		       sizeof(odp_pktio_stats_t));

	return err;
}

int sock_stats_fd(pktio_entry_t *pktio_entry,
		  odp_pktio_stats_t *stats,
		  int fd)
{
	odp_pktio_stats_t cur_stats;
	int ret = 0;

	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		return 0;

	memset(&cur_stats, 0, sizeof(odp_pktio_stats_t));
	if (pktio_entry->s.stats_type == STATS_ETHTOOL) {
		(void)ethtool_stats_get_fd(fd,
					   pktio_entry->s.name,
					   &cur_stats);
	} else if (pktio_entry->s.stats_type == STATS_SYSFS) {
		sysfs_stats(pktio_entry, &cur_stats);
	}

	stats->in_octets = cur_stats.in_octets -
				pktio_entry->s.stats.in_octets;
	stats->in_ucast_pkts = cur_stats.in_ucast_pkts -
				pktio_entry->s.stats.in_ucast_pkts;
	stats->in_discards = cur_stats.in_discards -
				pktio_entry->s.stats.in_discards;
	stats->in_errors = cur_stats.in_errors -
				pktio_entry->s.stats.in_errors;
	stats->in_unknown_protos = cur_stats.in_unknown_protos -
				pktio_entry->s.stats.in_unknown_protos;

	stats->out_octets = cur_stats.out_octets -
				pktio_entry->s.stats.out_octets;
	stats->out_ucast_pkts = cur_stats.out_ucast_pkts -
				pktio_entry->s.stats.out_ucast_pkts;
	stats->out_discards = cur_stats.out_discards -
				pktio_entry->s.stats.out_discards;
	stats->out_errors = cur_stats.out_errors -
				pktio_entry->s.stats.out_errors;

	return ret;
}

pktio_stats_type_t sock_stats_type_fd(pktio_entry_t *pktio_entry, int fd)
{
	odp_pktio_stats_t cur_stats;

	if (!ethtool_stats_get_fd(fd, pktio_entry->s.name, &cur_stats))
		return STATS_ETHTOOL;

	if (!sysfs_stats(pktio_entry, &cur_stats))
		return STATS_SYSFS;

	return STATS_UNSUPPORTED;
}
