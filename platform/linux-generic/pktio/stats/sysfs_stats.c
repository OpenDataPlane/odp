/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet_io_stats.h>

#include <odp_debug_internal.h>
#include <odp_sysfs_stats.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <linux/limits.h>

#define SYSFS_DIR "/sys/class/net/%s/statistics"

static int sysfs_get_val(const char *fname, uint64_t *val)
{
	FILE  *file;
	char str[128];
	int ret = -1;

	file = fopen(fname, "rt");
	if (file == NULL) {
		/* do not print debug err if sysfs is not supported by
		 * kernel driver.
		 */
		if (errno != ENOENT)
			_ODP_ERR("fopen %s: %s\n", fname, strerror(errno));
		return 0;
	}

	if (fgets(str, sizeof(str), file) != NULL)
		ret = sscanf(str, "%" SCNx64, val);

	(void)fclose(file);

	if (ret != 1) {
		_ODP_ERR("read %s\n", fname);
		return -1;
	}

	return 0;
}

int _odp_sysfs_stats(pktio_entry_t *pktio_entry,
		     odp_pktio_stats_t *stats)
{
	char fname[256];
	const char *dev = pktio_entry->name;
	int ret = 0;

	sprintf(fname, "/sys/class/net/%s/statistics/rx_bytes", dev);
	ret -= sysfs_get_val(fname, &stats->in_octets);

	sprintf(fname, "/sys/class/net/%s/statistics/rx_packets", dev);
	ret -= sysfs_get_val(fname, &stats->in_packets);

	sprintf(fname, "/sys/class/net/%s/statistics/rx_packets", dev);
	ret -= sysfs_get_val(fname, &stats->in_ucast_pkts);

	sprintf(fname, "/sys/class/net/%s/statistics/multicast", dev);
	ret -= sysfs_get_val(fname, &stats->in_mcast_pkts);

	sprintf(fname, "/sys/class/net/%s/statistics/rx_dropped", dev);
	ret -= sysfs_get_val(fname, &stats->in_discards);

	sprintf(fname, "/sys/class/net/%s/statistics/rx_errors", dev);
	ret -= sysfs_get_val(fname, &stats->in_errors);

	sprintf(fname, "/sys/class/net/%s/statistics/tx_bytes", dev);
	ret -= sysfs_get_val(fname, &stats->out_octets);

	sprintf(fname, "/sys/class/net/%s/statistics/tx_packets", dev);
	ret -= sysfs_get_val(fname, &stats->out_packets);

	sprintf(fname, "/sys/class/net/%s/statistics/tx_packets", dev);
	ret -= sysfs_get_val(fname, &stats->out_ucast_pkts);

	sprintf(fname, "/sys/class/net/%s/statistics/tx_dropped", dev);
	ret -= sysfs_get_val(fname, &stats->out_discards);

	sprintf(fname, "/sys/class/net/%s/statistics/tx_errors", dev);
	ret -= sysfs_get_val(fname, &stats->out_errors);

	return ret;
}

int _odp_sysfs_extra_stat_info(pktio_entry_t *pktio_entry,
			       odp_pktio_extra_stat_info_t info[], int num)
{
	struct dirent *e;
	DIR *dir;
	char sysfs_dir[PATH_MAX];
	int counters = 0;

	snprintf(sysfs_dir, PATH_MAX, SYSFS_DIR, pktio_entry->name);
	dir = opendir(sysfs_dir);
	if (!dir) {
		_ODP_ERR("Failed to open sysfs dir: %s\n", sysfs_dir);
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strncmp(e->d_name, ".", 1) == 0)
			continue;

		if (info && counters < num)
			snprintf(info[counters].name,
				 ODP_PKTIO_STATS_EXTRA_NAME_LEN, "%s",
				 e->d_name);
		counters++;
	}
	(void)closedir(dir);

	return counters;
}

int _odp_sysfs_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[],
			   int num)
{
	struct dirent *e;
	DIR *dir;
	char sysfs_dir[PATH_MAX];
	char file_path[PATH_MAX];
	int counters = 0;

	snprintf(sysfs_dir, PATH_MAX, SYSFS_DIR, pktio_entry->name);
	dir = opendir(sysfs_dir);
	if (!dir) {
		_ODP_ERR("Failed to open dir: %s\n", sysfs_dir);
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		uint64_t val;

		/* Skip . and .. */
		if (strncmp(e->d_name, ".", 1) == 0)
			continue;

		snprintf(file_path, PATH_MAX, "%s/%s", sysfs_dir, e->d_name);
		if (sysfs_get_val(file_path, &val)) {
			_ODP_ERR("Failed to read file: %s/n", file_path);
			counters = -1;
			break;
		}

		if (stats && counters < num)
			stats[counters] = val;

		counters++;
	}
	(void)closedir(dir);

	return counters;
}

int _odp_sysfs_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				  uint64_t *stat)
{
	struct dirent *e;
	DIR *dir;
	char sysfs_dir[PATH_MAX];
	char file_path[PATH_MAX];
	uint32_t counters = 0;
	int ret = -1;

	snprintf(sysfs_dir, PATH_MAX, SYSFS_DIR, pktio_entry->name);
	dir = opendir(sysfs_dir);
	if (!dir) {
		_ODP_ERR("Failed to open dir: %s\n", sysfs_dir);
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		/* Skip . and .. */
		if (strncmp(e->d_name, ".", 1) == 0)
			continue;

		if (counters == id) {
			uint64_t val;

			snprintf(file_path, PATH_MAX, "%s/%s",
				 sysfs_dir, e->d_name);
			if (sysfs_get_val(file_path, &val)) {
				_ODP_ERR("Failed to read file: %s/n", file_path);
			} else {
				*stat = val;
				ret = 0;
			}
			break;
		}
		counters++;
	}
	(void)closedir(dir);

	return ret;
}
