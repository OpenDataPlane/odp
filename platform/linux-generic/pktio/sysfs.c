/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <odp_errno_define.h>
#include <pktio/sysfs.h>

#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

ODP_PRINTF_FORMAT(3, 0)
static int _sysfs_attr_raw_get(char *buf, size_t buf_size, const char *fmt,
			       va_list args)
{
	char path[256];
	FILE *file;
	int ret;

	ret = vsnprintf(path, sizeof(path), fmt, args);

	if (ret < 0) {
		__odp_errno = errno;
		return -1;
	}

	if (ret >= (ssize_t)sizeof(path)) {
		__odp_errno = EINVAL;
		return -1;
	}

	file = fopen(path, "rt");
	if (file == NULL) {
		__odp_errno = errno;
		return -1;
	}

	buf = fgets(buf, buf_size, file);
	(void)fclose(file);

	if (buf == NULL) {
		__odp_errno = errno;
		return -1;
	}

	return 0;
}

ODP_PRINTF_FORMAT(3, 4)
int sysfs_attr_raw_get(char *buf, size_t buf_size, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = _sysfs_attr_raw_get(buf, buf_size, fmt, args);
	va_end(args);

	return ret;
}

ODP_PRINTF_FORMAT(2, 3)
int sysfs_attr_u64_get(uint64_t *value, const char *fmt, ...)
{
	char buf[20 + 1 + 1]; /* 20 digits (UINT64_MAX) + '\n' + '\0' */
	va_list args;
	char *endptr;
	int ret;

	va_start(args, fmt);
	ret = _sysfs_attr_raw_get(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (ret < 0)
		return -1;

	if (buf[0] == '\0') {
		__odp_errno = EINVAL;
		return -1;
	}

	*value = strtoull(buf, &endptr, 0);

	/* It is OK to have '\n' in sysfs */
	if (*endptr == '\n')
		endptr++;

	if (*endptr != '\0') {
		__odp_errno = EINVAL;
		return -1;
	}

	return 0;
}

int sysfs_netif_stats(const char *netif_name, odp_pktio_stats_t *stats)
{
	int ret;

	/*
	 * Do not print debug err if sysfs is not supported by
	 * kernel driver.
	 */

	ret = sysfs_attr_u64_get(&stats->in_octets,
				 "/sys/class/net/%s/statistics/rx_bytes",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	ret = sysfs_attr_u64_get(&stats->in_ucast_pkts,
				 "/sys/class/net/%s/statistics/rx_packets",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	ret = sysfs_attr_u64_get(&stats->in_discards,
				 "/sys/class/net/%s/statistics/rx_droppped",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	ret = sysfs_attr_u64_get(&stats->in_errors,
				 "/sys/class/net/%s/statistics/rx_errors",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	/* stats->in_unknown_protos is not supported in sysfs */

	ret = sysfs_attr_u64_get(&stats->out_octets,
				 "/sys/class/net/%s/statistics/tx_bytes",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	ret = sysfs_attr_u64_get(&stats->out_ucast_pkts,
				 "/sys/class/net/%s/statistics/tx_packets",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	ret = sysfs_attr_u64_get(&stats->out_discards,
				 "/sys/class/net/%s/statistics/tx_dropped",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	ret = sysfs_attr_u64_get(&stats->out_errors,
				 "/sys/class/net/%s/statistics/tx_errors",
				 netif_name);
	if (ret < 0 && __odp_errno != ENOENT)
		return -1;

	return 0;
}
