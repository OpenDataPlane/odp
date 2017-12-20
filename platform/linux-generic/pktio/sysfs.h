/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_SYSFS_H_
#define ODP_PKTIO_SYSFS_H_

/**
 * Read an attribute from /sysfs as raw string
 *
 * @param buf[out]	Attribute value
 * @param buf_size	Maximum number of bytes to read (including '\0')
 * @param fmt		printf-like path to the attribute
 *
 * @retval 0 on success, buf[] is guaranteed to be '\0'-terminated
 * @retval != 0 on failure
 */
ODP_PRINTF_FORMAT(3, 4)
int sysfs_attr_raw_get(char *buf, size_t buf_size, const char *fmt, ...);

/**
 * Read an attribute from /sysfs as uint64_t
 *
 * @param value[out]	Attribute value
 * @param fmt		printf-like path to the attribute
 *
 * @retval 0 on success
 * @retval != 0 on failure
 */
ODP_PRINTF_FORMAT(2, 3)
int sysfs_attr_u64_get(uint64_t *value, const char *fmt, ...);

/**
 * Get statistics for a network interface
 *
 * @param netif_name	Network interface name
 * @param stats[out]	Output buffer for counters
 *
 * @retval 0 on success
 * @retval != 0 on failure
 */
int sysfs_netif_stats(const char *netif_name, odp_pktio_stats_t *stats);

#endif /* ODP_PKTIO_SYSFS_H_ */
