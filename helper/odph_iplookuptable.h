/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:    BSD-3-Clause
 */

/**
 * @file
 *
 * ODP IP Lookup Table
 *
 * This is an implementation of the IP lookup table. The key of
 * this table is IPv4 address (32 bits), and the value can be
 * defined by user. This table uses the 16,8,8 ip lookup (longest
 * prefix matching) algorithm.
 */

#ifndef ODPH_IPLOOKUP_TABLE_H_
#define ODPH_IPLOOKUP_TABLE_H_

#include <odp/helper/table.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t ip;
	uint8_t cidr;
} odph_iplookup_prefix_t;

odph_table_t odph_iplookup_table_create(
		const char *name,
		uint32_t ODP_IGNORED_1,
		uint32_t ODP_IGNORED_2,
		uint32_t value_size);

odph_table_t odph_iplookup_table_lookup(const char *name);

int odph_iplookup_table_destroy(odph_table_t table);

int odph_iplookup_table_put_value(
		odph_table_t table, void *key, void *value);

int odph_iplookup_table_get_value(
		odph_table_t table, void *key,
		void *buffer, uint32_t buffer_size);

int odph_iplookup_table_remove_value(
		odph_table_t table, void *key);

extern odph_table_ops_t odph_iplookup_table_ops;

#ifdef __cplusplus
}
#endif

#endif /* ODPH_IPLOOKUP_TABLE_H_ */
