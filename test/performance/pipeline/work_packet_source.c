/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <stdint.h>
#include <stdlib.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"
#include "work.h"

#define CONF_STR_POOL "pool"
#define CONF_STR_LEN "len"

#define WORK_PACKET_SOURCE "packet_source"

typedef struct {
	odp_pool_t pool;
	uint32_t len;
} work_packet_source_data_t;

static int work_packet_source(uintptr_t data, odp_event_t ev[], int num, work_stats_t *stats)
{
	work_packet_source_data_t *priv = (work_packet_source_data_t *)data;
	int num_allocd = odp_packet_alloc_multi(priv->pool, priv->len, (odp_packet_t *)ev, num);

	num_allocd = num_allocd < 0 ? 0 : num_allocd;
	stats->data1 += num_allocd;

	return num_allocd;
}

static void work_packet_source_init(const work_param_t *param, work_init_t *init)
{
	work_packet_source_data_t *data = calloc(1U, sizeof(*data));
	const char *val_str;
	int val_i;

	if (data == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (param->param == NULL)
		ODPH_ABORT("No parameters available\n");

	if (config_setting_length(param->param) != 2)
		ODPH_ABORT("No valid parameters available\n");

	val_str = config_setting_get_string_elem(param->param, 0);

	if (val_str == NULL)
		ODPH_ABORT("No \"" CONF_STR_POOL "\" found\n");

	data->pool = (odp_pool_t)config_parser_get(POOL_DOMAIN, val_str);
	val_i = config_setting_get_int_elem(param->param, 1);

	if (val_i == 0)
		ODPH_ABORT("No \"" CONF_STR_LEN "\" found\n");

	data->len = val_i;
	init->fn = work_packet_source;
	init->data = (uintptr_t)data;
}

static void work_packet_source_print(const char *queue, const work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:         %s\n"
	       "  packets sent: %" PRIu64 "\n", queue, WORK_PACKET_SOURCE, stats->data1);
}

static void work_packet_source_destroy(uintptr_t data)
{
	free((void *)data);
}

WORK_AUTOREGISTER(WORK_PACKET_SOURCE, work_packet_source_init, work_packet_source_print,
		  work_packet_source_destroy)
