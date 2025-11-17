/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"
#include "work.h"

#define CONF_STR_POOL "pool"

#define WORK_PACKET_COPY "packet_copy"

static int work_packet_copy(uintptr_t data, odp_event_t ev[], int num, work_stats_t *stats)
{
	odp_pool_t pool = (odp_pool_t)data;
	odp_packet_t dst, src;

	if (odp_unlikely(odp_event_type(ev[0]) != ODP_EVENT_PACKET))
		return 0;

	for (int i = 0; i < num; ++i) {
		src = odp_packet_from_event(ev[i]);
		dst = odp_packet_copy(src, pool);

		if (odp_unlikely(dst == ODP_PACKET_INVALID))
			continue;

		ev[i] = odp_packet_to_event(dst);
		odp_packet_free(src);
		++stats->data1;
	}

	return 0;
}

static void work_packet_copy_init(const work_param_t *param, work_init_t *init)
{
	const char *val_str;

	if (param->param == NULL)
		ODPH_ABORT("No parameters available\n");

	if (config_setting_length(param->param) != 1)
		ODPH_ABORT("No valid parameters available\n");

	val_str = config_setting_get_string_elem(param->param, 0);

	if (val_str == NULL)
		ODPH_ABORT("No \"" CONF_STR_POOL "\" found\n");

	init->fn = work_packet_copy;
	init->data = config_parser_get(POOL_DOMAIN, val_str);
}

static void work_packet_copy_print(const char *queue, const work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:   %s\n"
	       "  copied: %" PRIu64 "\n", queue, WORK_PACKET_COPY, stats->data1);
}

static void work_packet_copy_destroy(uintptr_t data ODP_UNUSED)
{
}

WORK_AUTOREGISTER(WORK_PACKET_COPY, work_packet_copy_init, work_packet_copy_print,
		  work_packet_copy_destroy)
