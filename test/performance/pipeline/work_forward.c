/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"
#include "work.h"

#define CONF_STR_OUTPUT "output"

#define WORK_FORWARD "forward"

static int work_forward(uintptr_t data, odp_event_t ev[], int num, work_stats_t *stats)
{
	int ret;

	ret = odp_queue_enq_multi((odp_queue_t)data, ev, num);
	ret = ret < 0 ? 0 : ret;
	stats->data1 += ret;

	return ret;
}

static void work_forward_init(const work_param_t *param, work_init_t *init)
{
	const char *val_str;

	if (param->param == NULL)
		ODPH_ABORT("No parameters available\n");

	if (config_setting_length(param->param) != 1)
		ODPH_ABORT("No valid parameters available\n");

	val_str = config_setting_get_string_elem(param->param, 0);

	if (val_str == NULL)
		ODPH_ABORT("No \"" CONF_STR_OUTPUT "\" found\n");

	init->fn = work_forward;
	init->data = config_parser_get(QUEUE_DOMAIN, val_str);
}

static void work_forward_print(const char *queue, const work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:             %s\n"
	       "  events forwarded: %" PRIu64 "\n", queue, WORK_FORWARD, stats->data1);
}

static void work_forward_destroy(uintptr_t data ODP_UNUSED)
{
}

WORK_AUTOREGISTER(WORK_FORWARD, work_forward_init, work_forward_print, work_forward_destroy)
