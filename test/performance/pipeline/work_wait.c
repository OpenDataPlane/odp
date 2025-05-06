/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"
#include "work.h"

#define CONF_STR_WAIT_NS "wait_ns"

#define WORK_WAIT "wait"

static int work_wait(uintptr_t data, odp_event_t ev[] ODP_UNUSED, int num ODP_UNUSED,
		     work_stats_t *stats)
{
	odp_time_wait_ns((uint64_t)data);
	stats->data1 = (uint64_t)data;

	return 0;
}

static void work_wait_init(const work_param_t *param, work_init_t *init)
{
	long long val_ll;

	if (param->param == NULL)
		ODPH_ABORT("No parameters available\n");

	if (config_setting_length(param->param) != 1)
		ODPH_ABORT("No valid parameters available\n");

	val_ll = config_setting_get_int64_elem(param->param, 0);

	if (val_ll == -1)
		ODPH_ABORT("No \"" CONF_STR_WAIT_NS "\" found\n");

	init->fn = work_wait;
	init->data = (uintptr_t)val_ll;
}

static void work_wait_print(const char *queue, const work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:        %s\n"
	       "  time waited: %" PRIu64 "\n", queue, WORK_WAIT, stats->data1);
}

static void work_wait_destroy(uintptr_t data ODP_UNUSED)
{
}

WORK_AUTOREGISTER(WORK_WAIT, work_wait_init, work_wait_print, work_wait_destroy)
