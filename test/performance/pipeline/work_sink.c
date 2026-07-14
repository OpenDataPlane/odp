/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <odp_api.h>

#include "common.h"
#include "work.h"

#define WORK_SINK "sink"

static int work_sink(uintptr_t data ODP_UNUSED, odp_event_t ev[], int num,
		     odp_pl_work_stats_t *stats)
{
	odp_event_free_multi(ev, num);
	stats->data1 += num;

	return num;
}

static void work_sink_init(const odp_pl_work_param_t *param ODP_UNUSED, odp_pl_work_init_t *init)
{
	init->fn = work_sink;
}

static void work_sink_print(const char *queue, const odp_pl_work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:         %s\n"
	       "  events freed: %" PRIu64 "\n", queue, WORK_SINK, stats->data1);
}

static void work_sink_destroy(uintptr_t data ODP_UNUSED)
{
}

ODP_PL_WORK_AUTOREGISTER(WORK_SINK, work_sink_init, work_sink_print, work_sink_destroy)
