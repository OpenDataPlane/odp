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

#define CONF_STR_QS "output_queues"

#define WORK_GLOBAL_FORWARD "global_forward"

typedef struct {
	uint32_t num;
	odp_queue_t *out;
} work_global_forward_data_t;

static work_global_forward_data_t common;

static int work_global_forward(uintptr_t data, odp_event_t ev[], int num, work_stats_t *stats)
{
	work_global_forward_data_t *priv = (work_global_forward_data_t *)data;
	int ret;

	ret = odp_queue_enq_multi((odp_queue_t)priv->out[(odp_thread_id() - 1) % priv->num], ev,
				  num);
	ret = ret < 0 ? 0 : ret;
	stats->data1 += ret;

	return ret;
}

static void work_global_forward_init(const work_param_t *param, work_init_t *init)
{
	const char *val_str;
	config_setting_t *elem;
	int num;

	if (param->param == NULL)
		ODPH_ABORT("No parameters available\n");

	if (common.out == NULL) {
		if (config_setting_length(param->param) != 1)
			ODPH_ABORT("No valid parameters available\n");

		elem = config_setting_get_elem(param->param, 0);

		if (elem == NULL)
			ODPH_ABORT("No \"" CONF_STR_QS "\" found\n");

		num = config_setting_length(elem);

		if (num == 0)
			ODPH_ABORT("No valid \"" CONF_STR_QS "\" found\n");

		common.out = calloc(1U, num * sizeof(*common.out));

		if (common.out == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		for (int i = 0; i < num; ++i) {
			val_str = config_setting_get_string_elem(elem, i);
			common.out[i] = (odp_queue_t)config_parser_get(QUEUE_DOMAIN, val_str);
		}

		common.num = num;
	}

	init->fn = work_global_forward;
	init->data = (uintptr_t)&common;
}

static void work_global_forward_print(const char *queue, const work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:      %s\n"
	       "  forwarded: %" PRIu64 "\n", queue, WORK_GLOBAL_FORWARD, stats->data1);
}

static void work_global_forward_destroy(uintptr_t data ODP_UNUSED)
{
	if (common.out == NULL)
		return;

	free(common.out);
	common.out = NULL;
}

WORK_AUTOREGISTER(WORK_GLOBAL_FORWARD, work_global_forward_init, work_global_forward_print,
		  work_global_forward_destroy)
