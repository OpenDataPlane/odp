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

#define CONF_STR_TIMER "timer"
#define CONF_STR_POOL "pool"
#define CONF_STR_TIMEOUT_NS "timeout_ns"

#define WORK_TIMEOUT_SOURCE "timeout_source"

typedef struct {
	odp_timer_pool_t tmr_pool;
	odp_pool_t tmo_pool;
	odp_queue_t queue;
	uint64_t timeout_ns;
	odp_timer_t tmr;
} work_timeout_source_data_t;

static int work_timeout_source(uintptr_t data, odp_event_t ev[] ODP_UNUSED, int num ODP_UNUSED,
			       work_stats_t *stats)
{
	work_timeout_source_data_t *priv = (work_timeout_source_data_t *)data;
	odp_timeout_t tmo;
	odp_timer_start_t start;
	int ret;

	if (priv->tmr == ODP_TIMER_INVALID) {
		priv->tmr = odp_timer_alloc(priv->tmr_pool, priv->queue, NULL);

		if (priv->tmr == ODP_TIMER_INVALID)
			ODPH_ABORT("Error allocating timer, aborting\n");
	}

	tmo = odp_timeout_alloc(priv->tmo_pool);

	if (tmo == ODP_TIMEOUT_INVALID)
		return 0;

	start.tick_type = ODP_TIMER_TICK_REL;
	start.tick = odp_timer_ns_to_tick(priv->tmr_pool, priv->timeout_ns);
	start.tmo_ev = odp_timeout_to_event(tmo);
	ret = odp_timer_start(priv->tmr, &start);

	if (ret == ODP_TIMER_FAIL)
		ODPH_ABORT("Error arming timer, aborting\n");

	if (ret == ODP_TIMER_TOO_NEAR) {
		odp_timeout_free(tmo);
		++stats->data1;
	} else if (ret == ODP_TIMER_TOO_FAR) {
		odp_timeout_free(tmo);
		++stats->data2;
	} else if (ret == ODP_TIMER_BUSY) {
		odp_timeout_free(tmo);
		++stats->data3;
	} else {
		++stats->data4;
	}

	return 0;
}

static void work_timeout_source_init(const work_param_t *param, work_init_t *init)
{
	work_timeout_source_data_t *data = calloc(1U, sizeof(*data));
	const char *val_str;
	long long val_ll;

	if (data == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (param->param == NULL)
		ODPH_ABORT("No parameters available\n");

	if (config_setting_length(param->param) != 3)
		ODPH_ABORT("No valid parameters available\n");

	val_str = config_setting_get_string_elem(param->param, 0);

	if (val_str == NULL)
		ODPH_ABORT("No \"" CONF_STR_TIMER "\" found\n");

	data->tmr_pool = (odp_timer_pool_t)config_parser_get(TIMER_DOMAIN, val_str);
	val_str = config_setting_get_string_elem(param->param, 1);

	if (val_str == NULL)
		ODPH_ABORT("No \"" CONF_STR_POOL "\" found\n");

	data->tmo_pool = (odp_pool_t)config_parser_get(POOL_DOMAIN, val_str);
	val_ll = config_setting_get_int64_elem(param->param, 2);

	if (val_ll == 0)
		ODPH_ABORT("No \"" CONF_STR_TIMEOUT_NS "\" found\n");

	data->timeout_ns = val_ll;
	init->fn = work_timeout_source;
	data->queue = (odp_queue_t)config_parser_get(QUEUE_DOMAIN, param->queue);
	data->tmr = ODP_TIMER_INVALID;
	init->data = (uintptr_t)data;
}

static void work_timeout_source_print(const char *queue, const work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:           %s\n"
	       "  timer too near: %" PRIu64 "\n"
	       "  timer too far:  %" PRIu64 "\n"
	       "  timer busy:     %" PRIu64 "\n"
	       "  timer arms:     %" PRIu64 "\n", queue, WORK_TIMEOUT_SOURCE, stats->data1,
	       stats->data2, stats->data3, stats->data4);
}

static void work_timeout_source_destroy(uintptr_t data)
{
	work_timeout_source_data_t *priv = (work_timeout_source_data_t *)data;
	odp_event_t ev;
	int ret;

	ret = odp_timer_cancel(priv->tmr, &ev);

	if (ret == ODP_TIMER_SUCCESS)
		odp_event_free(ev);

	(void)odp_timer_free(priv->tmr);
	free(priv);
}

WORK_AUTOREGISTER(WORK_TIMEOUT_SOURCE, work_timeout_source_init, work_timeout_source_print,
		  work_timeout_source_destroy)
