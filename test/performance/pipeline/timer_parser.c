/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libconfig.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"

#define CONF_STR_NAME "name"
#define CONF_STR_CLK_SRC "clk_src"
#define CONF_STR_RES_NS "res_ns"
#define CONF_STR_RES_HZ "res_hz"
#define CONF_STR_MIN_TMO "min_tmo"
#define CONF_STR_MAX_TMO "max_tmo"
#define CONF_STR_NUM "num"

#define SRC0 "src0"
#define SRC1 "src1"
#define SRC2 "src2"
#define SRC3 "src3"
#define SRC4 "src4"
#define SRC5 "src5"

typedef struct {
	char *name;
	odp_timer_pool_param_t param;
	odp_timer_pool_t tmr_pool;
} timer_parse_t;

typedef struct {
	timer_parse_t *timers;
	uint32_t num;
} timer_parses_t;

static timer_parses_t timers;

static odp_bool_t parse_timer_entry(config_setting_t *cs, timer_parse_t *timer)
{
	const char *val_str;
	int val_i;
	long long val_ll;

	timer->tmr_pool = ODP_TIMER_POOL_INVALID;
	odp_timer_pool_param_init(&timer->param);
	timer->param.timer_type = ODP_TIMER_TYPE_SINGLE;

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	timer->name = strdup(val_str);

	if (timer->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_CLK_SRC, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, SRC0) == 0) {
			timer->param.clk_src = ODP_CLOCK_SRC_0;
		} else if (strcmp(val_str, SRC1) == 0) {
			timer->param.clk_src = ODP_CLOCK_SRC_1;
		} else if (strcmp(val_str, SRC2) == 0) {
			timer->param.clk_src = ODP_CLOCK_SRC_2;
		} else if (strcmp(val_str, SRC3) == 0) {
			timer->param.clk_src = ODP_CLOCK_SRC_3;
		} else if (strcmp(val_str, SRC4) == 0) {
			timer->param.clk_src = ODP_CLOCK_SRC_4;
		} else if (strcmp(val_str, SRC5) == 0) {
			timer->param.clk_src = ODP_CLOCK_SRC_5;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_CLK_SRC "\" found\n");
			return false;
		}
	}

	if (config_setting_lookup_int64(cs, CONF_STR_RES_NS, &val_ll) == CONFIG_TRUE)
		timer->param.res_ns = val_ll;

	if (config_setting_lookup_int64(cs, CONF_STR_RES_HZ, &val_ll) == CONFIG_TRUE)
		timer->param.res_hz = val_ll;

	if (config_setting_lookup_int64(cs, CONF_STR_MIN_TMO, &val_ll) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_MIN_TMO "\" found\n");
		return false;
	}

	timer->param.min_tmo = val_ll;

	if (config_setting_lookup_int64(cs, CONF_STR_MAX_TMO, &val_ll) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_MAX_TMO "\" found\n");
		return false;
	}

	timer->param.max_tmo = val_ll;

	if (config_setting_lookup_int(cs, CONF_STR_NUM, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NUM "\" found\n");
		return false;
	}

	timer->param.num_timers = val_i;

	return true;
}

static void free_timer_entry(timer_parse_t *timer)
{
	if (timer->tmr_pool != ODP_TIMER_POOL_INVALID)
		odp_timer_pool_destroy(timer->tmr_pool);

	free(timer->name);
}

static odp_bool_t timer_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num;
	timer_parse_t *timer;

	cs = config_lookup(config, TIMER_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" TIMER_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" TIMER_DOMAIN "\" entries found\n");
		return false;
	}

	timers.timers = calloc(1U, num * sizeof(*timers.timers));

	if (timers.timers == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" TIMER_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		timer = &timers.timers[timers.num];

		if (!parse_timer_entry(elem, timer)) {
			ODPH_ERR("Invalid \"" TIMER_DOMAIN "\" entry (%d)\n", i);
			free_timer_entry(timer);
			return false;
		}

		++timers.num;
	}

	return true;
}

static odp_bool_t timer_parser_deploy(void)
{
	timer_parse_t *timer;

	printf("\n*** " TIMER_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < timers.num; ++i) {
		timer = &timers.timers[i];
		timer->tmr_pool = odp_timer_pool_create(timer->name, &timer->param);

		if (timer->tmr_pool == ODP_TIMER_POOL_INVALID) {
			ODPH_ERR("Error creating timer pool (%s)\n", timer->name);
			return false;
		}

		if (odp_timer_pool_start_multi(&timer->tmr_pool, 1) != 1) {
			ODPH_ERR("Error starting timer pool (%s)\n", timer->name);
			return false;
		}

		printf("\nname: %s\n"
		       "info:\n", timer->name);
		odp_timer_pool_print(timer->tmr_pool);
	}

	return true;
}

static void timer_parser_destroy(void)
{
	for (uint32_t i = 0U; i < timers.num; ++i)
		free_timer_entry(&timers.timers[i]);

	free(timers.timers);
}

static uintptr_t timer_parser_get_resource(const char *resource)
{
	timer_parse_t *parse;
	odp_timer_pool_t pool = ODP_TIMER_POOL_INVALID;

	for (uint32_t i = 0U; i < timers.num; ++i) {
		parse = &timers.timers[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		pool = parse->tmr_pool;
		break;
	}

	if (pool == ODP_TIMER_POOL_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)pool;
}

CONFIG_PARSER_AUTOREGISTER(MED_PRIO, TIMER_DOMAIN, timer_parser_init, timer_parser_deploy, NULL,
			   timer_parser_destroy, timer_parser_get_resource)
