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
#include "cpumap.h"

#define CONF_STR_CPUMASK "cpumask"
#define CONF_STR_WORKERS "workers"

static cpumap_t cpumap;

static odp_bool_t cpumap_parser_init(config_t *config)
{
	config_setting_t *cs;
	const char *val_str;
	int num;

	cs = config_lookup(config, CPUMAP_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" CPUMAP_DOMAIN "\" domain\n");
		return true;
	}

	if (config_setting_lookup_string(cs, CONF_STR_CPUMASK, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_CPUMASK "\" found\n");
		return false;
	}

	odp_cpumask_from_str(&cpumap.cpumask, val_str);
	cs = config_setting_lookup(cs, CONF_STR_WORKERS);

	if (cs == NULL) {
		ODPH_ERR("No \"" CONF_STR_WORKERS "\" found\n");
		return false;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" CONF_STR_WORKERS "\" entries found\n");
		return false;
	}

	cpumap.workers = calloc(1U, num * sizeof(*cpumap.workers));

	if (cpumap.workers == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		val_str = config_setting_get_string_elem(cs, i);

		if (val_str == NULL) {
			ODPH_ERR("Unparsable \"" CONF_STR_WORKERS "\" entry (%d)\n", i);
			return false;
		}

		cpumap.workers[cpumap.num] = strdup(val_str);

		if (cpumap.workers[cpumap.num] == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		++cpumap.num;
	}

	return true;
}

static odp_bool_t cpumap_parser_deploy(void)
{
	char str[ODP_CPUMASK_STR_SIZE] = { 0 };

	(void)odp_cpumask_to_str(&cpumap.cpumask, str, ODP_CPUMASK_STR_SIZE);

	printf("\n*** " CPUMAP_DOMAIN " resources ***\n\n"
	       "name: N/A\n"
	       "info:\n"
	       "  cpumask: %s\n"
	       "  workers:\n", str);

	for (uint32_t i = 0U; i < cpumap.num; ++i)
		printf("    %s\n", cpumap.workers[i]);

	return true;
}

static void cpumap_parser_destroy(void)
{
	for (uint32_t i = 0U; i < cpumap.num; ++i)
		free(cpumap.workers[i]);

	free(cpumap.workers);
}

static uintptr_t cpumap_parser_get_resource(const char *resource ODP_UNUSED)
{
	return (uintptr_t)&cpumap;
}

CONFIG_PARSER_AUTOREGISTER(HIGH_PRIO, CPUMAP_DOMAIN, cpumap_parser_init, cpumap_parser_deploy,
			   NULL, cpumap_parser_destroy, cpumap_parser_get_resource)
