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
#include "worker.h"

#define CONF_STR_NAME "name"
#define CONF_STR_TYPE "type"
#define CONF_STR_BURST_SIZE "burst_size"
#define CONF_STR_WAIT_NS "wait_ns"
#define CONF_STR_INPUTS "inputs"
#define CONF_STR_OUTPUTS "outputs"

#define PLAIN "plain"
#define SCHEDULED "schedule"
#define DEF_BURST 32U
#define DEF_WAIT_NS_S ODP_TIME_SEC_IN_NS
#define DEF_WAIT_NS_P 0U

typedef struct {
	worker_t *workers;
	uint32_t num;
} worker_parses_t;

static worker_parses_t workers;

static odp_bool_t parse_worker_entry(config_setting_t *cs, worker_t *worker)
{
	const char *val_str;
	config_setting_t *elem;
	int val_i, num;
	long long val_ll;

	worker->burst_size = DEF_BURST;

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	worker->name = strdup(val_str);

	if (worker->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_TYPE "\" found\n");
		return false;
	}

	if (strcmp(val_str, PLAIN) == 0) {
		worker->type = WT_PLAIN;
		worker->wait_ns = DEF_WAIT_NS_P;
	} else if (strcmp(val_str, SCHEDULED) == 0) {
		worker->type = WT_SCHED;
		worker->wait_ns = DEF_WAIT_NS_S;
	} else {
		ODPH_ERR("No valid \"" CONF_STR_TYPE "\" found\n");
		return false;
	}

	if (config_setting_lookup_int(cs, CONF_STR_BURST_SIZE, &val_i) == CONFIG_TRUE)
		worker->burst_size = val_i;

	if (config_setting_lookup_int64(cs, CONF_STR_WAIT_NS, &val_ll) == CONFIG_TRUE)
		worker->wait_ns = val_ll;

	elem = config_setting_lookup(cs, CONF_STR_OUTPUTS);

	if (elem != NULL) {
		num = config_setting_length(elem);

		if (num == 0) {
			ODPH_ERR("No valid \"" CONF_STR_OUTPUTS "\" entries found\n");
			return false;
		}

		worker->outputs = calloc(1U, num * sizeof(*worker->outputs));

		if (worker->outputs == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		for (int i = 0; i < num; ++i) {
			val_str = config_setting_get_string_elem(elem, i);

			if (val_str == NULL) {
				ODPH_ERR("Unparsable \"" CONF_STR_OUTPUTS "\" entry (%d)\n", i);
				return false;
			}

			worker->outputs[worker->num_out] = strdup(val_str);

			if (worker->outputs[worker->num_out] == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			++worker->num_out;
		}
	}

	elem = config_setting_lookup(cs, CONF_STR_INPUTS);

	if (elem != NULL) {
		num = config_setting_length(elem);

		if (num == 0) {
			ODPH_ERR("No valid \"" CONF_STR_INPUTS "\" entries found\n");
			return false;
		}

		worker->inputs = calloc(1U, num * sizeof(*worker->inputs));

		if (worker->inputs == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		for (int i = 0; i < num; ++i) {
			val_str = config_setting_get_string_elem(elem, i);

			if (val_str == NULL) {
				ODPH_ERR("Unparsable \"" CONF_STR_INPUTS "\" entry (%d)\n", i);
				return false;
			}

			worker->inputs[worker->num_in] = strdup(val_str);

			if (worker->inputs[worker->num_in] == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			++worker->num_in;
		}
	}

	if (worker->type == WT_PLAIN && worker->num_in == 0U && worker->num_out == 0U) {
		ODPH_ERR("No \"" CONF_STR_INPUTS "\" or \"" CONF_STR_OUTPUTS "\" found\n");
		return false;
	}

	return true;
}

static void free_worker_entry(worker_t *worker)
{
	free(worker->name);

	for (uint32_t i = 0U; i < worker->num_in; ++i)
		free(worker->inputs[i]);

	free(worker->inputs);

	for (uint32_t i = 0U; i < worker->num_out; ++i)
		free(worker->outputs[i]);

	free(worker->outputs);
}

static odp_bool_t worker_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num;
	worker_t *worker;

	cs = config_lookup(config, WORKER_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" WORKER_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" WORKER_DOMAIN "\" entries found\n");
		return false;
	}

	workers.workers = calloc(1U, num * sizeof(*workers.workers));

	if (workers.workers == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" WORKER_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		worker = &workers.workers[workers.num];

		if (!parse_worker_entry(elem, worker)) {
			ODPH_ERR("Invalid \"" WORKER_DOMAIN "\" entry (%d)\n", i);
			free_worker_entry(worker);
			return false;
		}

		++workers.num;
	}

	return true;
}

static odp_bool_t worker_parser_deploy(void)
{
	worker_t *worker;

	printf("\n*** " WORKER_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < workers.num; ++i) {
		worker = &workers.workers[i];
		printf("\nname: %s\n"
		       "info:\n"
		       "  type: %s\n", worker->name,
		       worker->type == WT_SCHED ? "schedule" : "plain");

		if (worker->inputs != NULL) {
			printf("  inputs:\n");

			for (uint32_t j = 0U; j < worker->num_in; ++j)
				printf("    %s\n", worker->inputs[j]);
		}

		if (worker->outputs != NULL) {
			printf("  outputs:\n");

			for (uint32_t j = 0U; j < worker->num_out; ++j)
				printf("    %s\n", worker->outputs[j]);
		}
	}

	return true;
}

static void worker_parser_destroy(void)
{
	for (uint32_t i = 0U; i < workers.num; ++i)
		free_worker_entry(&workers.workers[i]);

	free(workers.workers);
}

static uintptr_t worker_parser_get_resource(const char *resource)
{
	worker_t *parse, *worker = NULL;

	for (uint32_t i = 0U; i < workers.num; ++i) {
		parse = &workers.workers[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		worker = parse;
		break;
	}

	if (worker == NULL)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)worker;
}

CONFIG_PARSER_AUTOREGISTER(LOW_PRIO, WORKER_DOMAIN, worker_parser_init, worker_parser_deploy, NULL,
			   worker_parser_destroy, worker_parser_get_resource)
