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
#include "flow.h"
#include "work.h"

#define CONF_STR_PARSE_TEMPLATE "template"
#define CONF_STR_NAME "name"
#define CONF_STR_INPUT "input"
#define CONF_STR_OUTPUT "output"
#define CONF_STR_WORK "work"
#define CONF_STR_TYPE "type"
#define CONF_STR_PARAM "param"
#define CONF_STR_PREFIX "prefix"
#define CONF_STR_IDX "start_index"
#define CONF_STR_INC "index_increment"

#define FLOW_NAME_LEN 32U

typedef struct {
	char *name;
	char *input;
	char *output;
	flow_t flow;
	work_param_t *work;
	uint32_t num;
} flow_parse_t;

typedef struct {
	flow_parse_t *flows;
	uint32_t num;
} flow_parses_t;

typedef struct {
	char *name_prefix;
	char *input_prefix;
	char *output_prefix;
	work_param_t *work;
	uint32_t name_idx;
	uint32_t name_inc;
	uint32_t input_idx;
	uint32_t input_inc;
	uint32_t output_idx;
	uint32_t output_inc;
	uint32_t num;
} flow_parse_template_t;

typedef enum {
	PARSE_OK,
	PARSE_TEMPL,
	PARSE_NOK
} res_t;

static flow_parses_t flows;

static odp_bool_t parse_work_entry(config_setting_t *cs, work_param_t *work)
{
	const char *val_str;

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_TYPE "\" found\n");
		return false;
	}

	work->type = strdup(val_str);

	if (work->type == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	work->param = config_setting_lookup(cs, CONF_STR_PARAM);

	return true;
}

static void free_work_entry(work_param_t *work)
{
	free(work->type);
}

static res_t parse_flow_entry(config_setting_t *cs, flow_parse_t *flow)
{
	const char *val_str;
	int num;
	config_setting_t *elem;
	work_param_t *work;

	memset(flow, 0, sizeof(*flow));

	if (config_setting_lookup(cs, CONF_STR_PARSE_TEMPLATE) != NULL)
		return PARSE_TEMPL;

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return PARSE_NOK;
	}

	flow->name = strdup(val_str);

	if (flow->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_INPUT, &val_str) == CONFIG_TRUE) {
		flow->input = strdup(val_str);

		if (flow->input == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	} else if (config_setting_lookup_string(cs, CONF_STR_OUTPUT, &val_str) == CONFIG_TRUE) {
		flow->output = strdup(val_str);

		if (flow->output == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	} else {
		ODPH_ERR("No \"" CONF_STR_INPUT "\" or \"" CONF_STR_OUTPUT "\" found\n");
		return PARSE_NOK;
	}

	cs = config_setting_lookup(cs, CONF_STR_WORK);

	if (cs == NULL) {
		ODPH_ERR("No \"" CONF_STR_WORK "\" found\n");
		return PARSE_NOK;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" CONF_STR_WORK "\" entries found\n");
		return PARSE_NOK;
	}

	flow->work = calloc(1U, num * sizeof(*flow->work));

	if (flow->work == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" CONF_STR_WORK "\" entry (%d)\n", i);
			return PARSE_NOK;
		}

		work = &flow->work[i];
		work->queue = flow->input != NULL ? flow->input : flow->output;

		if (!parse_work_entry(elem, work)) {
			ODPH_ERR("Invalid \"" CONF_STR_WORK "\" entry (%d)\n", i);
			free_work_entry(work);
			return PARSE_NOK;
		}

		++flow->num;
	}

	return PARSE_OK;
}

static int parse_flow_entry_template(config_setting_t *cs, flow_parse_template_t *templ)
{
	int val_i;
	uint32_t num;
	config_setting_t *elem;
	const char *val_str;
	work_param_t *work;

	memset(templ, 0, sizeof(*templ));

	if (config_setting_lookup_int(cs, CONF_STR_PARSE_TEMPLATE, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_PARSE_TEMPLATE "\" found\n");
		return -1;
	}

	num = val_i;

	if (num == 0U)
		return -1;

	elem = config_setting_lookup(cs, CONF_STR_NAME);

	if (elem == NULL) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return -1;
	}

	val_str = config_setting_get_string_elem(elem, 0);

	if (val_str == NULL) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_PREFIX "\" found\n");
		return -1;
	}

	templ->name_prefix = strdup(val_str);

	if (templ->name_prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->name_idx = val_i;
	val_i = config_setting_get_int_elem(elem, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->name_inc = val_i;
	elem = config_setting_lookup(cs, CONF_STR_INPUT);

	if (elem != NULL) {
		val_str = config_setting_get_string_elem(elem, 0);

		if (val_str == NULL) {
			ODPH_ERR("No \"" CONF_STR_INPUT "\" \"" CONF_STR_PREFIX "\" found\n");
			return -1;
		}

		templ->input_prefix = strdup(val_str);

		if (templ->input_prefix == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		val_i = config_setting_get_int_elem(elem, 1);

		if (val_i == -1) {
			ODPH_ERR("No \"" CONF_STR_INPUT "\" \"" CONF_STR_IDX "\" found\n");
			return -1;
		}

		templ->input_idx = val_i;
		val_i = config_setting_get_int_elem(elem, 2);

		if (val_i == -1) {
			ODPH_ERR("No \"" CONF_STR_INPUT "\" \"" CONF_STR_INC "\" found\n");
			return -1;
		}

		templ->input_inc = val_i;
	}

	if (templ->input_prefix == NULL) {
		elem = config_setting_lookup(cs, CONF_STR_OUTPUT);

		if (elem == NULL) {
			ODPH_ERR("No \"" CONF_STR_INPUT "\" or \"" CONF_STR_OUTPUT "\" found\n");
			return -1;
		}

		val_str = config_setting_get_string_elem(elem, 0);

		if (val_str == NULL) {
			ODPH_ERR("No \"" CONF_STR_OUTPUT "\" \"" CONF_STR_PREFIX "\" found\n");
			return -1;
		}

		templ->output_prefix = strdup(val_str);

		if (templ->output_prefix == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		val_i = config_setting_get_int_elem(elem, 1);

		if (val_i == -1) {
			ODPH_ERR("No \"" CONF_STR_OUTPUT "\" \"" CONF_STR_IDX "\" found\n");
			return -1;
		}

		templ->output_idx = val_i;
		val_i = config_setting_get_int_elem(elem, 2);

		if (val_i == -1) {
			ODPH_ERR("No \"" CONF_STR_OUTPUT "\" \"" CONF_STR_INC "\" found\n");
			return -1;
		}

		templ->output_inc = val_i;
	}

	cs = config_setting_lookup(cs, CONF_STR_WORK);

	if (cs == NULL) {
		ODPH_ERR("No \"" CONF_STR_WORK "\" found\n");
		return -1;
	}

	val_i = config_setting_length(cs);

	if (val_i == 0) {
		ODPH_ERR("No valid \"" CONF_STR_WORK "\" entries found\n");
		return -1;
	}

	templ->work = calloc(1U, val_i * sizeof(*templ->work));

	if (templ->work == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < val_i; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" CONF_STR_WORK "\" entry (%d)\n", i);
			return -1;
		}

		work = &templ->work[i];

		if (!parse_work_entry(elem, work)) {
			ODPH_ERR("Invalid \"" CONF_STR_WORK "\" entry (%d)\n", i);
			free_work_entry(work);
			return -1;
		}

		++templ->num;
	}

	return num;
}

static odp_bool_t parse_flow_entry_from_template(flow_parse_template_t *templ, flow_parse_t *flow)
{
	char flow_name[FLOW_NAME_LEN];
	char queue_name[ODP_QUEUE_NAME_LEN];
	work_param_t *work_templ, *work;

	memset(flow, 0, sizeof(*flow));
	memset(flow_name, 0, sizeof(flow_name));
	memset(queue_name, 0, sizeof(queue_name));
	(void)snprintf(flow_name, sizeof(flow_name), "%s%u", templ->name_prefix, templ->name_idx);
	templ->name_idx += templ->name_inc;
	flow->name = strdup(flow_name);

	if (flow->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (templ->input_prefix != NULL) {
		(void)snprintf(queue_name, sizeof(queue_name), "%s%u", templ->input_prefix,
			       templ->input_idx);
		templ->input_idx += templ->input_inc;
		flow->input = strdup(queue_name);

		if (flow->input == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	} else {
		(void)snprintf(queue_name, sizeof(queue_name), "%s%u", templ->output_prefix,
			       templ->output_idx);
		templ->output_idx += templ->output_inc;
		flow->output = strdup(queue_name);

		if (flow->output == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	flow->work = calloc(1U, templ->num * sizeof(*flow->work));

	if (flow->work == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (uint32_t i = 0; i < templ->num; ++i) {
		work = &flow->work[i];
		work_templ = &templ->work[i];
		work->queue = flow->input != NULL ? flow->input : flow->output;
		work->type = strdup(work_templ->type);

		if (work->type == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		work->param = work_templ->param;
	}

	flow->num = templ->num;

	return true;
}

static void free_flow_entry(flow_parse_t *flow)
{
	free(flow->name);
	flow_destroy_flow(flow->flow);

	for (uint32_t i = 0U; i < flow->num; ++i)
		free_work_entry(&flow->work[i]);

	free(flow->work);
}

static void free_flow_template(flow_parse_template_t *templ)
{
	free(templ->name_prefix);
	free(templ->input_prefix);
	free(templ->output_prefix);

	for (uint32_t i = 0U; i < templ->num; ++i)
		free_work_entry(&templ->work[i]);

	free(templ->work);
}

static odp_bool_t flow_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num, ret;
	flow_parse_t *flow;
	res_t res;
	flow_parse_template_t templ;

	cs = config_lookup(config, FLOW_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" FLOW_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" FLOW_DOMAIN "\" entries found\n");
		return false;
	}

	flows.flows = calloc(1U, num * sizeof(*flows.flows));

	if (flows.flows == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" FLOW_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		flow = &flows.flows[flows.num];
		res = parse_flow_entry(elem, flow);

		if (res == PARSE_NOK) {
			ODPH_ERR("Invalid \"" FLOW_DOMAIN "\" entry (%d)\n", i);
			free_flow_entry(flow);
			return false;
		} else if (res == PARSE_TEMPL) {
			ret = parse_flow_entry_template(elem, &templ);

			if (ret == -1) {
				ODPH_ERR("Invalid \"" FLOW_DOMAIN "\" entry (%d)\n", i);
				free_flow_template(&templ);
				return false;
			}

			flows.flows = realloc(flows.flows, (ret + flows.num + (num - i - 1)) *
					      sizeof(*flows.flows));

			if (flows.flows == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			for (int j = 0; j < ret; ++j) {
				flow = &flows.flows[flows.num];

				if (!parse_flow_entry_from_template(&templ, flow)) {
					ODPH_ERR("Invalid \"" FLOW_DOMAIN "\" entry (%d)\n", i);
					free_flow_template(&templ);
					free_flow_entry(flow);
					return false;
				}

				++flows.num;
			}

			free_flow_template(&templ);
		} else {
			++flows.num;
		}
	}

	return true;
}

static odp_bool_t flow_parser_deploy(void)
{
	flow_parse_t *parse;
	char *name;
	odp_queue_t queue;
	flow_t flow;
	work_t *work;

	printf("\n*** " FLOW_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < flows.num; ++i) {
		parse = &flows.flows[i];
		work = calloc(1U, parse->num * sizeof(*work));

		if (work == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");

		for (uint32_t j = 0U; j < parse->num; ++j)
			work[j] = work_create_work(&parse->work[j]);

		name = parse->input != NULL ? parse->input : parse->output;
		queue = (odp_queue_t)config_parser_get(QUEUE_DOMAIN, name);
		flow = odp_queue_context(queue);

		if (flow == NULL) {
			parse->flow = flow_create_flow(name);

			if (parse->input != NULL)
				(void)flow_add_input(parse->flow, work, parse->num);
			else
				(void)flow_add_output(parse->flow, work, parse->num);

			if (odp_queue_context_set(queue, (void *)parse->flow, flow_get_data_size())
			    < 0) {
				ODPH_ERR("Error setting queue context\n");
				return false;
			}
		} else {
			if (parse->input != NULL && !flow_add_input(flow, work, parse->num)) {
				ODPH_ERR("Error setting input flow\n");

				for (uint32_t j = 0U; j < parse->num; ++j)
					work_destroy_work(work[j]);

				free(work);
				return false;
			} else if (!flow_add_output(flow, work, parse->num)) {
				ODPH_ERR("Error setting output flow\n");

				for (uint32_t j = 0U; j < parse->num; ++j)
					work_destroy_work(work[j]);

				free(work);
				return false;
			}
		}
	}

	for (uint32_t i = 0U; i < flows.num; ++i) {
		parse = &flows.flows[i];
		printf("\nname: %s\n"
		       "info:\n", parse->name);

		if (parse->input != NULL) {
			printf("  type:  input\n"
			       "  queue: %s\n"
			       "  work:\n", parse->input);

			for (uint32_t j = 0U; j < parse->num; ++j)
				printf("    %s\n", parse->work[j].type);
		} else {
			printf("  type:  output\n"
			       "  queue: %s\n"
			       "  work:\n", parse->output);

			for (uint32_t j = 0U; j < parse->num; ++j)
				printf("    %s\n", parse->work[j].type);
		}
	}

	return true;
}

static void flow_parser_destroy(void)
{
	for (uint32_t i = 0U; i < flows.num; ++i)
		free_flow_entry(&flows.flows[i]);

	free(flows.flows);
}

static uintptr_t flow_parser_get_resource(const char *resource)
{
	flow_parse_t *parse;
	flow_t flow = NULL;

	for (uint32_t i = 0U; i < flows.num; ++i) {
		parse = &flows.flows[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		flow = parse->flow;
		break;
	}

	if (flow == NULL)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)flow;
}

CONFIG_PARSER_AUTOREGISTER(LOW_PRIO, FLOW_DOMAIN, flow_parser_init, flow_parser_deploy, NULL,
			   flow_parser_destroy, flow_parser_get_resource)
