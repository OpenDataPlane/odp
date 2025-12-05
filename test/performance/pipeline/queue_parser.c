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

#define CONF_STR_PARSE_TEMPLATE "template"
#define CONF_STR_NAME "name"
#define CONF_STR_TYPE "type"
#define CONF_STR_PRIO "priority"
#define CONF_STR_GROUP "group"
#define CONF_STR_SYNC "sync"
#define CONF_STR_SIZE "size"
#define CONF_STR_PREFIX "prefix"
#define CONF_STR_IDX "start_index"
#define CONF_STR_INC "index_increment"

#define PLAIN "plain"
#define SCHEDULED "schedule"
#define PARALLEL "parallel"
#define ATOMIC "atomic"
#define ORDERED "ordered"

typedef struct {
	char *name;
	char *ext;
	char *group;
	odp_queue_param_t param;
	odp_queue_t queue;
} queue_parse_t;

typedef struct {
	queue_parse_t *queues;
	uint32_t num;
} queue_parses_t;

typedef struct {
	char *prefix;
	char *type;
	char *group;
	char *sync;
	uint32_t idx;
	uint32_t inc;
	int priority;
} queue_parse_template_t;

typedef enum {
	PARSE_OK,
	PARSE_TEMPL,
	PARSE_NOK
} res_t;

static queue_parses_t queues;

static res_t parse_queue_entry(config_setting_t *cs, queue_parse_t *queue)
{
	const char *val_str;
	int val_i;

	if (config_setting_lookup(cs, CONF_STR_PARSE_TEMPLATE) != NULL)
		return PARSE_TEMPL;

	memset(queue, 0, sizeof(*queue));
	queue->queue = ODP_QUEUE_INVALID;
	odp_queue_param_init(&queue->param);

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return PARSE_NOK;
	}

	queue->name = strdup(val_str);

	if (queue->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, PLAIN) == 0) {
			queue->param.type = ODP_QUEUE_TYPE_PLAIN;
		} else if (strcmp(val_str, SCHEDULED) == 0) {
			queue->param.type = ODP_QUEUE_TYPE_SCHED;
		} else {
			queue->ext = strdup(val_str);

			if (queue->ext == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");
		}
	}

	if (queue->param.type == ODP_QUEUE_TYPE_PLAIN)
		return PARSE_OK;

	if (config_setting_lookup_int(cs, CONF_STR_PRIO, &val_i) == CONFIG_TRUE)
		queue->param.sched.prio = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_GROUP, &val_str) == CONFIG_TRUE) {
		queue->group = strdup(val_str);

		if (queue->group == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	if (config_setting_lookup_string(cs, CONF_STR_SYNC, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, PARALLEL) == 0) {
			queue->param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
		} else if (strcmp(val_str, ATOMIC) == 0) {
			queue->param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
		} else if (strcmp(val_str, ORDERED) == 0) {
			queue->param.sched.sync = ODP_SCHED_SYNC_ORDERED;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_SYNC "\" found\n");
			return PARSE_NOK;
		}
	}

	if (config_setting_lookup_int(cs, CONF_STR_SIZE, &val_i) == CONFIG_TRUE)
		queue->param.size = val_i;

	return PARSE_OK;
}

static int parse_queue_entry_template(config_setting_t *cs, queue_parse_template_t *templ)
{
	int val_i;
	uint32_t num;
	config_setting_t *elem;
	const char *val_str;

	memset(templ, 0, sizeof(*templ));
	templ->priority = -1;

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

	templ->prefix = strdup(val_str);

	if (templ->prefix == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	val_i = config_setting_get_int_elem(elem, 1);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_IDX "\" found\n");
		return -1;
	}

	templ->idx = val_i;
	val_i = config_setting_get_int_elem(elem, 2);

	if (val_i == -1) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" \"" CONF_STR_INC "\" found\n");
		return -1;
	}

	templ->inc = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_TRUE) {
		templ->type = strdup(val_str);

		if (templ->type == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	if (config_setting_lookup_int(cs, CONF_STR_PRIO, &val_i) == CONFIG_TRUE)
		templ->priority = val_i;

	if (config_setting_lookup_string(cs, CONF_STR_GROUP, &val_str) == CONFIG_TRUE) {
		templ->group = strdup(val_str);

		if (templ->group == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	if (config_setting_lookup_string(cs, CONF_STR_SYNC, &val_str) == CONFIG_TRUE) {
		templ->sync = strdup(val_str);

		if (templ->sync == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	return num;
}

static odp_bool_t parse_queue_entry_from_template(queue_parse_template_t *templ,
						  queue_parse_t *queue)
{
	char name[ODP_QUEUE_NAME_LEN];

	memset(queue, 0, sizeof(*queue));
	memset(name, 0, sizeof(name));
	queue->queue = ODP_QUEUE_INVALID;
	odp_queue_param_init(&queue->param);
	(void)snprintf(name, sizeof(name), "%s%u", templ->prefix, templ->idx);
	templ->idx += templ->inc;
	queue->name = strdup(name);

	if (queue->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (templ->type != NULL) {
		if (strcmp(templ->type, PLAIN) == 0) {
			queue->param.type = ODP_QUEUE_TYPE_PLAIN;
		} else if (strcmp(templ->type, SCHEDULED) == 0) {
			queue->param.type = ODP_QUEUE_TYPE_SCHED;
		} else {
			queue->ext = strdup(templ->type);

			if (queue->ext == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");
		}
	}

	if (templ->priority != -1)
		queue->param.sched.prio = templ->priority;

	if (templ->group != NULL) {
		queue->group = strdup(templ->group);

		if (queue->group == NULL)
			ODPH_ABORT("Error allocating memory, aborting\n");
	}

	if (templ->sync != NULL) {
		if (strcmp(templ->sync, PARALLEL) == 0) {
			queue->param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
		} else if (strcmp(templ->sync, ATOMIC) == 0) {
			queue->param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
		} else if (strcmp(templ->sync, ORDERED) == 0) {
			queue->param.sched.sync = ODP_SCHED_SYNC_ORDERED;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_SYNC "\" found\n");
			return false;
		}
	}

	return true;
}

static void free_queue_entry(queue_parse_t *queue)
{
	free(queue->name);
	free(queue->ext);
	free(queue->group);

	if (queue->queue != ODP_QUEUE_INVALID)
		(void)odp_queue_destroy(queue->queue);
}

static void free_queue_template(queue_parse_template_t *templ)
{
	free(templ->prefix);
	free(templ->type);
	free(templ->group);
	free(templ->sync);
}

static odp_bool_t queue_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num, ret;
	queue_parse_t *queue;
	res_t res;
	queue_parse_template_t templ;

	cs = config_lookup(config, QUEUE_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" QUEUE_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" QUEUE_DOMAIN "\" entries found\n");
		return false;
	}

	queues.queues = calloc(1U, num * sizeof(*queues.queues));

	if (queues.queues == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" QUEUE_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		queue = &queues.queues[queues.num];
		res = parse_queue_entry(elem, queue);

		if (res == PARSE_NOK) {
			ODPH_ERR("Invalid \"" QUEUE_DOMAIN "\" entry (%d)\n", i);
			free_queue_entry(queue);
			return false;
		} else if (res == PARSE_TEMPL) {
			ret = parse_queue_entry_template(elem, &templ);

			if (ret == -1) {
				ODPH_ERR("Invalid \"" QUEUE_DOMAIN "\" entry (%d)\n", i);
				free_queue_template(&templ);
				return false;
			}

			queues.queues = realloc(queues.queues, (ret + queues.num + (num - i - 1)) *
						sizeof(*queues.queues));

			if (queues.queues == NULL)
				ODPH_ABORT("Error allocating memory, aborting\n");

			for (int j = 0; j < ret; ++j) {
				queue = &queues.queues[queues.num];

				if (!parse_queue_entry_from_template(&templ, queue)) {
					ODPH_ERR("Invalid \"" QUEUE_DOMAIN "\" entry (%d)\n", i);
					free_queue_template(&templ);
					free_queue_entry(queue);
					return false;
				}

				++queues.num;
			}

			free_queue_template(&templ);
		} else {
			++queues.num;
		}
	}

	return true;
}

static odp_bool_t queue_parser_deploy(void)
{
	queue_parse_t *queue;

	printf("\n*** " QUEUE_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < queues.num; ++i) {
		queue = &queues.queues[i];

		if (queue->ext != NULL)
			continue;

		if (queue->group != NULL)
			queue->param.sched.group =
			       (odp_schedule_group_t)config_parser_get(SCHED_DOMAIN, queue->group);

		queue->queue = odp_queue_create(queue->name, &queue->param);

		if (queue->queue == ODP_QUEUE_INVALID) {
			ODPH_ERR("Error creating queue (%s)\n", queue->name);
			return false;
		}

		printf("\nname: %s\n"
		       "info:\n", queue->name);
		odp_queue_print(queue->queue);
	}

	return true;
}

static void queue_parser_destroy(void)
{
	for (uint32_t i = 0U; i < queues.num; ++i)
		free_queue_entry(&queues.queues[i]);

	free(queues.queues);
}

static uintptr_t queue_parser_get_resource(const char *resource)
{
	queue_parse_t *parse;
	odp_queue_t queue = ODP_QUEUE_INVALID;

	for (uint32_t i = 0U; i < queues.num; ++i) {
		parse = &queues.queues[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		if (parse->ext != NULL)
			queue = (odp_queue_t)config_parser_get(parse->ext, resource);
		else
			queue = parse->queue;

		break;
	}

	if (queue == ODP_QUEUE_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)queue;
}

CONFIG_PARSER_AUTOREGISTER(HIGH_PRIO, QUEUE_DOMAIN, queue_parser_init, queue_parser_deploy, NULL,
			   queue_parser_destroy, queue_parser_get_resource)
