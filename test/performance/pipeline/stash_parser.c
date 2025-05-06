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
#define CONF_STR_TYPE "type"
#define CONF_STR_PUT_MODE "put_mode"
#define CONF_STR_GET_MODE "get_mode"
#define CONF_STR_NUM "num"
#define CONF_STR_SIZE "size"
#define CONF_STR_CACHE_SIZE "cache_size"

#define DEFAULT "default"
#define FIFO "fifo"
#define MT "mt"
#define ST "st"
#define LC "local"

typedef struct {
	char *name;
	odp_stash_param_t param;
	odp_stash_t stash;
} stash_parse_t;

typedef struct {
	stash_parse_t *stashes;
	uint32_t num;
} stash_parses_t;

static stash_parses_t stashes;

static odp_bool_t parse_stash_entry(config_setting_t *cs, stash_parse_t *stash)
{
	const char *val_str;
	long long val_ll;
	int val_i;

	stash->stash = ODP_STASH_INVALID;
	odp_stash_param_init(&stash->param);

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	stash->name = strdup(val_str);

	if (stash->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, DEFAULT) == 0) {
			stash->param.type = ODP_STASH_TYPE_DEFAULT;
		} else if (strcmp(val_str, FIFO) == 0) {
			stash->param.type = ODP_STASH_TYPE_FIFO;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_TYPE "\" found\n");
			return false;
		}
	}

	if (config_setting_lookup_string(cs, CONF_STR_PUT_MODE, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, MT) == 0) {
			stash->param.put_mode = ODP_STASH_OP_MT;
		} else if (strcmp(val_str, ST) == 0) {
			stash->param.put_mode = ODP_STASH_OP_ST;
		} else if (strcmp(val_str, LC) == 0) {
			stash->param.put_mode = ODP_STASH_OP_LOCAL;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_PUT_MODE "\" found\n");
			return false;
		}
	}

	if (config_setting_lookup_string(cs, CONF_STR_GET_MODE, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, MT) == 0) {
			stash->param.get_mode = ODP_STASH_OP_MT;
		} else if (strcmp(val_str, ST) == 0) {
			stash->param.get_mode = ODP_STASH_OP_ST;
		} else if (strcmp(val_str, LC) == 0) {
			stash->param.get_mode = ODP_STASH_OP_LOCAL;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_GET_MODE "\" found\n");
			return false;
		}
	}

	if (config_setting_lookup_int64(cs, CONF_STR_NUM, &val_ll) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NUM "\" found\n");
		return false;
	}

	stash->param.num_obj = val_ll;

	if (config_setting_lookup_int(cs, CONF_STR_SIZE, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_SIZE "\" found\n");
		return false;
	}

	stash->param.obj_size = val_i;

	if (config_setting_lookup_int(cs, CONF_STR_CACHE_SIZE, &val_i) == CONFIG_TRUE)
		stash->param.cache_size = val_i;

	return true;
}

static void free_stash_entry(stash_parse_t *stash)
{
	free(stash->name);

	if (stash->stash != ODP_STASH_INVALID)
		(void)odp_stash_destroy(stash->stash);
}

static odp_bool_t stash_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num;
	stash_parse_t *stash;

	cs = config_lookup(config, STASH_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" STASH_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" STASH_DOMAIN "\" entries found\n");
		return false;
	}

	stashes.stashes = calloc(1U, num * sizeof(*stashes.stashes));

	if (stashes.stashes == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" STASH_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		stash = &stashes.stashes[stashes.num];

		if (!parse_stash_entry(elem, stash)) {
			ODPH_ERR("Invalid \"" STASH_DOMAIN "\" entry (%d)\n", i);
			free_stash_entry(stash);
			return false;
		}

		++stashes.num;
	}

	return true;
}

static odp_bool_t stash_parser_deploy(void)
{
	stash_parse_t *stash;

	printf("\n*** " STASH_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < stashes.num; ++i) {
		stash = &stashes.stashes[i];
		stash->stash = odp_stash_create(stash->name, &stash->param);

		if (stash->stash == ODP_STASH_INVALID) {
			ODPH_ERR("Error creating pool (%s)\n", stash->name);
			return false;
		}

		printf("\nname: %s\n"
		       "info:\n", stash->name);
		odp_stash_print(stash->stash);
	}

	return true;
}

static void stash_parser_destroy(void)
{
	for (uint32_t i = 0U; i < stashes.num; ++i)
		free_stash_entry(&stashes.stashes[i]);

	free(stashes.stashes);
}

static uintptr_t stash_parser_get_resource(const char *resource)
{
	stash_parse_t *parse;
	odp_stash_t stash = ODP_STASH_INVALID;

	for (uint32_t i = 0U; i < stashes.num; ++i) {
		parse = &stashes.stashes[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		stash = parse->stash;
		break;
	}

	if (stash == ODP_STASH_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)stash;
}

CONFIG_PARSER_AUTOREGISTER(MED_PRIO, STASH_DOMAIN, stash_parser_init, stash_parser_deploy, NULL,
			   stash_parser_destroy, stash_parser_get_resource)
