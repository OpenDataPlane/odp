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
#define CONF_STR_SIZE "size"
#define CONF_STR_CACHE_SIZE "cache_size"
#define CONF_STR_NUM "num"

#define PACKET "packet"
#define BUFFER "buffer"
#define TIMEOUT "timeout"
#define DMA_COMPL "dma_completion"

typedef struct {
	char *name;
	odp_pool_type_t type;
	odp_pool_param_t p_param;
	odp_dma_pool_param_t d_param;
	odp_pool_t pool;
} pool_parse_t;

typedef struct {
	pool_parse_t *pools;
	uint32_t num;
} pool_parses_t;

static pool_parses_t pools;

static odp_bool_t parse_pool_entry(config_setting_t *cs, pool_parse_t *pool)
{
	const char *val_str;
	int val_i;
	uint32_t size = 0U, num;

	pool->pool = ODP_POOL_INVALID;
	odp_pool_param_init(&pool->p_param);
	odp_dma_pool_param_init(&pool->d_param);

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	pool->name = strdup(val_str);

	if (pool->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_TYPE, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_TYPE "\" found\n");
		return false;
	}

	if (strcmp(val_str, PACKET) == 0) {
		pool->type = ODP_POOL_PACKET;
	} else if (strcmp(val_str, BUFFER) == 0) {
		pool->type = ODP_POOL_BUFFER;
	} else if (strcmp(val_str, TIMEOUT) == 0) {
		pool->type = ODP_POOL_TIMEOUT;
	} else if (strcmp(val_str, DMA_COMPL) == 0) {
		pool->type = ODP_POOL_DMA_COMPL;
	} else {
		ODPH_ERR("No valid \"" CONF_STR_TYPE "\" found\n");
		return false;
	}

	if (config_setting_lookup_int(cs, CONF_STR_CACHE_SIZE, &val_i) == CONFIG_TRUE) {
		pool->p_param.buf.cache_size = val_i;
		pool->p_param.pkt.cache_size = val_i;
		pool->p_param.tmo.cache_size = val_i;
		pool->d_param.cache_size = val_i;
	}

	if (config_setting_lookup_int(cs, CONF_STR_NUM, &val_i) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NUM "\" found\n");
		return false;
	}

	num = val_i;

	if (pool->type == ODP_POOL_PACKET || pool->type == ODP_POOL_BUFFER) {
		if (config_setting_lookup_int(cs, CONF_STR_SIZE, &val_i) == CONFIG_FALSE) {
			ODPH_ERR("No \"" CONF_STR_SIZE "\" found\n");
			return false;
		}

		size = val_i;
	}

	pool->p_param.type = pool->type;

	if (pool->type == ODP_POOL_PACKET) {
		pool->p_param.pkt.len = size;
		pool->p_param.pkt.seg_len = size;
		pool->p_param.pkt.num = num;
	} else if (pool->type == ODP_POOL_BUFFER) {
		pool->p_param.buf.size = size;
		pool->p_param.buf.num = num;
	} else if (pool->type == ODP_POOL_TIMEOUT) {
		pool->p_param.tmo.num = num;
	} else {
		pool->d_param.num = num;
	}

	return true;
}

static void free_pool_entry(pool_parse_t *pool)
{
	free(pool->name);

	if (pool->pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(pool->pool);
}

static odp_bool_t pool_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num;
	pool_parse_t *pool;

	cs = config_lookup(config, POOL_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" POOL_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" POOL_DOMAIN "\" entries found\n");
		return false;
	}

	pools.pools = calloc(1U, num * sizeof(*pools.pools));

	if (pools.pools == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" POOL_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		pool = &pools.pools[pools.num];

		if (!parse_pool_entry(elem, pool)) {
			ODPH_ERR("Invalid \"" POOL_DOMAIN "\" entry (%d)\n", i);
			free_pool_entry(pool);
			return false;
		}

		++pools.num;
	}

	return true;
}

static odp_bool_t pool_parser_deploy(void)
{
	pool_parse_t *pool;

	printf("\n*** " POOL_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < pools.num; ++i) {
		pool = &pools.pools[i];

		if (pool->type != ODP_POOL_DMA_COMPL)
			pool->pool = odp_pool_create(pool->name, &pool->p_param);
		else
			pool->pool = odp_dma_pool_create(pool->name, &pool->d_param);

		if (pool->pool == ODP_POOL_INVALID) {
			ODPH_ERR("Error creating pool (%s)\n", pool->name);
			return false;
		}

		printf("\nname: %s\n"
		       "info:\n", pool->name);
		odp_pool_print(pool->pool);
	}

	return true;
}

static void pool_parser_destroy(void)
{
	for (uint32_t i = 0U; i < pools.num; ++i)
		free_pool_entry(&pools.pools[i]);

	free(pools.pools);
}

static uintptr_t pool_parser_get_resource(const char *resource)
{
	pool_parse_t *parse;
	odp_pool_t pool = ODP_POOL_INVALID;

	for (uint32_t i = 0U; i < pools.num; ++i) {
		parse = &pools.pools[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		pool = parse->pool;
		break;
	}

	if (pool == ODP_POOL_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)pool;
}

CONFIG_PARSER_AUTOREGISTER(HIGH_PRIO, POOL_DOMAIN, pool_parser_init, pool_parser_deploy, NULL,
			   pool_parser_destroy, pool_parser_get_resource)
