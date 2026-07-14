/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "common.h"
#include "config_parser.h"

#define CONF_STR_NAME "name"
#define CONF_STR_COMPL_MODE_MASK "compl_mode_mask"
#define CONF_STR_ORDER "order"

#define ORDER_NONE "none"
#define ORDER_COMPL "compl"
#define ORDER_ALL "all"

typedef struct {
	char *name;
	odp_dma_param_t param;
	odp_dma_t dma;
} dma_parse_t;

typedef struct {
	dma_parse_t *dmas;
	uint32_t num;
} dma_parses_t;

static dma_parses_t dmas;

static odp_bool_t parse_dma_entry(config_setting_t *cs, dma_parse_t *dma)
{
	const char *val_str;

	dma->dma = ODP_DMA_INVALID;
	odp_dma_param_init(&dma->param);
	dma->param.compl_mode_mask = ODP_DMA_COMPL_EVENT;

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	dma->name = strdup(val_str);

	if (dma->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	if (config_setting_lookup_string(cs, CONF_STR_COMPL_MODE_MASK, &val_str) == CONFIG_TRUE)
		dma->param.compl_mode_mask = (odp_dma_compl_mode_t)strtoul(val_str, NULL, 0);

	if (config_setting_lookup_string(cs, CONF_STR_ORDER, &val_str) == CONFIG_TRUE) {
		if (strcmp(val_str, ORDER_NONE) == 0) {
			dma->param.order = ODP_DMA_ORDER_NONE;
		} else if (strcmp(val_str, ORDER_COMPL) == 0) {
			dma->param.order = ODP_DMA_ORDER_COMPL;
		} else if (strcmp(val_str, ORDER_ALL) == 0) {
			dma->param.order = ODP_DMA_ORDER_ALL;
		} else {
			ODPH_ERR("No valid \"" CONF_STR_ORDER "\" found\n");
			return false;
		}
	}

	return true;
}

static void free_dma_entry(dma_parse_t *dma)
{
	free(dma->name);

	if (dma->dma != ODP_DMA_INVALID)
		(void)odp_dma_destroy(dma->dma);
}

static odp_bool_t dma_parser_init(config_t *config)
{
	config_setting_t *cs, *elem;
	int num;
	dma_parse_t *dma;

	cs = config_lookup(config, ODP_PL_DMA_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" ODP_PL_DMA_DOMAIN "\" domain\n");
		return true;
	}

	num = config_setting_length(cs);

	if (num == 0) {
		ODPH_ERR("No valid \"" ODP_PL_DMA_DOMAIN "\" entries found\n");
		return false;
	}

	dmas.dmas = calloc(1U, num * sizeof(*dmas.dmas));

	if (dmas.dmas == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		elem = config_setting_get_elem(cs, i);

		if (elem == NULL) {
			ODPH_ERR("Unparsable \"" ODP_PL_DMA_DOMAIN "\" entry (%d)\n", i);
			return false;
		}

		dma = &dmas.dmas[dmas.num];

		if (!parse_dma_entry(elem, dma)) {
			ODPH_ERR("Invalid \"" ODP_PL_DMA_DOMAIN "\" entry (%d)\n", i);
			free_dma_entry(dma);
			return false;
		}

		++dmas.num;
	}

	return true;
}

static odp_bool_t dma_parser_deploy(void)
{
	dma_parse_t *dma;

	printf("\n*** " ODP_PL_DMA_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < dmas.num; ++i) {
		dma = &dmas.dmas[i];
		dma->dma = odp_dma_create(dma->name, &dma->param);

		if (dma->dma == ODP_DMA_INVALID) {
			ODPH_ERR("Error creating DMA session (%s)\n", dma->name);
			return false;
		}

		printf("\nname: %s\n"
		       "info:\n", dma->name);
		odp_dma_print(dma->dma);
	}

	return true;
}

static void dma_parser_destroy(void)
{
	for (uint32_t i = 0U; i < dmas.num; ++i)
		free_dma_entry(&dmas.dmas[i]);

	free(dmas.dmas);
}

static uintptr_t dma_parser_get_resource(const char *resource)
{
	dma_parse_t *parse;
	odp_dma_t dma = ODP_DMA_INVALID;

	for (uint32_t i = 0U; i < dmas.num; ++i) {
		parse = &dmas.dmas[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		dma = parse->dma;
		break;
	}

	if (dma == ODP_DMA_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)dma;
}

CONFIG_PARSER_AUTOREGISTER(MED_PRIO, ODP_PL_DMA_DOMAIN, dma_parser_init, dma_parser_deploy, NULL,
			   dma_parser_destroy, dma_parser_get_resource)
