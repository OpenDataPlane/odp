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

#define CONF_STR_GROUPS "groups"
#define CONF_STR_NAME "name"

typedef struct {
	char *name;
	odp_schedule_group_t grp;
} grp_parse_t;

typedef struct {
	grp_parse_t *grps;
	uint32_t num;
} scd_parse_t;

static scd_parse_t scd;

static odp_bool_t parse_grp_entry(config_setting_t *cs, grp_parse_t *grp)
{
	const char *val_str;

	grp->grp = ODP_SCHED_GROUP_INVALID;

	if (config_setting_lookup_string(cs, CONF_STR_NAME, &val_str) == CONFIG_FALSE) {
		ODPH_ERR("No \"" CONF_STR_NAME "\" found\n");
		return false;
	}

	grp->name = strdup(val_str);

	if (grp->name == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	return true;
}

static void free_grp_entry(grp_parse_t *grp)
{
	free(grp->name);

	if (grp->grp != ODP_SCHED_GROUP_INVALID)
		(void)odp_schedule_group_destroy(grp->grp);
}

static odp_bool_t sched_parser_init(config_t *config)
{
	config_setting_t *cs, *elem, *tmp;
	int num;
	grp_parse_t *grp;

	cs = config_lookup(config, SCHED_DOMAIN);

	if (cs == NULL)	{
		printf("Nothing to parse for \"" SCHED_DOMAIN "\" domain\n");
		return true;
	}

	elem = config_setting_lookup(cs, CONF_STR_GROUPS);

	if (elem == NULL) {
		ODPH_ERR("No \"" CONF_STR_GROUPS "\" entries found\n");
		return false;
	}

	num = config_setting_length(elem);

	if (num == 0) {
		ODPH_ERR("No valid \"" CONF_STR_GROUPS "\" entries found\n");
		return false;
	}

	scd.grps = calloc(1U, num * sizeof(*scd.grps));

	if (scd.grps == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	for (int i = 0; i < num; ++i) {
		tmp = config_setting_get_elem(elem, i);

		if (tmp == NULL) {
			ODPH_ERR("Unparsable \"" CONF_STR_GROUPS "\" entry (%d)\n", i);
			return false;
		}

		grp = &scd.grps[scd.num];

		if (!parse_grp_entry(tmp, grp)) {
			ODPH_ERR("Invalid \"" CONF_STR_GROUPS "\" entry (%d)\n", i);
			free_grp_entry(grp);
			return false;
		}

		++scd.num;
	}

	/* TODO: Global schedule config parsing */

	return true;
}

static odp_bool_t sched_parser_deploy(void)
{
	grp_parse_t *grp;
	odp_thrmask_t mask;

	printf("\n*** " SCHED_DOMAIN " resources ***\n");

	for (uint32_t i = 0U; i < scd.num; ++i) {
		grp = &scd.grps[i];
		odp_thrmask_zero(&mask);
		grp->grp = odp_schedule_group_create(grp->name, &mask);

		if (grp->grp == ODP_SCHED_GROUP_INVALID) {
			ODPH_ERR("Error creating schedule group (%s)\n", grp->name);
			return false;
		}

		printf("\nname: %s\n", grp->name);
	}

	odp_schedule_print();

	return true;
}

static void sched_parser_destroy(void)
{
	for (uint32_t i = 0U; i < scd.num; ++i)
		free_grp_entry(&scd.grps[i]);

	free(scd.grps);
}

static uintptr_t sched_parser_get_resource(const char *resource)
{
	grp_parse_t *parse;
	odp_schedule_group_t grp = ODP_SCHED_GROUP_INVALID;

	for (uint32_t i = 0U; i < scd.num; ++i) {
		parse = &scd.grps[i];

		if (strcmp(parse->name, resource) != 0)
			continue;

		grp = parse->grp;
		break;
	}

	if (grp == ODP_SCHED_GROUP_INVALID)
		ODPH_ABORT("No resource found (%s), aborting\n", resource);

	return (uintptr_t)grp;
}

CONFIG_PARSER_AUTOREGISTER(CRIT_PRIO, SCHED_DOMAIN, sched_parser_init, sched_parser_deploy, NULL,
			   sched_parser_destroy, sched_parser_get_resource)
