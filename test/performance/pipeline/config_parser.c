/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <dlfcn.h>
#include <stdlib.h>

#include <odp/helper/odph_api.h>
#include <sys/queue.h>

#include "config_parser.h"

typedef struct parser_s {
	TAILQ_ENTRY(parser_s) p;

	const char *domain;
	conf_init_fn_t init_fn;
	conf_deploy_fn_t deploy_fn;
	conf_undeploy_fn_t undeploy_fn;
	conf_destroy_fn_t destroy_fn;
	conf_resource_fn_t resource_fn;
} parser_t;

typedef struct {
	TAILQ_HEAD(, parser_s) p;

	config_t config;
	const opts_t *opts;
	void **handles;
	odp_bool_t init_done;
	odp_bool_t config_done;
} parsers_t;

static parsers_t parsers;

/* Loaded after baseline work is registered so library work of the same name takes precedence. */
static odp_bool_t load_libs(void)
{
	if (parsers.opts->num_libs == 0U)
		return true;

	parsers.handles = calloc(parsers.opts->num_libs, sizeof(*parsers.handles));

	if (parsers.handles == NULL) {
		ODPH_ERR("Error allocating memory\n");
		return false;
	}

	for (uint32_t i = 0U; i < parsers.opts->num_libs; ++i) {
		parsers.handles[i] = dlopen(parsers.opts->libs[i], RTLD_NOW);

		if (parsers.handles[i] == NULL) {
			ODPH_ERR("Error loading library %s: %s\n", parsers.opts->libs[i],
				 dlerror());
			return false;
		}
	}

	return true;
}

static void unload_libs(void)
{
	if (parsers.handles == NULL)
		return;

	for (uint32_t i = 0U; i < parsers.opts->num_libs; ++i) {
		if (parsers.handles[i] != NULL)
			dlclose(parsers.handles[i]);
	}

	free(parsers.handles);
}

odp_bool_t config_parser_init(const opts_t *opts)
{
	int ret;
	parser_t *parser;
	odp_bool_t p_ret = true;

	parsers.opts = opts;

	if (!load_libs())
		return false;

	config_init(&parsers.config);
	parsers.config_done = true;
	ret = config_read_file(&parsers.config, parsers.opts->path);

	if (ret == CONFIG_FALSE) {
		ODPH_ERR("Error opening configuration file, line %d: %s\n",
			 config_error_line(&parsers.config), config_error_text(&parsers.config));
		return false;
	}

	TAILQ_FOREACH(parser, &parsers.p, p) {
		if (!parser->init_fn(&parsers.config)) {
			ODPH_ERR("Error parsing domain: %s\n", parser->domain);
			p_ret = false;
			break;
		}
	}

	return p_ret;
}

odp_bool_t config_parser_deploy(void)
{
	parser_t *parser;

	TAILQ_FOREACH(parser, &parsers.p, p)
		if (!parser->deploy_fn())
			return false;

	return true;
}

uintptr_t config_parser_get(const char *domain, const char *resource)
{
	parser_t *parser;

	TAILQ_FOREACH(parser, &parsers.p, p)
		if (strcmp(domain, parser->domain) == 0)
			return parser->resource_fn(resource);

	ODPH_ABORT("No domain found (%s)\n", domain);
}

void config_parser_register_parser(const char *domain, conf_init_fn_t init_fn,
				   conf_deploy_fn_t deploy_fn, conf_undeploy_fn_t undeploy_fn,
				   conf_destroy_fn_t destroy_fn, conf_resource_fn_t resource_fn)
{
	parser_t *entry = calloc(1U, sizeof(*entry));

	if (entry == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	entry->domain = domain;
	entry->init_fn = init_fn;
	entry->deploy_fn = deploy_fn;
	entry->undeploy_fn = undeploy_fn;
	entry->destroy_fn = destroy_fn;
	entry->resource_fn = resource_fn;

	if (!parsers.init_done) {
		TAILQ_INIT(&parsers.p);
		parsers.init_done = true;
	}

	TAILQ_INSERT_TAIL(&parsers.p, entry, p);
}

void config_parser_undeploy(void)
{
	parser_t *parser;

	TAILQ_HEAD(tailhead, parser_s);

	TAILQ_FOREACH_REVERSE(parser, &parsers.p, tailhead, p)
		if (parser->undeploy_fn != NULL)
			parser->undeploy_fn();
}

void config_parser_destroy(void)
{
	parser_t *parser, *drop;

	TAILQ_HEAD(tailhead, parser_s);

	TAILQ_FOREACH_REVERSE(parser, &parsers.p, tailhead, p)
		parser->destroy_fn();

	for (parser = TAILQ_FIRST(&parsers.p); parser != NULL;) {
		TAILQ_REMOVE(&parsers.p, parser, p);
		drop = parser;
		parser = TAILQ_NEXT(parser, p);
		free(drop);
	}

	if (parsers.config_done)
		config_destroy(&parsers.config);

	unload_libs();
}
