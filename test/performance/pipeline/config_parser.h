/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef CONFIG_PARSER_H_
#define CONFIG_PARSER_H_

#include <libconfig.h>
#include <odp_api.h>

#include "helpers.h"

typedef odp_bool_t (*conf_init_fn_t)(config_t *config);
typedef odp_bool_t (*conf_deploy_fn_t)(void);
typedef void (*conf_undeploy_fn_t)(void);
typedef void (*conf_destroy_fn_t)(void);
typedef uintptr_t (*conf_resource_fn_t)(const char *resource);

odp_bool_t config_parser_init(char *path);

odp_bool_t config_parser_deploy(void);

uintptr_t config_parser_get(const char *domain, const char *resource);

void config_parser_register_parser(const char *domain, conf_init_fn_t init_fn,
				   conf_deploy_fn_t deploy_fn, conf_undeploy_fn_t undeploy_fn,
				   conf_destroy_fn_t destroy_fn, conf_resource_fn_t resource_fn);

void config_parser_undeploy(void);

void config_parser_destroy(void);

#define CONFIG_PARSER_AUTOREGISTER(prio, domain, init, deploy, undeploy, destroy, resource)	  \
	__attribute__((constructor(prio)))							  \
	static void CONCAT(autoregister, __LINE__)(void) {					  \
		config_parser_register_parser(domain, init, deploy, undeploy, destroy, resource); \
	}

#endif
