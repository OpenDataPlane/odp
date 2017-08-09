/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_POOL_SUBSYSTEM_H_
#define ODP_POOL_SUBSYSTEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_module.h>
#include <odp/api/pool.h>

/* ODP pool public APIs subsystem */
ODP_SUBSYSTEM_DECLARE(pool);

/* Subsystem APIs declarations */
ODP_SUBSYSTEM_API(pool, int, capability, odp_pool_capability_t *capa);
ODP_SUBSYSTEM_API(pool, odp_pool_t, create, const char *name,
		  odp_pool_param_t *params);
ODP_SUBSYSTEM_API(pool, int, destroy, odp_pool_t pool);
ODP_SUBSYSTEM_API(pool, odp_pool_t, lookup, const char *name);
ODP_SUBSYSTEM_API(pool, int, info, odp_pool_t pool, odp_pool_info_t *info);
ODP_SUBSYSTEM_API(pool, void, print, odp_pool_t pool);
ODP_SUBSYSTEM_API(pool, uint64_t, to_u64, odp_pool_t pool);
ODP_SUBSYSTEM_API(pool, void, param_init, odp_pool_param_t *params);

typedef ODP_MODULE_CLASS(pool) {
	odp_module_base_t base;

	odp_api_proto(pool, capability) capability;
	odp_api_proto(pool, create) create;
	odp_api_proto(pool, destroy) destroy;
	odp_api_proto(pool, lookup) lookup;
	odp_api_proto(pool, info) info;
	odp_api_proto(pool, print) print;
	odp_api_proto(pool, to_u64) to_u64;
	odp_api_proto(pool, param_init) param_init;
} pool_module_t;

#ifdef __cplusplus
}
#endif

#endif
