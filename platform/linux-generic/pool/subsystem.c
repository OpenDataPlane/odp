/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <odp/api/pool.h>
#include <odp_internal.h>
#include <subsystem/spec/pool_subsystem.h>
#include <odp_debug_internal.h>
#include <odp_module.h>

#define SUBSYSTEM_VERSION 0x00010000UL
ODP_SUBSYSTEM_DEFINE(pool, "memory pool public APIs", SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(pool)
{
	odp_subsystem_constructor(pool);
}

int odp_pool_init_global(void)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->base.init_global == NULL) {
		ODP_ERR("No defined init_global function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->base.init_global();
}

int odp_pool_term_global(void)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->base.term_global == NULL) {
		ODP_ERR("No defined term_global function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->base.term_global();
}

int odp_pool_init_local(void)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->base.term_global == NULL) {
		ODP_ERR("No defined init_local function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->base.init_local();
}

int odp_pool_term_local(void)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->base.term_local == NULL) {
		ODP_ERR("No defined term_local function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->base.term_local();
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->capability == NULL) {
		ODP_ERR("No defined capability function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->capability(capa);
}

odp_pool_t odp_pool_create(const char *name, odp_pool_param_t *params)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return ODP_POOL_INVALID;
	}
	if (mod->create == NULL) {
		ODP_ERR("No defined create function "
			"in module %s of pool subsystem\n", mod->base.name);
		return ODP_POOL_INVALID;
	}

	return mod->create(name, params);
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->destroy == NULL) {
		ODP_ERR("No defined destroy function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->destroy(pool_hdl);
}

odp_pool_t odp_pool_lookup(const char *name)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return ODP_POOL_INVALID;
	}
	if (mod->lookup == NULL) {
		ODP_ERR("No defined lookup function "
			"in module %s of pool subsystem\n", mod->base.name);
		return ODP_POOL_INVALID;
	}

	return mod->lookup(name);
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->info == NULL) {
		ODP_ERR("No defined info function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->info(pool_hdl, info);
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return;
	}
	if (mod->print == NULL) {
		ODP_ERR("No defined print function "
			"in module %s of pool subsystem\n", mod->base.name);
		return;
	}

	mod->print(pool_hdl);
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return;
	}
	if (mod->param_init == NULL) {
		ODP_ERR("No defined param_init function "
			"in module %s of pool subsystem\n", mod->base.name);
		return;
	}

	mod->param_init(params);
}

uint64_t odp_pool_to_u64(odp_pool_t hdl)
{
	pool_module_t *mod;

	mod = odp_subsystem_active_module(pool, mod);
	if (mod == NULL) {
		ODP_ERR("No active module in pool subsystem\n");
		return -1;
	}
	if (mod->to_u64 == NULL) {
		ODP_ERR("No defined to_u64 function "
			"in module %s of pool subsystem\n", mod->base.name);
		return -1;
	}

	return mod->to_u64(hdl);
}

