/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <odp/api/buffer.h>
#include <odp_buffer_subsystem.h>
#include <odp_debug_internal.h>
#include <odp_module.h>

ODP_SUBSYSTEM_DEFINE(buffer, "memory buffer public APIs",
		     BUFFER_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(buffer)
{
	odp_subsystem_constructor(buffer);
}

odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_from_event(ev);
}

odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_to_event(buf);
}

void *odp_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_addr(buf);
}

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_size(buf);
}

void odp_buffer_print(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_print(buf);
}

uint64_t odp_buffer_to_u64(odp_buffer_t hdl)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_to_u64(hdl);
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_alloc(pool_hdl);
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_alloc_multi(pool_hdl, buf, num);
}

void odp_buffer_free(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_free(buf);
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_free_multi(buf, num);
}

odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_pool(buf);
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	odp_buffer_module_t *mod;

	mod = odp_subsystem_active_module(buffer, mod);
	return mod->buffer_is_valid(buf);
}

