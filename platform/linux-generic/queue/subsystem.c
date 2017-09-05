/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <odp/api/queue.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp_queue_subsystem.h>
#include <odp_module.h>

ODP_SUBSYSTEM_DEFINE(queue, "queue public APIs", QUEUE_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(queue)
{
	odp_subsystem_constructor(queue);
}

int odp_queue_init_global(void)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->base.init_global);

	return mod->base.init_global();
}

int odp_queue_term_global(void)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->base.term_global);

	return mod->base.term_global();
}

int odp_queue_init_local(void)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->base.init_local);

	return mod->base.init_local();
}

int odp_queue_term_local(void)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->base.term_local);

	return mod->base.term_local();
}

odp_queue_t odp_queue_create(const char *name,
			     const odp_queue_param_t *param)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->create);

	return mod->create(name, param);
}

int odp_queue_destroy(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->destroy);

	return mod->destroy(queue_hdl);
}

odp_queue_t odp_queue_lookup(const char *name)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->lookup);

	return mod->lookup(name);
}

int odp_queue_capability(odp_queue_capability_t *capa)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->capability);

	return mod->capability(capa);
}

int odp_queue_context_set(odp_queue_t queue_hdl, void *context,
			  uint32_t len ODP_UNUSED)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->context_set);

	return mod->context_set(queue_hdl, context, len);
}

void *odp_queue_context(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->context);

	return mod->context(queue_hdl);
}

int odp_queue_enq(odp_queue_t queue_hdl, odp_event_t ev)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->enq);

	return mod->enq(queue_hdl, ev);
}

int odp_queue_enq_multi(odp_queue_t queue_hdl,
			const odp_event_t events[], int num)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->enq_multi);

	return mod->enq_multi(queue_hdl, events, num);
}

odp_event_t odp_queue_deq(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->deq);

	return mod->deq(queue_hdl);
}

int odp_queue_deq_multi(odp_queue_t queue_hdl, odp_event_t events[], int num)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->deq_multi);

	return mod->deq_multi(queue_hdl, events, num);
}

odp_queue_type_t odp_queue_type(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->type);

	return mod->type(queue_hdl);
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->sched_type);

	return mod->sched_type(queue_hdl);
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->sched_prio);

	return mod->sched_prio(queue_hdl);
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->sched_group);

	return mod->sched_group(queue_hdl);
}

int odp_queue_lock_count(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->lock_count);

	return mod->lock_count(queue_hdl);
}

uint64_t odp_queue_to_u64(odp_queue_t queue_hdl)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->to_u64);

	return mod->to_u64(queue_hdl);
}

void odp_queue_param_init(odp_queue_param_t *params)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->param_init);

	return mod->param_init(params);
}

int odp_queue_info(odp_queue_t queue_hdl, odp_queue_info_t *info)
{
	odp_queue_module_t *mod =
		odp_subsystem_active_module(queue, mod);

	ODP_ASSERT(mod);
	ODP_ASSERT(mod->info);

	return mod->info(queue_hdl, info);
}
