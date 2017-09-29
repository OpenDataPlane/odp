/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <config.h>

/* API header files */
#include <odp.h>

/* Internal header files */
#include <odp_debug_internal.h>
#include <odp_internal.h>
#include <odp_module.h>
#include <odp_schedule_subsystem.h>

ODP_SUBSYSTEM_DEFINE(schedule, "schedule public APIs",
		     SCHEDULE_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(schedule)
{
	odp_subsystem_constructor(schedule);
}

int odp_schedule_init_global(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->base.init_global);

	return module->base.init_global();
}

int odp_schedule_term_global(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->base.term_global);

	return module->base.term_global();
}

int odp_schedule_init_local(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->base.init_local);

	return module->base.init_local();
}

int odp_schedule_term_local(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->base.term_local);

	return module->base.term_local();
}

uint64_t odp_schedule_wait_time(uint64_t ns)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->wait_time);

	return module->wait_time(ns);
}

odp_event_t odp_schedule(odp_queue_t *from, uint64_t wait)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule);

	return module->schedule(from, wait);
}

int odp_schedule_multi(odp_queue_t *from, uint64_t wait, odp_event_t events[],
		       int num)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_multi);

	return module->schedule_multi(from, wait, events, num);
}

void odp_schedule_pause(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_pause);

	return module->schedule_pause();
}

void odp_schedule_resume(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_resume);

	return module->schedule_resume();
}

void odp_schedule_release_atomic(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_release_atomic);

	return module->schedule_release_atomic();
}

void odp_schedule_release_ordered(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_release_ordered);

	return module->schedule_release_ordered();
}

void odp_schedule_prefetch(int num)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_prefetch);

	return module->schedule_prefetch(num);
}

int odp_schedule_num_prio(void)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_num_prio);

	return module->schedule_num_prio();
}

odp_schedule_group_t odp_schedule_group_create(const char *name,
					       const odp_thrmask_t *mask)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_create);

	return module->schedule_group_create(name, mask);
}

int odp_schedule_group_destroy(odp_schedule_group_t group)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_destroy);

	return module->schedule_group_destroy(group);
}

odp_schedule_group_t odp_schedule_group_lookup(const char *name)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_lookup);

	return module->schedule_group_lookup(name);
}

int odp_schedule_group_join(odp_schedule_group_t group,
			    const odp_thrmask_t *mask)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_join);

	return module->schedule_group_join(group, mask);
}

int odp_schedule_group_leave(odp_schedule_group_t group,
			     const odp_thrmask_t *mask)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_leave);

	return module->schedule_group_leave(group, mask);
}

int odp_schedule_group_thrmask(odp_schedule_group_t group,
			       odp_thrmask_t *thrmask)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_thrmask);

	return module->schedule_group_thrmask(group, thrmask);
}

int odp_schedule_group_info(odp_schedule_group_t group,
			    odp_schedule_group_info_t *info)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_group_info);

	return module->schedule_group_info(group, info);
}

void odp_schedule_order_lock(unsigned lock_index)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_order_lock);

	return module->schedule_order_lock(lock_index);
}

void odp_schedule_order_unlock(unsigned lock_index)
{
	odp_schedule_module_t *module =
		odp_subsystem_active_module(schedule, module);

	ODP_ASSERT(module);
	ODP_ASSERT(module->schedule_order_unlock);

	return module->schedule_order_unlock(lock_index);
}
