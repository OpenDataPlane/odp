/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_schedule_if.h>

extern const schedule_fn_t schedule_sp_fn;
extern const schedule_api_t schedule_sp_api;

extern const schedule_fn_t schedule_default_fn;
extern const schedule_api_t schedule_default_api;

extern const schedule_fn_t schedule_iquery_fn;
extern const schedule_api_t schedule_iquery_api;

extern const schedule_fn_t  schedule_scalable_fn;
extern const schedule_api_t schedule_scalable_api;

#ifdef ODP_SCHEDULE_SP
const schedule_fn_t *sched_fn   = &schedule_sp_fn;
const schedule_api_t *sched_api = &schedule_sp_api;
#elif defined(ODP_SCHEDULE_IQUERY)
const schedule_fn_t *sched_fn   = &schedule_iquery_fn;
const schedule_api_t *sched_api = &schedule_iquery_api;
#elif defined(ODP_SCHEDULE_SCALABLE)
const schedule_fn_t  *sched_fn  = &schedule_scalable_fn;
const schedule_api_t *sched_api = &schedule_scalable_api;
#else
const schedule_fn_t  *sched_fn  = &schedule_default_fn;
const schedule_api_t *sched_api = &schedule_default_api;
#endif

uint64_t odp_schedule_wait_time(uint64_t ns)
{
	return sched_api->schedule_wait_time(ns);
}

odp_event_t odp_schedule(odp_queue_t *from, uint64_t wait)
{
	return sched_api->schedule(from, wait);
}

int odp_schedule_multi(odp_queue_t *from, uint64_t wait, odp_event_t events[],
		       int num)
{
	return sched_api->schedule_multi(from, wait, events, num);
}

void odp_schedule_pause(void)
{
	return sched_api->schedule_pause();
}

void odp_schedule_resume(void)
{
	return sched_api->schedule_resume();
}

void odp_schedule_release_atomic(void)
{
	return sched_api->schedule_release_atomic();
}

void odp_schedule_release_ordered(void)
{
	return sched_api->schedule_release_ordered();
}

void odp_schedule_prefetch(int num)
{
	return sched_api->schedule_prefetch(num);
}

int odp_schedule_num_prio(void)
{
	return sched_api->schedule_num_prio();
}

odp_schedule_group_t odp_schedule_group_create(const char *name,
					       const odp_thrmask_t *mask)
{
	return sched_api->schedule_group_create(name, mask);
}

int odp_schedule_group_destroy(odp_schedule_group_t group)
{
	return sched_api->schedule_group_destroy(group);
}

odp_schedule_group_t odp_schedule_group_lookup(const char *name)
{
	return sched_api->schedule_group_lookup(name);
}

int odp_schedule_group_join(odp_schedule_group_t group,
			    const odp_thrmask_t *mask)
{
	return sched_api->schedule_group_join(group, mask);
}

int odp_schedule_group_leave(odp_schedule_group_t group,
			     const odp_thrmask_t *mask)
{
	return sched_api->schedule_group_leave(group, mask);
}

int odp_schedule_group_thrmask(odp_schedule_group_t group,
			       odp_thrmask_t *thrmask)
{
	return sched_api->schedule_group_thrmask(group, thrmask);
}

int odp_schedule_group_info(odp_schedule_group_t group,
			    odp_schedule_group_info_t *info)
{
	return sched_api->schedule_group_info(group, info);
}

void odp_schedule_order_lock(uint32_t lock_index)
{
	return sched_api->schedule_order_lock(lock_index);
}

void odp_schedule_order_unlock(uint32_t lock_index)
{
	return sched_api->schedule_order_unlock(lock_index);
}

void odp_schedule_order_unlock_lock(uint32_t unlock_index, uint32_t lock_index)
{
	sched_api->schedule_order_unlock_lock(unlock_index, lock_index);
}

void odp_schedule_order_lock_start(uint32_t lock_index)
{
	sched_api->schedule_order_lock_start(lock_index);
}

void odp_schedule_order_lock_wait(uint32_t lock_index)
{
	sched_api->schedule_order_lock_wait(lock_index);
}

