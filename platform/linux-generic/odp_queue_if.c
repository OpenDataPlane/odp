/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_queue_if.h>

extern const queue_api_t queue_default_api;
extern const queue_fn_t queue_default_fn;

const queue_api_t *queue_api = &queue_default_api;
const queue_fn_t *queue_fn = &queue_default_fn;

odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param)
{
	return queue_api->queue_create(name, param);
}

int odp_queue_destroy(odp_queue_t queue)
{
	return queue_api->queue_destroy(queue);
}

odp_queue_t odp_queue_lookup(const char *name)
{
	return queue_api->queue_lookup(name);
}

int odp_queue_capability(odp_queue_capability_t *capa)
{
	return queue_api->queue_capability(capa);
}

int odp_queue_context_set(odp_queue_t queue, void *context, uint32_t len)
{
	return queue_api->queue_context_set(queue, context, len);
}

void *odp_queue_context(odp_queue_t queue)
{
	return queue_api->queue_context(queue);
}

int odp_queue_enq(odp_queue_t queue, odp_event_t ev)
{
	return queue_api->queue_enq(queue, ev);
}

int odp_queue_enq_multi(odp_queue_t queue, const odp_event_t events[], int num)
{
	return queue_api->queue_enq_multi(queue, events, num);
}

odp_event_t odp_queue_deq(odp_queue_t queue)
{
	return queue_api->queue_deq(queue);
}

int odp_queue_deq_multi(odp_queue_t queue, odp_event_t events[], int num)
{
	return queue_api->queue_deq_multi(queue, events, num);
}

odp_queue_type_t odp_queue_type(odp_queue_t queue)
{
	return queue_api->queue_type(queue);
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t queue)
{
	return queue_api->queue_sched_type(queue);
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t queue)
{
	return queue_api->queue_sched_prio(queue);
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t queue)
{
	return queue_api->queue_sched_group(queue);
}

int odp_queue_lock_count(odp_queue_t queue)
{
	return queue_api->queue_lock_count(queue);
}

uint64_t odp_queue_to_u64(odp_queue_t hdl)
{
	return queue_api->queue_to_u64(hdl);
}

void odp_queue_param_init(odp_queue_param_t *param)
{
	return queue_api->queue_param_init(param);
}

int odp_queue_info(odp_queue_t queue, odp_queue_info_t *info)
{
	return queue_api->queue_info(queue, info);
}
