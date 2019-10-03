/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>

#include <odp_queue_if.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>

#include <stdlib.h>
#include <string.h>

#include <odp/api/align.h>
#include <odp/api/plat/queue_inline_types.h>

#include <odp/visibility_begin.h>

_odp_queue_inline_offset_t ODP_ALIGNED_CACHE _odp_queue_inline_offset;
const _odp_queue_api_fn_t *_odp_queue_api;

#include <odp/visibility_end.h>

extern const _odp_queue_api_fn_t queue_scalable_api;
extern const queue_fn_t queue_scalable_fn;

extern const _odp_queue_api_fn_t queue_basic_api;
extern const queue_fn_t queue_basic_fn;

const queue_fn_t *queue_fn;

odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param)
{
	return _odp_queue_api->queue_create(name, param);
}

int odp_queue_destroy(odp_queue_t queue)
{
	return _odp_queue_api->queue_destroy(queue);
}

odp_queue_t odp_queue_lookup(const char *name)
{
	return _odp_queue_api->queue_lookup(name);
}

int odp_queue_capability(odp_queue_capability_t *capa)
{
	return _odp_queue_api->queue_capability(capa);
}

int odp_queue_context_set(odp_queue_t queue, void *context, uint32_t len)
{
	return _odp_queue_api->queue_context_set(queue, context, len);
}

odp_queue_type_t odp_queue_type(odp_queue_t queue)
{
	return _odp_queue_api->queue_type(queue);
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t queue)
{
	return _odp_queue_api->queue_sched_type(queue);
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t queue)
{
	return _odp_queue_api->queue_sched_prio(queue);
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t queue)
{
	return _odp_queue_api->queue_sched_group(queue);
}

uint32_t odp_queue_lock_count(odp_queue_t queue)
{
	return _odp_queue_api->queue_lock_count(queue);
}

uint64_t odp_queue_to_u64(odp_queue_t hdl)
{
	return _odp_queue_api->queue_to_u64(hdl);
}

void odp_queue_param_init(odp_queue_param_t *param)
{
	return _odp_queue_api->queue_param_init(param);
}

int odp_queue_info(odp_queue_t queue, odp_queue_info_t *info)
{
	return _odp_queue_api->queue_info(queue, info);
}

int _odp_queue_init_global(void)
{
	const char *sched = getenv("ODP_SCHEDULER");

	if (sched == NULL || !strcmp(sched, "default"))
		sched = _ODP_SCHEDULE_DEFAULT;

	if (!strcmp(sched, "basic") || !strcmp(sched, "sp")) {
		queue_fn = &queue_basic_fn;
		_odp_queue_api = &queue_basic_api;
	} else if (!strcmp(sched, "scalable")) {
		queue_fn = &queue_scalable_fn;
		_odp_queue_api = &queue_scalable_api;
	} else {
		ODP_ABORT("Unknown scheduler specified via ODP_SCHEDULER\n");
		return -1;
	}

	return queue_fn->init_global();
}

int _odp_queue_term_global(void)
{
	return queue_fn->term_global();
}
