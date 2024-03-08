/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2023 Nokia
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

_odp_queue_inline_offset_t _odp_queue_inline_offset ODP_ALIGNED_CACHE;
const _odp_queue_api_fn_t *_odp_queue_api;

#include <odp/visibility_end.h>

extern const _odp_queue_api_fn_t _odp_queue_scalable_api;
extern const queue_fn_t _odp_queue_scalable_fn;

extern const _odp_queue_api_fn_t _odp_queue_basic_api;
extern const queue_fn_t _odp_queue_basic_fn;

const queue_fn_t *_odp_queue_fn;

odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param)
{
	return _odp_queue_api->queue_create(name, param);
}

int odp_queue_create_multi(const char *name[], const odp_queue_param_t param[],
			   odp_bool_t share_param, odp_queue_t queue[], int num)
{
	return _odp_queue_api->queue_create_multi(name, param, share_param,
						  queue, num);
}

int odp_queue_destroy(odp_queue_t queue)
{
	return _odp_queue_api->queue_destroy(queue);
}

int odp_queue_destroy_multi(odp_queue_t queue[], int num)
{
	return _odp_queue_api->queue_destroy_multi(queue, num);
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
	_odp_queue_api->queue_param_init(param);
}

int odp_queue_info(odp_queue_t queue, odp_queue_info_t *info)
{
	return _odp_queue_api->queue_info(queue, info);
}

void odp_queue_print(odp_queue_t queue)
{
	_odp_queue_api->queue_print(queue);
}

void odp_queue_print_all(void)
{
	_odp_queue_api->queue_print_all();
}

int _odp_queue_init_global(void)
{
	const char *sched = getenv("ODP_SCHEDULER");

	if (sched == NULL || !strcmp(sched, "default"))
		sched = _ODP_SCHEDULE_DEFAULT;

	if (!strcmp(sched, "basic") || !strcmp(sched, "sp")) {
		_odp_queue_fn = &_odp_queue_basic_fn;
		_odp_queue_api = &_odp_queue_basic_api;
	} else if (!strcmp(sched, "scalable")) {
		_odp_queue_fn = &_odp_queue_scalable_fn;
		_odp_queue_api = &_odp_queue_scalable_api;
	} else {
		_ODP_ABORT("Unknown scheduler specified via ODP_SCHEDULER\n");
		return -1;
	}

	return _odp_queue_fn->init_global();
}

int _odp_queue_term_global(void)
{
	return _odp_queue_fn->term_global();
}
