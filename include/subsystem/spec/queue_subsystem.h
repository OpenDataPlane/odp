/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef ODP_QUEUE_SUBSYSTEM_H
#define ODP_QUEUE_SUBSYSTEM_H
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_module.h>
#include <odp/api/queue.h>

#define QUEUE_SUBSYSTEM_VERSION 0x00010000UL

/* ODP queue public APIs subsystem */
ODP_SUBSYSTEM_DECLARE(queue);

/* Subsystem APIs declarations */
ODP_SUBSYSTEM_API(queue, odp_queue_t, create, const char *name,
		  const odp_queue_param_t *param);
ODP_SUBSYSTEM_API(queue, int, destroy, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, odp_queue_t, lookup, const char *name);
ODP_SUBSYSTEM_API(queue, int, capability, odp_queue_capability_t *capa);
ODP_SUBSYSTEM_API(queue, int, context_set, odp_queue_t queue,
		  void *context, uint32_t len);
ODP_SUBSYSTEM_API(queue, void *, context, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, int, enq, odp_queue_t queue, odp_event_t ev);
ODP_SUBSYSTEM_API(queue, int, enq_multi, odp_queue_t queue,
		  const odp_event_t events[], int num);
ODP_SUBSYSTEM_API(queue, odp_event_t, deq, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, int, deq_multi, odp_queue_t queue,
		  odp_event_t events[], int num);
ODP_SUBSYSTEM_API(queue, odp_queue_type_t, type, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, odp_schedule_sync_t, sched_type, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, odp_schedule_prio_t, sched_prio, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, odp_schedule_group_t, sched_group,
		  odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, uint32_t, lock_count, odp_queue_t queue);
ODP_SUBSYSTEM_API(queue, uint64_t, to_u64, odp_queue_t hdl);
ODP_SUBSYSTEM_API(queue, void, param_init, odp_queue_param_t *param);
ODP_SUBSYSTEM_API(queue, int, info, odp_queue_t queue,
		  odp_queue_info_t *info);

typedef ODP_MODULE_CLASS(queue) {
	odp_module_base_t base;

	odp_api_proto(queue, enq_multi) enq_multi;
	odp_api_proto(queue, deq_multi) deq_multi;
	odp_api_proto(queue, enq) enq;
	odp_api_proto(queue, deq) deq;
	odp_api_proto(queue, context) context;
	odp_api_proto(queue, sched_type) sched_type;
	odp_api_proto(queue, sched_prio) sched_prio;
	odp_api_proto(queue, sched_group) sched_group;
	odp_api_proto(queue, create) create;
	odp_api_proto(queue, destroy) destroy;
	odp_api_proto(queue, lookup) lookup;
	odp_api_proto(queue, capability) capability;
	odp_api_proto(queue, context_set) context_set;
	odp_api_proto(queue, type) type;
	odp_api_proto(queue, lock_count) lock_count;
	odp_api_proto(queue, to_u64) to_u64;
	odp_api_proto(queue, param_init) param_init;
	odp_api_proto(queue, info) info;
} odp_queue_module_t;

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
