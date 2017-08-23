/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_SUBSYSTEM_H_
#define ODP_SCHEDULE_SUBSYSTEM_H_

/* API header files */
#include <odp/api/align.h>
#include <odp/api/schedule.h>

/* Internal header files */
#include <odp_module.h>

#define SCHEDULE_SUBSYSTEM_VERSION 0x00010000UL

ODP_SUBSYSTEM_DECLARE(schedule);

ODP_SUBSYSTEM_API(schedule, uint64_t, wait_time, uint64_t ns);
ODP_SUBSYSTEM_API(schedule, odp_event_t, schedule, odp_queue_t *from,
		  uint64_t wait);
ODP_SUBSYSTEM_API(schedule, int, schedule_multi, odp_queue_t *from,
		  uint64_t wait, odp_event_t events[], int num);
ODP_SUBSYSTEM_API(schedule, void, schedule_pause, void);
ODP_SUBSYSTEM_API(schedule, void, schedule_resume, void);
ODP_SUBSYSTEM_API(schedule, void, schedule_release_atomic, void);
ODP_SUBSYSTEM_API(schedule, void, schedule_release_ordered, void);
ODP_SUBSYSTEM_API(schedule, void, schedule_prefetch, int num);
ODP_SUBSYSTEM_API(schedule, int, schedule_num_prio, void);
ODP_SUBSYSTEM_API(schedule, odp_schedule_group_t, schedule_group_create,
		  const char *name, const odp_thrmask_t *mask);
ODP_SUBSYSTEM_API(schedule, int, schedule_group_destroy,
		  odp_schedule_group_t group);
ODP_SUBSYSTEM_API(schedule, odp_schedule_group_t, schedule_group_lookup,
		  const char *name);
ODP_SUBSYSTEM_API(schedule, int, schedule_group_join,
		  odp_schedule_group_t group, const odp_thrmask_t *mask);
ODP_SUBSYSTEM_API(schedule, int, schedule_group_leave,
		  odp_schedule_group_t group, const odp_thrmask_t *mask);
ODP_SUBSYSTEM_API(schedule, int, schedule_group_thrmask,
		  odp_schedule_group_t group, odp_thrmask_t *thrmask);
ODP_SUBSYSTEM_API(schedule, int, schedule_group_info,
		  odp_schedule_group_t group, odp_schedule_group_info_t *info);
ODP_SUBSYSTEM_API(schedule, void, schedule_order_lock, unsigned lock_index);
ODP_SUBSYSTEM_API(schedule, void, schedule_order_unlock, unsigned lock_index);

typedef ODP_MODULE_CLASS(schedule) {
	odp_module_base_t base;
	/* Called from CP threads */
	odp_api_proto(schedule, schedule_group_create) schedule_group_create;
	odp_api_proto(schedule, schedule_group_destroy) schedule_group_destroy;
	odp_api_proto(schedule, schedule_group_lookup) schedule_group_lookup;
	odp_api_proto(schedule, schedule_group_join) schedule_group_join;
	odp_api_proto(schedule, schedule_group_leave) schedule_group_leave;
	odp_api_proto(schedule, schedule_group_thrmask) schedule_group_thrmask;
	odp_api_proto(schedule, schedule_group_info) schedule_group_info;
	odp_api_proto(schedule, schedule_num_prio) schedule_num_prio;
	/* Called from DP threads */
	odp_api_proto(schedule, schedule) schedule ODP_ALIGNED_CACHE;
	odp_api_proto(schedule, schedule_multi) schedule_multi;
	odp_api_proto(schedule, schedule_prefetch) schedule_prefetch;
	odp_api_proto(schedule, schedule_order_lock) schedule_order_lock;
	odp_api_proto(schedule, schedule_order_unlock) schedule_order_unlock;
	odp_api_proto(schedule, schedule_release_atomic)
		schedule_release_atomic;
	odp_api_proto(schedule, schedule_release_ordered)
		schedule_release_ordered;
	odp_api_proto(schedule, wait_time) wait_time;
	odp_api_proto(schedule, schedule_pause) schedule_pause;
	odp_api_proto(schedule, schedule_resume) schedule_resume;
} odp_schedule_module_t;

#endif  /* ODP_SCHEDULE_SUBSYSTEM_H_ */
