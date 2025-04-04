/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2025 Nokia
 */

#ifndef ODP_PLAT_SCHEDULE_INLINE_TYPES_H_
#define ODP_PLAT_SCHEDULE_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/schedule_types.h>
#include <odp/api/thrmask.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Schedule API functions */
typedef struct {
	uint64_t (*schedule_wait_time)(uint64_t ns);
	int (*schedule_capability)(odp_schedule_capability_t *capa);
	void (*schedule_config_init)(odp_schedule_config_t *config);
	int (*schedule_config)(const odp_schedule_config_t *config);
	odp_event_t (*schedule)(odp_queue_t *from, uint64_t wait);
	int (*schedule_multi)(odp_queue_t *from, uint64_t wait, odp_event_t events[], int num);
	int (*schedule_multi_wait)(odp_queue_t *from, odp_event_t events[], int num);
	int (*schedule_multi_no_wait)(odp_queue_t *from, odp_event_t events[], int num);
	void (*schedule_pause)(void);
	void (*schedule_resume)(void);
	void (*schedule_release_atomic)(void);
	void (*schedule_release_ordered)(void);
	void (*schedule_prefetch)(int num);
	int (*schedule_min_prio)(void);
	int (*schedule_max_prio)(void);
	int (*schedule_default_prio)(void);
	int (*schedule_num_prio)(void);
	int (*schedule_group_min_prio)(odp_schedule_group_t group);
	int (*schedule_group_max_prio)(odp_schedule_group_t group);
	int (*schedule_group_default_prio)(odp_schedule_group_t group);
	int (*schedule_group_num_prio)(odp_schedule_group_t group);
	odp_schedule_group_t (*schedule_group_create)(const char *name, const odp_thrmask_t *mask);
	odp_schedule_group_t (*schedule_group_create_2)(const char *name,
							const odp_thrmask_t *mask,
							const odp_schedule_group_param_t *param);
	int (*schedule_group_destroy)(odp_schedule_group_t group);
	odp_schedule_group_t (*schedule_group_lookup)(const char *name);
	int (*schedule_group_join)(odp_schedule_group_t group, const odp_thrmask_t *mask);
	int (*schedule_group_leave)(odp_schedule_group_t group, const odp_thrmask_t *mask);
	int (*schedule_group_thrmask)(odp_schedule_group_t group, odp_thrmask_t *mask);
	int (*schedule_group_info)(odp_schedule_group_t group, odp_schedule_group_info_t *info);
	void (*schedule_order_lock)(uint32_t lock_index);
	void (*schedule_order_unlock)(uint32_t lock_index);
	void (*schedule_order_unlock_lock)(uint32_t unlock_index, uint32_t lock_index);
	void (*schedule_order_lock_start)(uint32_t lock_index);
	void (*schedule_order_lock_wait)(uint32_t lock_index);
	void (*schedule_order_wait)(void);
	void (*schedule_print)(void);

} _odp_schedule_api_fn_t;

/* Scheduler configuration status */
int _odp_schedule_configured(void);

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
