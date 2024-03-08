/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2023 Nokia
 */

#ifndef ODP_PLAT_QUEUE_INLINE_TYPES_H_
#define ODP_PLAT_QUEUE_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/api/event_types.h>
#include <odp/api/queue_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Queue entry field accessor */
#define _odp_qentry_field(qentry, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)qentry + \
	 _odp_queue_inline_offset.field))

/* Queue entry field offsets for inline functions */
typedef struct _odp_queue_inline_offset_t {
	uint16_t context;

} _odp_queue_inline_offset_t;

/* Queue API functions */
typedef struct {
	odp_queue_t (*queue_create)(const char *name,
				    const odp_queue_param_t *param);
	int (*queue_create_multi)(const char *name[],
				  const odp_queue_param_t param[],
				  odp_bool_t share_param, odp_queue_t queue[],
				  int num);
	int (*queue_destroy)(odp_queue_t queue);
	int (*queue_destroy_multi)(odp_queue_t queue[], int num);
	odp_queue_t (*queue_lookup)(const char *name);
	int (*queue_capability)(odp_queue_capability_t *capa);
	int (*queue_context_set)(odp_queue_t queue, void *context,
				 uint32_t len);
	int (*queue_enq)(odp_queue_t queue, odp_event_t ev);
	int (*queue_enq_multi)(odp_queue_t queue, const odp_event_t events[],
			       int num);
	odp_event_t (*queue_deq)(odp_queue_t queue);
	int (*queue_deq_multi)(odp_queue_t queue, odp_event_t events[],
			       int num);
	odp_queue_type_t (*queue_type)(odp_queue_t queue);
	odp_schedule_sync_t (*queue_sched_type)(odp_queue_t queue);
	odp_schedule_prio_t (*queue_sched_prio)(odp_queue_t queue);
	odp_schedule_group_t (*queue_sched_group)(odp_queue_t queue);
	uint32_t (*queue_lock_count)(odp_queue_t queue);
	uint64_t (*queue_to_u64)(odp_queue_t queue);
	void (*queue_param_init)(odp_queue_param_t *param);
	int (*queue_info)(odp_queue_t queue, odp_queue_info_t *info);
	void (*queue_print)(odp_queue_t queue);
	void (*queue_print_all)(void);

} _odp_queue_api_fn_t;

extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
