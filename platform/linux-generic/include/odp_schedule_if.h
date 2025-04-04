/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#ifndef ODP_SCHEDULE_IF_H_
#define ODP_SCHEDULE_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>
#include <odp/api/schedule.h>
#include <odp/api/plat/schedule_inline_types.h>

#include <odp_event_internal.h>
#include <odp_queue_if.h>

#define _ODP_SCHED_ID_BASIC    0
#define _ODP_SCHED_ID_SP       1

/* Scheduler identifier */
extern int _odp_sched_id;

typedef struct schedule_config_t {
	struct {
		int all;
		int worker;
		int control;
	} group_enable;

	uint32_t max_groups;
	uint32_t max_group_prios;
	uint32_t max_prios;
	int min_prio;
	int max_prio;
	int def_prio;

} schedule_config_t;

typedef void (*schedule_pktio_start_fn_t)(int pktio_index,
					 int num_in_queue,
					 int in_queue_idx[],
					 odp_queue_t odpq[]);
typedef int (*schedule_thr_add_fn_t)(odp_schedule_group_t group, int thr);
typedef int (*schedule_thr_rem_fn_t)(odp_schedule_group_t group, int thr);
typedef int (*schedule_num_grps_fn_t)(void);
typedef int (*schedule_create_queue_fn_t)(uint32_t queue_index,
					  const odp_schedule_param_t *param);
typedef void (*schedule_destroy_queue_fn_t)(uint32_t queue_index);
typedef int (*schedule_sched_queue_fn_t)(uint32_t queue_index);
typedef int (*schedule_unsched_queue_fn_t)(uint32_t queue_index);
typedef int (*schedule_ord_enq_multi_fn_t)(odp_queue_t queue, void *event_hdr[],
					   int num, int *ret);
typedef int (*schedule_init_global_fn_t)(void);
typedef int (*schedule_term_global_fn_t)(void);
typedef int (*schedule_init_local_fn_t)(void);
typedef int (*schedule_term_local_fn_t)(void);
typedef void (*schedule_order_lock_fn_t)(void);
typedef void (*schedule_order_unlock_fn_t)(void);
typedef void (*schedule_order_unlock_lock_fn_t)(void);
typedef uint32_t (*schedule_max_ordered_locks_fn_t)(void);
typedef void (*schedule_get_config_fn_t)(schedule_config_t *config);
typedef const _odp_schedule_api_fn_t *(*schedule_sched_api_fn_t)(void);

typedef struct schedule_fn_t {
	schedule_pktio_start_fn_t   pktio_start;
	schedule_thr_add_fn_t       thr_add;
	schedule_thr_rem_fn_t       thr_rem;
	schedule_create_queue_fn_t  create_queue;
	schedule_destroy_queue_fn_t destroy_queue;
	schedule_sched_queue_fn_t   sched_queue;
	schedule_ord_enq_multi_fn_t ord_enq_multi;
	schedule_init_global_fn_t   init_global;
	schedule_term_global_fn_t   term_global;
	schedule_init_local_fn_t    init_local;
	schedule_term_local_fn_t    term_local;
	schedule_order_lock_fn_t    order_lock;
	schedule_order_unlock_fn_t  order_unlock;
	schedule_order_unlock_lock_fn_t order_unlock_lock;
	schedule_max_ordered_locks_fn_t max_ordered_locks;
	schedule_get_config_fn_t        get_config;
	schedule_sched_api_fn_t		sched_api;

} schedule_fn_t;

/* Interface towards the scheduler */
extern const schedule_fn_t *_odp_sched_fn;

/* Interface for the scheduler */
int _odp_sched_cb_pktin_poll(int pktio_index, int pktin_index,
			     _odp_event_hdr_t *hdr_tbl[], int num);
void _odp_sched_cb_pktio_stop_finalize(int pktio_index);

#ifdef __cplusplus
}
#endif

#endif
