/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_IF_H_
#define ODP_SCHEDULE_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>
#include <odp_queue_if.h>
#include <odp/api/schedule.h>
#include <odp_forward_typedefs_internal.h>

/* Number of ordered locks per queue */
#define SCHEDULE_ORDERED_LOCKS_PER_QUEUE 2

typedef struct schedule_config_t {
	struct {
		int all;
		int worker;
		int control;
	} group_enable;

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
typedef int (*schedule_ord_enq_multi_fn_t)(odp_queue_t queue,
					   void *buf_hdr[], int num, int *ret);
typedef int (*schedule_init_global_fn_t)(void);
typedef int (*schedule_term_global_fn_t)(void);
typedef int (*schedule_init_local_fn_t)(void);
typedef int (*schedule_term_local_fn_t)(void);
typedef void (*schedule_order_lock_fn_t)(void);
typedef void (*schedule_order_unlock_fn_t)(void);
typedef void (*schedule_order_unlock_lock_fn_t)(void);
typedef void (*schedule_order_lock_start_fn_t)(void);
typedef void (*schedule_order_lock_wait_fn_t)(void);
typedef uint32_t (*schedule_max_ordered_locks_fn_t)(void);
typedef void (*schedule_get_config_fn_t)(schedule_config_t *config);

typedef struct schedule_fn_t {
	schedule_pktio_start_fn_t   pktio_start;
	schedule_thr_add_fn_t       thr_add;
	schedule_thr_rem_fn_t       thr_rem;
	schedule_num_grps_fn_t      num_grps;
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
	schedule_order_lock_start_fn_t	start_order_lock;
	schedule_order_lock_wait_fn_t	wait_order_lock;
	schedule_order_unlock_lock_fn_t  order_unlock_lock;
	schedule_max_ordered_locks_fn_t max_ordered_locks;
	schedule_get_config_fn_t        get_config;

} schedule_fn_t;

/* Interface towards the scheduler */
extern const schedule_fn_t *sched_fn;

/* Interface for the scheduler */
int sched_cb_pktin_poll(int pktio_index, int pktin_index,
			odp_buffer_hdr_t *hdr_tbl[], int num);
int sched_cb_pktin_poll_one(int pktio_index, int rx_queue, odp_event_t evts[]);
void sched_cb_pktio_stop_finalize(int pktio_index);

/* For debugging */
extern int _odp_schedule_configured;

/* API functions */
typedef struct {
	uint64_t (*schedule_wait_time)(uint64_t ns);
	int (*schedule_capability)(odp_schedule_capability_t *capa);
	void (*schedule_config_init)(odp_schedule_config_t *config);
	int (*schedule_config)(const odp_schedule_config_t *config);
	odp_event_t (*schedule)(odp_queue_t *from, uint64_t wait);
	int (*schedule_multi)(odp_queue_t *from, uint64_t wait,
			      odp_event_t events[], int num);
	int (*schedule_multi_wait)(odp_queue_t *from, odp_event_t events[],
				   int num);
	int (*schedule_multi_no_wait)(odp_queue_t *from, odp_event_t events[],
				      int num);
	void (*schedule_pause)(void);
	void (*schedule_resume)(void);
	void (*schedule_release_atomic)(void);
	void (*schedule_release_ordered)(void);
	void (*schedule_prefetch)(int num);
	int (*schedule_min_prio)(void);
	int (*schedule_max_prio)(void);
	int (*schedule_default_prio)(void);
	int (*schedule_num_prio)(void);
	odp_schedule_group_t (*schedule_group_create)
		(const char *name, const odp_thrmask_t *mask);
	int (*schedule_group_destroy)(odp_schedule_group_t group);
	odp_schedule_group_t (*schedule_group_lookup)(const char *name);
	int (*schedule_group_join)(odp_schedule_group_t group,
				   const odp_thrmask_t *mask);
	int (*schedule_group_leave)(odp_schedule_group_t group,
				    const odp_thrmask_t *mask);
	int (*schedule_group_thrmask)(odp_schedule_group_t group,
				      odp_thrmask_t *mask);
	int (*schedule_group_info)(odp_schedule_group_t group,
				   odp_schedule_group_info_t *info);
	void (*schedule_order_lock)(uint32_t lock_index);
	void (*schedule_order_unlock)(uint32_t lock_index);
	void (*schedule_order_unlock_lock)(uint32_t unlock_index,
					   uint32_t lock_index);
	void (*schedule_order_lock_start)(uint32_t lock_index);
	void (*schedule_order_lock_wait)(uint32_t lock_index);

} schedule_api_t;

#ifdef __cplusplus
}
#endif

#endif
