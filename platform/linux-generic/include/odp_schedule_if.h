/* Copyright (c) 2013, Linaro Limited
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
#include <odp/api/schedule.h>

/* Constants defined by the scheduler. These should be converted into interface
 * functions. */

/* Number of ordered locks per queue */
#define SCHEDULE_ORDERED_LOCKS_PER_QUEUE 2

typedef void (*schedule_pktio_start_fn_t)(int pktio_index, int num_in_queue,
					  int in_queue_idx[]);
typedef int (*schedule_thr_add_fn_t)(odp_schedule_group_t group, int thr);
typedef int (*schedule_thr_rem_fn_t)(odp_schedule_group_t group, int thr);
typedef int (*schedule_num_grps_fn_t)(void);
typedef int (*schedule_init_queue_fn_t)(uint32_t queue_index,
					const odp_schedule_param_t *sched_param
				       );
typedef void (*schedule_destroy_queue_fn_t)(uint32_t queue_index);
typedef int (*schedule_sched_queue_fn_t)(uint32_t queue_index);
typedef int (*schedule_ord_enq_fn_t)(uint32_t queue_index, void *buf_hdr,
				     int sustain, int *ret);
typedef int (*schedule_ord_enq_multi_fn_t)(uint32_t queue_index,
					   void *buf_hdr[], int num,
					   int sustain, int *ret);
typedef int (*schedule_init_global_fn_t)(void);
typedef int (*schedule_term_global_fn_t)(void);
typedef int (*schedule_init_local_fn_t)(void);
typedef int (*schedule_term_local_fn_t)(void);

typedef struct schedule_fn_t {
	schedule_pktio_start_fn_t   pktio_start;
	schedule_thr_add_fn_t       thr_add;
	schedule_thr_rem_fn_t       thr_rem;
	schedule_num_grps_fn_t      num_grps;
	schedule_init_queue_fn_t    init_queue;
	schedule_destroy_queue_fn_t destroy_queue;
	schedule_sched_queue_fn_t   sched_queue;
	schedule_ord_enq_fn_t       ord_enq;
	schedule_ord_enq_multi_fn_t ord_enq_multi;
	schedule_init_global_fn_t   init_global;
	schedule_term_global_fn_t   term_global;
	schedule_init_local_fn_t    init_local;
	schedule_term_local_fn_t    term_local;
} schedule_fn_t;

/* Interface towards the scheduler */
extern const schedule_fn_t *sched_fn;

/* Interface for the scheduler */
int sched_cb_pktin_poll(int pktio_index, int num_queue, int index[]);
int sched_cb_num_pktio(void);
int sched_cb_num_queues(void);
int sched_cb_queue_prio(uint32_t queue_index);
int sched_cb_queue_grp(uint32_t queue_index);
int sched_cb_queue_is_ordered(uint32_t queue_index);
int sched_cb_queue_is_atomic(uint32_t queue_index);
odp_queue_t sched_cb_queue_handle(uint32_t queue_index);
void sched_cb_queue_destroy_finalize(uint32_t queue_index);
int sched_cb_queue_deq_multi(uint32_t queue_index, odp_event_t ev[], int num);
int sched_cb_queue_empty(uint32_t queue_index);

/* API functions */
typedef struct {
	uint64_t (*schedule_wait_time)(uint64_t);
	odp_event_t (*schedule)(odp_queue_t *, uint64_t);
	int (*schedule_multi)(odp_queue_t *, uint64_t, odp_event_t [], int);
	void (*schedule_pause)(void);
	void (*schedule_resume)(void);
	void (*schedule_release_atomic)(void);
	void (*schedule_release_ordered)(void);
	void (*schedule_prefetch)(int);
	int (*schedule_num_prio)(void);
	odp_schedule_group_t (*schedule_group_create)(const char *,
						      const odp_thrmask_t *);
	int (*schedule_group_destroy)(odp_schedule_group_t);
	odp_schedule_group_t (*schedule_group_lookup)(const char *);
	int (*schedule_group_join)(odp_schedule_group_t, const odp_thrmask_t *);
	int (*schedule_group_leave)(odp_schedule_group_t,
				    const odp_thrmask_t *);
	int (*schedule_group_thrmask)(odp_schedule_group_t, odp_thrmask_t *);
	int (*schedule_group_info)(odp_schedule_group_t,
				   odp_schedule_group_info_t *);
	void (*schedule_order_lock)(unsigned);
	void (*schedule_order_unlock)(unsigned);

} schedule_api_t;

#ifdef __cplusplus
}
#endif

#endif
