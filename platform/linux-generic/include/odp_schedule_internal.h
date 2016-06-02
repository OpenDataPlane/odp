/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_INTERNAL_H_
#define ODP_SCHEDULE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of dequeues */
#define MAX_DEQ 4

typedef struct {
	int thr;
	int num;
	int index;
	int pause;
	uint16_t round;
	uint16_t prefer_offset;
	uint16_t pktin_polls;
	odp_queue_t pri_queue;
	odp_event_t cmd_ev;
	odp_queue_t queue;
	odp_event_t ev_stash[MAX_DEQ];
	void *origin_qe;
	uint64_t order;
	uint64_t sync[SCHEDULE_ORDERED_LOCKS_PER_QUEUE];
	odp_pool_t pool;
	int enq_called;
	int ignore_ordered_context;
} sched_local_t;

extern __thread sched_local_t sched_local;

void cache_order_info(uint32_t queue_index);
int release_order(void *origin_qe, uint64_t order,
		  odp_pool_t pool, int enq_called);

/* API functions implemented in odp_schedule_ordered.c */
void schedule_order_lock(unsigned lock_index);
void schedule_order_unlock(unsigned lock_index);

#ifdef __cplusplus
}
#endif

#endif
