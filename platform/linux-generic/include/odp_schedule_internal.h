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
	queue_entry_t *origin_qe;
	odp_buffer_hdr_t *buf_hdr[MAX_DEQ];
	uint64_t order;
	uint64_t sync[SCHEDULE_ORDERED_LOCKS_PER_QUEUE];
	odp_pool_t pool;
	int enq_called;
	int ignore_ordered_context;
} sched_local_t;

extern __thread sched_local_t sched_local;

#ifdef __cplusplus
}
#endif

#endif
