/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_IF_H_
#define ODP_SCHEDULE_IF_H_

#include <odp/api/queue.h>
#include <odp_queue_if.h>
#include <odp/api/schedule.h>

typedef struct schedule_fn_t {
	int status_sync;
	void (*pktio_start)(int pktio_index, int num_in_queue,
			    int in_queue_idx[]);
	int (*thr_add)(odp_schedule_group_t group, int thr);
	int (*thr_rem)(odp_schedule_group_t group, int thr);
	int (*num_grps)(void);
	int (*init_queue)(uint32_t queue_index,
			  const odp_schedule_param_t *sched_param);
	void (*destroy_queue)(uint32_t queue_index);
	int (*sched_queue)(uint32_t queue_index);
	int (*ord_enq_multi)(queue_t q_int, void *buf_hdr[], int num, int *ret);
	void (*order_lock)(void);
	void (*order_unlock)(void);
	unsigned (*max_ordered_locks)(void);

	/* Called only when status_sync is set */
	int (*unsched_queue)(uint32_t queue_index);
	void (*save_context)(uint32_t queue_index);
} schedule_fn_t;

extern const schedule_fn_t *sched_fn;

#endif
