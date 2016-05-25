/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */



#ifndef ODP_SCHEDULE_INTERNAL_H_
#define ODP_SCHEDULE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>
#include <odp/api/packet_io.h>
#include <odp_forward_typedefs_internal.h>

/* Constants defined by the scheduler. These should be converted into interface
 * functions. */

/* Number of ordered locks per queue */
#define SCHEDULE_ORDERED_LOCKS_PER_QUEUE 2

typedef void (*schedule_pktio_start_fn_t)(odp_pktio_t pktio, int num_in_queue,
					  int in_queue_idx[]);
typedef int (*schedule_thr_add_fn_t)(odp_schedule_group_t group, int thr);
typedef int (*schedule_thr_rem_fn_t)(odp_schedule_group_t group, int thr);
typedef int (*schedule_num_grps_fn_t)(void);
typedef int (*schedule_init_queue_fn_t)(uint32_t queue_index);
typedef void (*schedule_destroy_queue_fn_t)(uint32_t queue_index);
typedef int (*schedule_sched_queue_fn_t)(uint32_t queue_index);


typedef struct schedule_fn_t {
	schedule_pktio_start_fn_t   pktio_start;
	schedule_thr_add_fn_t       thr_add;
	schedule_thr_rem_fn_t       thr_rem;
	schedule_num_grps_fn_t      num_grps;
	schedule_init_queue_fn_t    init_queue;
	schedule_destroy_queue_fn_t destroy_queue;
	schedule_sched_queue_fn_t   sched_queue;

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

#ifdef __cplusplus
}
#endif

#endif
