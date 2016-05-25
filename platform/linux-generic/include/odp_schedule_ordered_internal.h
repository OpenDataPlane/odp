/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_ORDERED_INTERNAL_H_
#define ODP_SCHEDULE_ORDERED_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SUSTAIN_ORDER 1

int schedule_ordered_queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr,
			       int sustain, int *ret);
int schedule_ordered_queue_enq_multi(queue_entry_t *queue,
				     odp_buffer_hdr_t *buf_hdr[],
				     int num, int sustain, int *ret);
int release_order(queue_entry_t *origin_qe, uint64_t order,
		  odp_pool_t pool, int enq_called);
void get_sched_order(queue_entry_t **origin_qe, uint64_t *order);
void sched_enq_called(void);
void sched_order_resolved(odp_buffer_hdr_t *buf_hdr);

#ifdef __cplusplus
}
#endif

#endif
