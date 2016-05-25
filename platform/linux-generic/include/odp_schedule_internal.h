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


#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp/api/queue.h>
#include <odp/api/packet_io.h>
#include <odp_queue_internal.h>

int schedule_queue_init(queue_entry_t *qe);
void schedule_queue_destroy(queue_entry_t *qe);
int schedule_queue(const queue_entry_t *qe);

typedef void (*schedule_pktio_start_fn_t)(odp_pktio_t pktio, int num_in_queue,
					  int in_queue_idx[]);

typedef struct schedule_fn_t {
	schedule_pktio_start_fn_t pktio_start;

} schedule_fn_t;

/* Interface towards the scheduler */
extern const schedule_fn_t *sched_fn;


#ifdef __cplusplus
}
#endif

#endif
