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


#include <odp/buffer.h>
#include <odp_buffer_internal.h>
#include <odp/queue.h>
#include <odp/packet_io.h>
#include <odp_queue_internal.h>


int schedule_queue_init(queue_entry_t *qe);
void schedule_queue_destroy(queue_entry_t *qe);

static inline int schedule_queue(const queue_entry_t *qe)
{
	return odp_queue_enq(qe->s.pri_queue, qe->s.cmd_ev);
}

int schedule_pktio_start(odp_pktio_t pktio, int prio);
void odp_schedule_release_context(void);

#ifdef __cplusplus
}
#endif

#endif
