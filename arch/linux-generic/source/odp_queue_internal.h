/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP queue - implementation internal
 */

#ifndef ODP_QUEUE_INTERNAL_H_
#define ODP_QUEUE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue.h>
#include <odp_buffer_internal.h>
#include <odp_packet_io.h>
#include <odp_spinlock.h>
#include <odp_align.h>

#define QUEUE_STATUS_FREE     0
#define QUEUE_STATUS_READY    1
#define QUEUE_STATUS_NOTSCHED 2
#define QUEUE_STATUS_SCHED    3

/* forward declaration */
union queue_entry_u;

typedef int (*enqueue_func_t)(union queue_entry_u *, odp_buffer_hdr_t *);
typedef	odp_buffer_hdr_t *(*dequeue_func_t)(union queue_entry_u *);

struct queue_entry_s {
	odp_spinlock_t    lock ODP_ALIGNED_CACHE;
	enqueue_func_t    enqueue ODP_ALIGNED_CACHE;
	dequeue_func_t    dequeue;
	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	odp_queue_t       handle;
	odp_queue_type_t  type;
	int               status;
	odp_queue_param_t param;
	odp_pktio_t       pktin;
	odp_pktio_t       pktout;
	char              name[ODP_QUEUE_NAME_LEN];
};

typedef union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];
} queue_entry_t;


queue_entry_t *get_qentry(uint32_t queue_id);
odp_queue_t to_qhandle(uint32_t queue_id);
uint32_t from_qhandle(odp_queue_t handle);

/* local function prototypes */
int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *queue_deq(queue_entry_t *queue);

#ifdef __cplusplus
}
#endif

#endif

