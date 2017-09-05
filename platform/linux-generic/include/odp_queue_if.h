/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_QUEUE_IF_H_
#define ODP_QUEUE_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>
#include <odp/api/schedule.h>
#include <odp/api/packet_io.h>
#include <odp_forward_typedefs_internal.h>

#define QUEUE_MULTI_MAX CONFIG_BURST_SIZE

/* Internal abstract queue handle */
typedef struct { char dummy; } _queue_t;
typedef _queue_t *queue_t;

#define QUEUE_NULL ((queue_t)NULL)

typedef int (*queue_enq_fn_t)(queue_t q_int, odp_buffer_hdr_t *);
typedef int (*queue_enq_multi_fn_t)(queue_t q_int, odp_buffer_hdr_t **, int);
typedef odp_buffer_hdr_t *(*queue_deq_fn_t)(queue_t q_int);
typedef int (*queue_deq_multi_fn_t)(queue_t q_int, odp_buffer_hdr_t **, int);

/* Queue functions towards other internal components */
typedef struct {
	queue_t (*from_ext)(odp_queue_t handle);
	odp_queue_t (*to_ext)(queue_t q_int);
	queue_enq_fn_t enq;
	queue_enq_multi_fn_t enq_multi;
	queue_deq_fn_t deq;
	queue_deq_multi_fn_t deq_multi;
	odp_pktout_queue_t (*get_pktout)(queue_t q_int);
	void (*set_pktout)(queue_t q_int, odp_pktio_t pktio, int index);
	odp_pktin_queue_t (*get_pktin)(queue_t q_int);
	void (*set_pktin)(queue_t q_int, odp_pktio_t pktio, int index);
	void (*set_enq_deq_fn)(queue_t q_int, queue_enq_fn_t enq,
			       queue_enq_multi_fn_t enq_multi,
			       queue_deq_fn_t deq,
			       queue_deq_multi_fn_t deq_multi);
} queue_fn_t;

extern const queue_fn_t *queue_fn;

#ifdef __cplusplus
}
#endif

#endif
