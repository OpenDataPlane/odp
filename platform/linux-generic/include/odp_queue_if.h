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

typedef int (*queue_init_global_fn_t)(void);
typedef int (*queue_term_global_fn_t)(void);
typedef int (*queue_init_local_fn_t)(void);
typedef int (*queue_term_local_fn_t)(void);
typedef int (*queue_enq_fn_t)(odp_queue_t queue, odp_buffer_hdr_t *buf_hdr);
typedef int (*queue_enq_multi_fn_t)(odp_queue_t queue,
				    odp_buffer_hdr_t **buf_hdr, int num);
typedef odp_buffer_hdr_t *(*queue_deq_fn_t)(odp_queue_t queue);
typedef int (*queue_deq_multi_fn_t)(odp_queue_t queue,
				    odp_buffer_hdr_t **buf_hdr, int num);
typedef odp_pktout_queue_t (*queue_get_pktout_fn_t)(odp_queue_t queue);
typedef void (*queue_set_pktout_fn_t)(odp_queue_t queue, odp_pktio_t pktio,
				      int index);
typedef odp_pktin_queue_t (*queue_get_pktin_fn_t)(odp_queue_t queue);
typedef void (*queue_set_pktin_fn_t)(odp_queue_t queue, odp_pktio_t pktio,
				     int index);
typedef void (*queue_set_enq_deq_fn_t)(odp_queue_t queue,
				       queue_enq_fn_t enq,
				       queue_enq_multi_fn_t enq_multi,
				       queue_deq_fn_t deq,
				       queue_deq_multi_fn_t deq_multi);

/* Queue functions towards other internal components */
typedef struct {
	queue_init_global_fn_t init_global;
	queue_term_global_fn_t term_global;
	queue_init_local_fn_t init_local;
	queue_term_local_fn_t term_local;
	queue_enq_fn_t enq;
	queue_enq_multi_fn_t enq_multi;
	queue_deq_fn_t deq;
	queue_deq_multi_fn_t deq_multi;
	queue_get_pktout_fn_t get_pktout;
	queue_set_pktout_fn_t set_pktout;
	queue_get_pktin_fn_t get_pktin;
	queue_set_pktin_fn_t set_pktin;
	queue_set_enq_deq_fn_t set_enq_deq_fn;
} queue_fn_t;

extern const queue_fn_t *queue_fn;

#ifdef __cplusplus
}
#endif

#endif
