/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_QUEUE_INTERNAL_H_
#define ODP_QUEUE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>
#include <odp/api/queue.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_queue_if.h>
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp_config_internal.h>
#include <odp_ring_st_internal.h>
#include <odp_queue_lf.h>

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_DESTROYED    1
#define QUEUE_STATUS_READY        2
#define QUEUE_STATUS_NOTSCHED     3
#define QUEUE_STATUS_SCHED        4

struct queue_entry_s {
	odp_ticketlock_t  ODP_ALIGNED_CACHE lock;
	ring_st_t         ring_st;
	int               status;

	queue_enq_fn_t       ODP_ALIGNED_CACHE enqueue;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;

	uint32_t          index;
	odp_queue_t       handle;
	odp_queue_type_t  type;
	odp_queue_param_t param;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	void             *queue_lf;
	char              name[ODP_QUEUE_NAME_LEN];
};

union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct queue_entry_s))];
};

typedef struct queue_global_t {
	queue_entry_t   queue[ODP_CONFIG_QUEUES];
	uint32_t        *ring_data;
	uint32_t        queue_lf_num;
	uint32_t        queue_lf_size;
	queue_lf_func_t queue_lf_func;
	odp_shm_t       queue_gbl_shm;
	odp_shm_t       queue_ring_shm;

	struct {
		uint32_t max_queue_size;
		uint32_t default_queue_size;
	} config;

} queue_global_t;

extern queue_global_t *queue_glb;

static inline uint32_t queue_to_index(odp_queue_t handle)
{
	queue_entry_t *qentry = (queue_entry_t *)(uintptr_t)handle;

	return qentry->s.index;
}

static inline queue_entry_t *qentry_from_index(uint32_t queue_id)
{
	return &queue_glb->queue[queue_id];
}

static inline odp_queue_t queue_from_index(uint32_t queue_id)
{
	return (odp_queue_t)qentry_from_index(queue_id);
}

#ifdef __cplusplus
}
#endif

#endif
