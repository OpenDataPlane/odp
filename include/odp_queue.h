/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_QUEUE_H_
#define ODP_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>
#include <odp_buffer.h>


/**
 * ODP queue
 */
typedef uint32_t odp_queue_t;

#define ODP_QUEUE_INVALID  0

#define ODP_QUEUE_NAME_LEN 32


/**
 * ODP queue type
 */
typedef int odp_queue_type_t;

#define ODP_QUEUE_TYPE_SCHED  0
#define ODP_QUEUE_TYPE_POLL   1
#define ODP_QUEUE_TYPE_PKTIN  2
#define ODP_QUEUE_TYPE_PKTOUT 3

/**
 * ODP schedule priority
 */
typedef int odp_schedule_prio_t;

#define ODP_SCHED_PRIO_HIGHEST  0
#define ODP_SCHED_PRIO_NORMAL   (ODP_CONFIG_SCHED_PRIOS / 2)
#define ODP_SCHED_PRIO_LOWEST   (ODP_CONFIG_SCHED_PRIOS - 1)
#define ODP_SCHED_PRIO_DEFAULT  ODP_SCHED_PRIO_NORMAL

/**
 * ODP schedule synchronisation
 */
typedef int odp_schedule_sync_t;

#define ODP_SCHED_SYNC_NONE     0
#define ODP_SCHED_SYNC_ATOMIC   1
#define ODP_SCHED_SYNC_ORDERED  2
#define ODP_SCHED_SYNC_DEFAULT  ODP_SCHED_SYNC_ATOMIC

/**
 * ODP schedule core group
 */
typedef int odp_schedule_group_t;

#define ODP_SCHED_GROUP_ALL     0
#define ODP_SCHED_GROUP_DEFAULT ODP_SCHED_GROUP_ALL

typedef union odp_queue_param_t {
	struct {
		odp_schedule_prio_t  prio;
		odp_schedule_sync_t  sync;
		odp_schedule_group_t group;
	} sched;

} odp_queue_param_t;


/**
 * Queue create
 *
 * @param name    Queue name
 * @param type    Queue type
 * @param param   Queue parameters. Uses defaults if NULL.
 *
 * @return Queue handle or ODP_QUEUE_INVALID
 */
odp_queue_t odp_queue_create(const char *name, odp_queue_type_t type,
			     odp_queue_param_t *param);

/**
 * Find a queue by name
 *
 * @param name    Queue name
 *
 * @return Queue handle or ODP_QUEUE_INVALID
 */
odp_queue_t odp_queue_lookup(const char *name);

/**
 * Queue enqueue
 *
 * @param queue   Queue handle
 * @param buf     Buffer handle
 *
 * @return 0 if succesful
 */
int odp_queue_enq(odp_queue_t queue, odp_buffer_t buf);

/**
 * Enqueue multiple buffers to a queue
 *
 * @param queue   Queue handle
 * @param buf     Buffer handles
 * @param num     Number of buffer handles
 *
 * @return 0 if succesful
 */
int odp_queue_enq_multi(odp_queue_t queue, odp_buffer_t buf[], int num);

/**
 * Queue dequeue
 *
 * Dequeues next buffer from head of the queue. Cannot be used for
 * ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule() instead).
 *
 * @param queue   Queue handle
 *
 * @return Buffer handle, or ODP_BUFFER_INVALID
 */
odp_buffer_t odp_queue_deq(odp_queue_t queue);

/**
 * Dequeue multiple buffers from a queue
 *
 * Dequeues multiple buffers from head of the queue. Cannot be used for
 * ODP_QUEUE_TYPE_SCHED type queues (use odp_schedule() instead).
 *
 * @param queue   Queue handle
 * @param buf     Buffer handles for output
 * @param num     Maximum number of buffer handles

 * @return Number of buffers written (0 ... num)
 */
int odp_queue_deq_multi(odp_queue_t queue, odp_buffer_t buf[], int num);

/**
 * Queue type
 *
 * @param queue   Queue handle
 *
 * @return Queue type
 */
odp_queue_type_t odp_queue_type(odp_queue_t queue);

#ifdef __cplusplus
}
#endif

#endif







