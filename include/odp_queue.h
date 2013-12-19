/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

#define ODP_QUEUE_TYPE_SCHED   0
#define ODP_QUEUE_TYPE_POLL    1
#define ODP_QUEUE_TYPE_PKTIN   2
#define ODP_QUEUE_TYPE_PKTOUT  3

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


#ifdef __cplusplus
}
#endif

#endif







