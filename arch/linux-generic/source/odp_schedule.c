/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_schedule.h>
#include <odp_schedule_internal.h>
#include <odp_align.h>
#include <odp_queue.h>
#include <odp_shared_memory.h>
#include <odp_buffer.h>
#include <odp_buffer_pool.h>
#include <odp_internal.h>
#include <odp_config.h>
#include <odp_debug.h>

/* Limits to number of scheduled queues */
#define SCHED_POOL_SIZE (256*1024)


typedef struct {
	odp_queue_t       pri_queue[ODP_CONFIG_SCHED_PRIOS];
	odp_buffer_pool_t pool;
} sched_t;

typedef struct {
	odp_queue_t queue;

} queue_desc_t;

static sched_t *sched;


int odp_schedule_init_global(void)
{
	odp_buffer_pool_t pool;
	void *pool_base;
	int i;

	ODP_DBG("Schedule init ... ");

	sched = odp_shm_reserve("odp_scheduler",
				sizeof(sched_t),
				ODP_CACHE_LINE_SIZE);

	if (sched == NULL) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}


	pool_base = odp_shm_reserve("odp_sched_pool",
				    SCHED_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("odp_sched_pool", pool_base,
				      SCHED_POOL_SIZE, sizeof(queue_desc_t),
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_RAW);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Schedule init: Pool create failed.\n");
		return -1;
	}

	sched->pool = pool;

	for (i = 0; i < ODP_CONFIG_SCHED_PRIOS; i++) {
		odp_queue_t queue;
		char name[] = "odp_priXX";

		name[7] = '0' + i / 10;
		name[8] = '0' + i - 10*(i / 10);

		queue = odp_queue_create(name, ODP_QUEUE_TYPE_POLL, NULL);

		if (queue == ODP_QUEUE_INVALID) {
			ODP_ERR("Schedule init: Queue create failed.\n");
			return -1;
		}

		sched->pri_queue[i] = queue;
	}

	ODP_DBG("done\n");

	return 0;
}


void odp_schedule_queue(odp_queue_t queue, int prio)
{
	odp_buffer_t desc_buf;
	queue_desc_t *desc;

	desc_buf = odp_buffer_alloc(sched->pool);
	desc     = odp_buffer_addr(desc_buf);

	desc->queue = queue;

	odp_queue_enq(sched->pri_queue[prio], desc_buf);
}


/* Only parallel implemented */
odp_buffer_t odp_schedule(odp_queue_t *out_queue)
{
	int i;

	for (i = 0; i < ODP_CONFIG_SCHED_PRIOS; i++) {
		odp_queue_t  pri_queue;
		odp_buffer_t desc_buf;

		pri_queue = sched->pri_queue[i];
		desc_buf  = odp_queue_deq(pri_queue);

		if (odp_buffer_is_valid(desc_buf)) {
			queue_desc_t *desc;
			odp_queue_t queue;
			odp_buffer_t buf;

			desc  = odp_buffer_addr(desc_buf);
			queue = desc->queue;
			buf   = odp_queue_deq(queue);

			if (odp_buffer_is_valid(buf) ||
			    odp_queue_type(queue) == ODP_QUEUE_TYPE_PKTIN) {
				/* Continue scheduling the queue */
				odp_queue_enq(pri_queue, desc_buf);
			} else {
				/* Remove empty queue from scheduling
				 * odp_queue_deq cleared the sched status
				 */
				odp_buffer_free(desc_buf);
			}

			/* Output the source queue handle */
			if (out_queue)
				*out_queue = queue;

			return buf;
		}
	}

	return ODP_BUFFER_INVALID;
}


odp_buffer_t odp_schedule_poll(odp_queue_t *queue)
{
	odp_buffer_t buf;

	do {
		buf = odp_schedule(queue);
	} while (!odp_buffer_is_valid(buf));

	return buf;
}


int odp_schedule_num_prio(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}
