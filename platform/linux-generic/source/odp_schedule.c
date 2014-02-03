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
#include <odp_thread.h>

#include <odp_queue_internal.h>


/* Limits to number of scheduled queues */
#define SCHED_POOL_SIZE (256*1024)

/* Scheduler sub queues */
#define QUEUES_PER_PRIO  4

/* TODO: random or queue based selection */
#define RAND_PRI_QUEUE(x) ((QUEUES_PER_PRIO-1) & (queue_to_id(x)))


typedef struct {
	odp_queue_t       pri_queue[ODP_CONFIG_SCHED_PRIOS][QUEUES_PER_PRIO];
	odp_buffer_pool_t pool;
} sched_t;

typedef struct {
	odp_queue_t queue;

} queue_desc_t;

typedef struct {
	odp_queue_t  pri_queue;
	odp_buffer_t desc_buf;
} thread_local_atomic_t;


static sched_t *sched;

/* Thread local atomic context status */
static __thread thread_local_atomic_t tl_atomic = {ODP_QUEUE_INVALID,
						   ODP_BUFFER_INVALID};


static inline odp_queue_t select_pri_queue(odp_queue_t queue, int prio)
{
	int id = RAND_PRI_QUEUE(queue);
	return sched->pri_queue[prio][id];
}


int odp_schedule_init_global(void)
{
	odp_buffer_pool_t pool;
	void *pool_base;
	int i, j;

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
		char name[] = "odp_priXX_YY";

		name[7] = '0' + i / 10;
		name[8] = '0' + i - 10*(i / 10);

		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			name[10] = '0' + j / 10;
			name[11] = '0' + j - 10*(j / 10);

			queue = odp_queue_create(name,
						 ODP_QUEUE_TYPE_POLL, NULL);

			if (queue == ODP_QUEUE_INVALID) {
				ODP_ERR("Sched init: Queue create failed.\n");
				return -1;
			}

			sched->pri_queue[i][j] = queue;
		}
	}

	ODP_DBG("done\n");

	return 0;
}


odp_buffer_t odp_schedule_buffer_alloc(odp_queue_t queue)
{
	odp_buffer_t buf;

	buf = odp_buffer_alloc(sched->pool);

	if (buf != ODP_BUFFER_INVALID) {
		queue_desc_t *desc;
		desc        = odp_buffer_addr(buf);
		desc->queue = queue;
	}

	return buf;
}


void odp_schedule_queue(odp_queue_t queue, int prio)
{
	odp_buffer_t desc_buf;
	odp_queue_t  pri_queue;

	pri_queue = select_pri_queue(queue, prio);
	desc_buf  = queue_sched_buf(queue);

	odp_queue_enq(pri_queue, desc_buf);
}


void odp_schedule_release_atomic_context(void)
{
	if (tl_atomic.pri_queue != ODP_QUEUE_INVALID) {
		/* Release current atomic queue */
		odp_queue_enq(tl_atomic.pri_queue, tl_atomic.desc_buf);
		tl_atomic.pri_queue = ODP_QUEUE_INVALID;
	}
}


/*
 * Schedule queues
 *
 * TODO: SYNC_ORDERED not implemented yet
 */
odp_buffer_t odp_schedule(odp_queue_t *out_queue)
{
	int i, j;
	int thr;

	odp_schedule_release_atomic_context();

	thr = odp_thread_id();

	for (i = 0; i < ODP_CONFIG_SCHED_PRIOS; i++) {
		int id;

		id = thr & (QUEUES_PER_PRIO-1);

		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			odp_queue_t  pri_q;
			odp_buffer_t desc_buf;

			pri_q    = sched->pri_queue[i][id];
			desc_buf = odp_queue_deq(pri_q);

			id++;
			if (id >= QUEUES_PER_PRIO)
				id = 0;

			if (desc_buf != ODP_BUFFER_INVALID) {
				queue_desc_t *desc;
				odp_queue_t queue;
				odp_buffer_t buf;

				desc  = odp_buffer_addr(desc_buf);
				queue = desc->queue;
				buf   = odp_queue_deq(queue);

				if (buf == ODP_BUFFER_INVALID) {
					/* Remove empty queue from scheduling,
					 * except packet input queues
					 */
					if (odp_queue_type(queue) ==
					    ODP_QUEUE_TYPE_PKTIN)
						odp_queue_enq(pri_q, desc_buf);

					continue;
				}

				if (queue_sched_atomic(queue)) {
					/* Hold queue during atomic access */
					tl_atomic.pri_queue = pri_q;
					tl_atomic.desc_buf  = desc_buf;
				} else {
					/* Continue scheduling the queue */
					odp_queue_enq(pri_q, desc_buf);
				}

				/* Output the source queue handle */
				if (out_queue)
					*out_queue = queue;

				return buf;
			}
		}
	}

	return ODP_BUFFER_INVALID;
}


odp_buffer_t odp_schedule_poll(odp_queue_t *queue)
{
	odp_buffer_t buf;

	do {
		buf = odp_schedule(queue);
	} while (buf == ODP_BUFFER_INVALID);

	return buf;
}


int odp_schedule_num_prio(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}
