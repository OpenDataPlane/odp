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
#include <odp_debug_internal.h>
#include <odp_thread.h>
#include <odp_time.h>
#include <odp_spinlock.h>
#include <odp_hints.h>

#include <odp_queue_internal.h>


/* Limits to number of scheduled queues */
#define SCHED_POOL_SIZE (256*1024)

/* Scheduler sub queues */
#define QUEUES_PER_PRIO  4

/* TODO: random or queue based selection */
#define SEL_PRI_QUEUE(x) ((QUEUES_PER_PRIO-1) & (queue_to_id(x)))

/* Maximum number of dequeues */
#define MAX_DEQ 4


/* Mask of queues per priority */
typedef uint8_t pri_mask_t;

_ODP_STATIC_ASSERT((8*sizeof(pri_mask_t)) >= QUEUES_PER_PRIO,
		   "pri_mask_t_is_too_small");


typedef struct {
	odp_queue_t       pri_queue[ODP_CONFIG_SCHED_PRIOS][QUEUES_PER_PRIO];
	pri_mask_t        pri_mask[ODP_CONFIG_SCHED_PRIOS];
	odp_spinlock_t    mask_lock;
	odp_buffer_pool_t pool;
} sched_t;

typedef struct {
	odp_queue_t queue;

} queue_desc_t;

typedef struct {
	odp_queue_t  pri_queue;
	odp_buffer_t desc_buf;

	odp_buffer_t buf[MAX_DEQ];
	int num;
	int index;
	odp_queue_t queue;
	int pause;

} sched_local_t;

/* Global scheduler context */
static sched_t *sched;

/* Thread local scheduler context */
static __thread sched_local_t sched_local;


static inline odp_queue_t select_pri_queue(odp_queue_t queue, int prio)
{
	int id = SEL_PRI_QUEUE(queue);
	return sched->pri_queue[prio][id];
}


int odp_schedule_init_global(void)
{
	odp_shm_t shm;
	odp_buffer_pool_t pool;
	int i, j;
	odp_buffer_pool_param_t params;

	ODP_DBG("Schedule init ... ");

	shm = odp_shm_reserve("odp_scheduler",
			      sizeof(sched_t),
			      ODP_CACHE_LINE_SIZE, 0);

	sched = odp_shm_addr(shm);

	if (sched == NULL) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	params.buf_size  = sizeof(queue_desc_t);
	params.buf_align = 0;
	params.num_bufs  = SCHED_POOL_SIZE/sizeof(queue_desc_t);
	params.buf_type  = ODP_BUFFER_TYPE_RAW;

	pool = odp_buffer_pool_create("odp_sched_pool", ODP_SHM_NULL, &params);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Schedule init: Pool create failed.\n");
		return -1;
	}

	sched->pool = pool;
	odp_spinlock_init(&sched->mask_lock);

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
			sched->pri_mask[i]     = 0;
		}
	}

	ODP_DBG("done\n");

	return 0;
}


int odp_schedule_init_local(void)
{
	int i;

	sched_local.pri_queue = ODP_QUEUE_INVALID;
	sched_local.desc_buf  = ODP_BUFFER_INVALID;

	for (i = 0; i < MAX_DEQ; i++)
		sched_local.buf[i] = ODP_BUFFER_INVALID;

	sched_local.num   = 0;
	sched_local.index = 0;
	sched_local.queue = ODP_QUEUE_INVALID;
	sched_local.pause = 0;

	return 0;
}


void odp_schedule_mask_set(odp_queue_t queue, int prio)
{
	int id = SEL_PRI_QUEUE(queue);

	odp_spinlock_lock(&sched->mask_lock);
	sched->pri_mask[prio] |= 1 << id;
	odp_spinlock_unlock(&sched->mask_lock);
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

	odp_queue_enq(pri_queue, odp_buffer_to_event(desc_buf));
}


void odp_schedule_release_atomic(void)
{
	if (sched_local.pri_queue != ODP_QUEUE_INVALID &&
	    sched_local.num       == 0) {
		/* Release current atomic queue */
		odp_queue_enq(sched_local.pri_queue,
			      odp_buffer_to_event(sched_local.desc_buf));
		sched_local.pri_queue = ODP_QUEUE_INVALID;
	}
}


static inline int copy_bufs(odp_buffer_t out_buf[], unsigned int max)
{
	int i = 0;

	while (sched_local.num && max) {
		out_buf[i] = sched_local.buf[sched_local.index];
		sched_local.index++;
		sched_local.num--;
		max--;
		i++;
	}

	return i;
}


/*
 * Schedule queues
 *
 * TODO: SYNC_ORDERED not implemented yet
 */
static int schedule(odp_queue_t *out_queue, odp_buffer_t out_buf[],
		    unsigned int max_num, unsigned int max_deq)
{
	int i, j;
	int thr;
	int ret;

	if (sched_local.num) {
		ret = copy_bufs(out_buf, max_num);

		if (out_queue)
			*out_queue = sched_local.queue;

		return ret;
	}

	odp_schedule_release_atomic();

	if (odp_unlikely(sched_local.pause))
		return 0;

	thr = odp_thread_id();

	for (i = 0; i < ODP_CONFIG_SCHED_PRIOS; i++) {
		int id;

		if (sched->pri_mask[i] == 0)
			continue;

		id = thr & (QUEUES_PER_PRIO-1);

		for (j = 0; j < QUEUES_PER_PRIO; j++, id++) {
			odp_queue_t  pri_q;
			odp_event_t  ev;
			odp_buffer_t desc_buf;

			if (id >= QUEUES_PER_PRIO)
				id = 0;

			if (odp_unlikely((sched->pri_mask[i] & (1 << id)) == 0))
				continue;

			pri_q    = sched->pri_queue[i][id];
			ev       = odp_queue_deq(pri_q);
			desc_buf = odp_buffer_from_event(ev);

			if (desc_buf != ODP_BUFFER_INVALID) {
				queue_desc_t *desc;
				odp_queue_t queue;
				int num;

				desc  = odp_buffer_addr(desc_buf);
				queue = desc->queue;

				if (odp_queue_type(queue) ==
					ODP_QUEUE_TYPE_PKTIN &&
					!queue_is_sched(queue))
					continue;

				num = odp_queue_deq_multi(queue,
							  sched_local.buf,
							  max_deq);

				if (num == 0) {
					/* Remove empty queue from scheduling,
					 * except packet input queues
					 */
					if (odp_queue_type(queue) ==
					    ODP_QUEUE_TYPE_PKTIN &&
					    !queue_is_destroyed(queue))
						odp_queue_enq(pri_q, odp_buffer_to_event(desc_buf));

					continue;
				}

				sched_local.num   = num;
				sched_local.index = 0;
				ret = copy_bufs(out_buf, max_num);

				sched_local.queue = queue;

				if (queue_sched_atomic(queue)) {
					/* Hold queue during atomic access */
					sched_local.pri_queue = pri_q;
					sched_local.desc_buf  = desc_buf;
				} else {
					/* Continue scheduling the queue */
					odp_queue_enq(pri_q, odp_buffer_to_event(desc_buf));
				}

				/* Output the source queue handle */
				if (out_queue)
					*out_queue = queue;

				return ret;
			}
		}
	}

	return 0;
}


static int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
			  odp_buffer_t out_buf[],
			  unsigned int max_num, unsigned int max_deq)
{
	uint64_t start_cycle, cycle, diff;
	int ret;

	start_cycle = 0;

	while (1) {
		ret = schedule(out_queue, out_buf, max_num, max_deq);

		if (ret)
			break;

		if (wait == ODP_SCHED_WAIT)
			continue;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (start_cycle == 0) {
			start_cycle = odp_time_cycles();
			continue;
		}

		cycle = odp_time_cycles();
		diff  = odp_time_diff_cycles(start_cycle, cycle);

		if (wait < diff)
			break;
	}

	return ret;
}


odp_event_t odp_schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_buffer_t buf;

	buf = ODP_BUFFER_INVALID;

	schedule_loop(out_queue, wait, &buf, 1, MAX_DEQ);

	return odp_buffer_to_event(buf);
}


int odp_schedule_multi(odp_queue_t *out_queue, uint64_t wait,
		       odp_event_t events[], unsigned int num)
{
	return schedule_loop(out_queue, wait,
			     (odp_buffer_t *)events, num, MAX_DEQ);
}


void odp_schedule_pause(void)
{
	sched_local.pause = 1;
}


void odp_schedule_resume(void)
{
	sched_local.pause = 0;
}


uint64_t odp_schedule_wait_time(uint64_t ns)
{
	if (ns <= ODP_SCHED_NO_WAIT)
		ns = ODP_SCHED_NO_WAIT + 1;

	return odp_time_ns_to_cycles(ns);
}


int odp_schedule_num_prio(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}
