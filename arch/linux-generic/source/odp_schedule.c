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


#include <odp_schedule.h>
#include <odp_schedule_internal.h>
#include <odp_align.h>
#include <odp_queue.h>
#include <odp_shared_memory.h>
#include <odp_buffer.h>
#include <odp_buffer_pool.h>
#include <odp_internal.h>
#include <odp_config.h>


#include <stdio.h>

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

	printf("Schedule init ... ");

	sched = odp_shm_reserve("odp_scheduler",
				sizeof(sched_t),
				ODP_CACHE_LINE_SIZE);

	if (sched == NULL) {
		printf("Schedule init: Shm reserve failed.\n");
		return -1;
	}


	pool_base = odp_shm_reserve("odp_sched_pool",
				    SCHED_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("odp_sched_pool", pool_base,
				      SCHED_POOL_SIZE, sizeof(queue_desc_t),
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_RAW);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		printf("Schedule init: Pool create failed.\n");
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
			printf("Schedule init: Queue create failed.\n");
			return -1;
		}

		sched->pri_queue[i] = queue;
	}

	printf("done\n");

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
odp_buffer_t odp_schedule(void)
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

			return buf;
		}
	}

	return ODP_BUFFER_INVALID;
}



odp_buffer_t odp_schedule_poll(void)
{
	odp_buffer_t buf;

	do {
		buf = odp_schedule();
	} while (!odp_buffer_is_valid(buf));

	return buf;
}



int odp_schedule_num_prio(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}





