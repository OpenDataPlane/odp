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




#include <odp_std_types.h>

#include <odp_align.h>
#include <odp_buffer_internal.h>
#include <odp_internal.h>
#include <odp_queue.h>
#include <odp_shared_memory.h>
#include <odp_spinlock.h>


#include <stdio.h>
#include <string.h>


#define ODP_CONFIG_QUEUES  1024



#define QUEUE_STATUS_FREE  0
#define QUEUE_STATUS_INIT  1
#define QUEUE_STATUS_READY 2


struct queue_entry_s {
	odp_spinlock_t    lock;
	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	odp_queue_t       queue;
	int               status;
};


typedef union queue_entry_u {
	struct queue_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];

} queue_entry_t;


typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];

} queue_table_t;



static queue_table_t *queue_tbl;




static inline queue_entry_t *get_queue(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}


static inline odp_queue_t to_handle(uint32_t queue_id)
{
	return queue_id + 1;
}

static inline uint32_t from_handle(odp_queue_t handle)
{
	return handle - 1;
}


int odp_queue_init_global(void)
{
	uint32_t i;

	queue_tbl = odp_shm_reserve("odp_queues",
				    sizeof(queue_table_t),
				    sizeof(queue_entry_t));

	if (queue_tbl == NULL)
		return -1;

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_queue(i);
		odp_spinlock_init(&queue->s.lock);

		/* Queue id 0 is invalid */
		queue->s.queue = to_handle(i);
	}

	printf("Queue init global\n");
	printf("  struct queue_entry_s size %zu\n",
	       sizeof(struct queue_entry_s));
	printf("  queue_entry_t size        %zu\n", sizeof(queue_entry_t));
	printf("\n");

	return 0;
}


odp_queue_t odp_queue_create(const char *name, odp_queue_type_t type)
{
	uint32_t i;
	odp_queue_t queue_id = ODP_QUEUE_INVALID;

	(void) name;
	(void) type;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		odp_spinlock_lock(&queue->s.lock);

		if (queue->s.status == QUEUE_STATUS_FREE) {
			queue->s.status = QUEUE_STATUS_INIT;
			odp_spinlock_unlock(&queue->s.lock);
			queue_id = queue->s.queue;
			break;
		}

		odp_spinlock_unlock(&queue->s.lock);
	}

	return queue_id;
}






