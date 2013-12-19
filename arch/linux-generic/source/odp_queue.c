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
#include <odp_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_internal.h>
#include <odp_queue.h>
#include <odp_shared_memory.h>
#include <odp_spinlock.h>
#include <odp_schedule_internal.h>
#include <odp_config.h>

#include <stdio.h>
#include <string.h>


#define QUEUE_STATUS_FREE     0
#define QUEUE_STATUS_INIT     1
#define QUEUE_STATUS_READY    2
#define QUEUE_STATUS_NOTSCHED 3
#define QUEUE_STATUS_SCHED    4

/* forward declaration */
union queue_entry_u;

struct queue_entry_s {
	odp_spinlock_t    lock;
	int (*enqueue)(union queue_entry_u *, odp_buffer_hdr_t *);
	odp_buffer_hdr_t *(*dequeue)(union queue_entry_u *);
	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	odp_queue_t       handle;
	odp_queue_type_t  type;
	int               status;
	odp_queue_param_t param;
	char              name[ODP_QUEUE_NAME_LEN];
};


typedef union queue_entry_u {
	struct queue_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];

} queue_entry_t;


typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];

} queue_table_t;



static queue_table_t *queue_tbl;

/* local function prototypes */
static int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
static odp_buffer_hdr_t *queue_deq(queue_entry_t *queue);



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


static void queue_init(queue_entry_t *queue, const char *name,
		       odp_queue_type_t type, odp_queue_param_t *param)
{
	strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
	queue->s.type = type;

	if (param) {
		memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	} else {
		/* Defaults */
		memset(&queue->s.param, 0, sizeof(odp_queue_param_t));
		queue->s.param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		queue->s.param.sched.sync  = ODP_SCHED_SYNC_DEFAULT;
		queue->s.param.sched.group = ODP_SCHED_GROUP_DEFAULT;
	}

	queue->s.enqueue = queue_enq;
	queue->s.dequeue = queue_deq;

	queue->s.head = NULL;
	queue->s.tail = NULL;
}


int odp_queue_init_global(void)
{
	uint32_t i;

	printf("Queue init ... ");

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

		queue->s.handle = to_handle(i);
	}

	printf("done\n");
	printf("Queue init global\n");
	printf("  struct queue_entry_s size %zu\n",
	       sizeof(struct queue_entry_s));
	printf("  queue_entry_t size        %zu\n", sizeof(queue_entry_t));
	printf("\n");

	return 0;
}


odp_queue_t odp_queue_create(const char *name, odp_queue_type_t type,
			     odp_queue_param_t *param)
{
	uint32_t i;
	odp_queue_t handle = ODP_QUEUE_INVALID;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		odp_spinlock_lock(&queue->s.lock);

		if (queue->s.status == QUEUE_STATUS_FREE) {
			queue->s.status = QUEUE_STATUS_INIT;
			odp_spinlock_unlock(&queue->s.lock);
			queue_init(queue, name, type, param);

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;
			break;
		}

		odp_spinlock_unlock(&queue->s.lock);
	}

	return handle;
}



odp_queue_t odp_queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->s.status == QUEUE_STATUS_FREE)
			continue;

		odp_spinlock_lock(&queue->s.lock);

		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			odp_spinlock_unlock(&queue->s.lock);
			return queue->s.handle;
		}

		odp_spinlock_unlock(&queue->s.lock);
	}

	return ODP_QUEUE_INVALID;
}



static int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	if (queue->s.head == NULL) {
		/* Empty queue */
		queue->s.head = buf_hdr;
		queue->s.tail = buf_hdr;
		buf_hdr->next = NULL;
	} else {
		queue->s.tail->next = buf_hdr;
		queue->s.tail = buf_hdr;
		buf_hdr->next = NULL;
	}

	return 0;
}


int odp_queue_enq(odp_queue_t handle, odp_buffer_t buf)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;
	uint32_t queue_id;
	int sched = 0;

	queue_id = from_handle(handle);
	queue    = get_queue(queue_id);
	buf_hdr  = odp_buf_to_hdr(buf);

	odp_spinlock_lock(&queue->s.lock);
	queue->s.enqueue(queue, buf_hdr);

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1;
	}

	odp_spinlock_unlock(&queue->s.lock);

	/* Add queue to scheduling */
	if (sched)
		odp_schedule_queue(handle, queue->s.param.sched.prio);

	return 0;
}


static odp_buffer_hdr_t *queue_deq(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr;

	if (queue->s.head == NULL) {
		/* Already empty queue */
		if (queue->s.status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		return NULL;
	}


	buf_hdr       = queue->s.head;
	queue->s.head = buf_hdr->next;
	buf_hdr->next = NULL;

	if (queue->s.head == NULL) {
		/* Queue is now empty */
		queue->s.tail = NULL;
	}

	return buf_hdr;
}


odp_buffer_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	uint32_t queue_id;
	odp_buffer_hdr_t *buf_hdr;

	queue_id = from_handle(handle);
	queue    = get_queue(queue_id);

	odp_spinlock_lock(&queue->s.lock);
	buf_hdr = queue->s.dequeue(queue);
	odp_spinlock_unlock(&queue->s.lock);

	if (buf_hdr)
		return buf_hdr->handle.handle;

	return ODP_BUFFER_INVALID;
}

