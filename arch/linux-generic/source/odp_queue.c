/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_queue.h>
#include <odp_queue_internal.h>
#include <odp_std_types.h>
#include <odp_align.h>
#include <odp_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_internal.h>
#include <odp_shared_memory.h>
#include <odp_schedule_internal.h>
#include <odp_config.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug.h>

#ifdef USE_TICKETLOCK
#include <odp_ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp_spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#endif

#include <string.h>


typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;


queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

odp_queue_t to_qhandle(uint32_t queue_id)
{
	return queue_id + 1;
}

uint32_t from_qhandle(odp_queue_t handle)
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

	switch (type) {
	case ODP_QUEUE_TYPE_PKTIN:
		queue->s.enqueue = pktin_enqueue;
		queue->s.dequeue = pktin_dequeue;
		break;
	case ODP_QUEUE_TYPE_PKTOUT:
		queue->s.enqueue = pktout_enqueue;
		queue->s.dequeue = pktout_dequeue;
		break;
	default:
		queue->s.enqueue = queue_enq;
		queue->s.dequeue = queue_deq;
		break;
	}

	queue->s.head = NULL;
	queue->s.tail = NULL;
}


int odp_queue_init_global(void)
{
	uint32_t i;

	ODP_DBG("Queue init ... ");

	queue_tbl = odp_shm_reserve("odp_queues",
				    sizeof(queue_table_t),
				    sizeof(queue_entry_t));

	if (queue_tbl == NULL)
		return -1;

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);
		LOCK_INIT(&queue->s.lock);
		queue->s.handle = to_qhandle(i);
	}

	ODP_DBG("done\n");
	ODP_DBG("Queue init global\n");
	ODP_DBG("  struct queue_entry_s size %zu\n",
		sizeof(struct queue_entry_s));
	ODP_DBG("  queue_entry_t size        %zu\n",
		sizeof(queue_entry_t));
	ODP_DBG("\n");

	return 0;
}

odp_queue_type_t odp_queue_type(odp_queue_t handle)
{
	queue_entry_t *queue;
	uint32_t queue_id;

	queue_id = from_qhandle(handle);
	queue    = get_qentry(queue_id);

	return queue->s.type;
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

		LOCK(&queue->s.lock);

		if (queue->s.status == QUEUE_STATUS_FREE) {
			queue_init(queue, name, type, param);
			if (type == ODP_QUEUE_TYPE_SCHED ||
			    type == ODP_QUEUE_TYPE_PKTIN)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;

			UNLOCK(&queue->s.lock);
			break;
		}

		UNLOCK(&queue->s.lock);
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

		LOCK(&queue->s.lock);

		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			UNLOCK(&queue->s.lock);
			return queue->s.handle;
		}

		UNLOCK(&queue->s.lock);
	}

	return ODP_QUEUE_INVALID;
}


int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	int sched = 0;

	LOCK(&queue->s.lock);

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

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1; /* retval: schedule queue */
	}

	UNLOCK(&queue->s.lock);

	/* Add queue to scheduling */
	if (sched == 1)
		odp_schedule_queue(queue->s.handle, queue->s.param.sched.prio);

	return 0;
}


int odp_queue_enq(odp_queue_t handle, odp_buffer_t buf)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;
	uint32_t queue_id;

	queue_id = from_qhandle(handle);
	queue    = get_qentry(queue_id);
	buf_hdr  = odp_buf_to_hdr(buf);

	return queue->s.enqueue(queue, buf_hdr);
}


odp_buffer_hdr_t *queue_deq(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr = NULL;

	LOCK(&queue->s.lock);

	if (queue->s.head == NULL) {
		/* Already empty queue */
		if (queue->s.status == QUEUE_STATUS_SCHED &&
		    queue->s.type != ODP_QUEUE_TYPE_PKTIN)
			queue->s.status = QUEUE_STATUS_NOTSCHED;
	} else {
		buf_hdr       = queue->s.head;
		queue->s.head = buf_hdr->next;
		buf_hdr->next = NULL;

		if (queue->s.head == NULL) {
			/* Queue is now empty */
			queue->s.tail = NULL;
		}
	}

	UNLOCK(&queue->s.lock);

	return buf_hdr;
}


odp_buffer_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	uint32_t queue_id;
	odp_buffer_hdr_t *buf_hdr;

	queue_id = from_qhandle(handle);
	queue    = get_qentry(queue_id);

	buf_hdr = queue->s.dequeue(queue);

	if (buf_hdr)
		return buf_hdr->handle.handle;

	return ODP_BUFFER_INVALID;
}


void queue_lock(queue_entry_t *queue)
{
	LOCK(&queue->s.lock);
}


void queue_unlock(queue_entry_t *queue)
{
	UNLOCK(&queue->s.lock);
}
