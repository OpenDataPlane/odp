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
#include <odp_buffer_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_internal.h>
#include <odp_shared_memory.h>
#include <odp_schedule_internal.h>
#include <odp_config.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug_internal.h>
#include <odp_hints.h>
#include <odp_sync.h>

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
		queue->s.enqueue_multi = pktin_enq_multi;
		queue->s.dequeue_multi = pktin_deq_multi;
		break;
	case ODP_QUEUE_TYPE_PKTOUT:
		queue->s.enqueue = pktout_enqueue;
		queue->s.dequeue = pktout_dequeue;
		queue->s.enqueue_multi = pktout_enq_multi;
		queue->s.dequeue_multi = pktout_deq_multi;
		break;
	default:
		queue->s.enqueue = queue_enq;
		queue->s.dequeue = queue_deq;
		queue->s.enqueue_multi = queue_enq_multi;
		queue->s.dequeue_multi = queue_deq_multi;
		break;
	}

	queue->s.head = NULL;
	queue->s.tail = NULL;
	queue->s.sched_buf = ODP_BUFFER_INVALID;
}


int odp_queue_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	ODP_DBG("Queue init ... ");

	shm = odp_shm_reserve("odp_queues",
			      sizeof(queue_table_t),
			      sizeof(queue_entry_t), 0);

	queue_tbl = odp_shm_addr(shm);

	if (queue_tbl == NULL)
		return -1;

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);
		LOCK_INIT(&queue->s.lock);
		queue->s.handle = queue_from_id(i);
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

	queue = queue_to_qentry(handle);

	return queue->s.type;
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync;
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.prio;
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.group;
}

odp_queue_t odp_queue_create(const char *name, odp_queue_type_t type,
			     odp_queue_param_t *param)
{
	uint32_t i;
	queue_entry_t *queue;
	odp_queue_t handle = ODP_QUEUE_INVALID;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];

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

	if (handle != ODP_QUEUE_INVALID &&
	    (type == ODP_QUEUE_TYPE_SCHED || type == ODP_QUEUE_TYPE_PKTIN)) {
		odp_buffer_t buf;

		buf = odp_schedule_buffer_alloc(handle);
		if (buf == ODP_BUFFER_INVALID) {
			ODP_ERR("queue_init: sched buf alloc failed\n");
			return ODP_QUEUE_INVALID;
		}

		queue->s.sched_buf = buf;
		odp_schedule_mask_set(handle, queue->s.param.sched.prio);
	}

	return handle;
}

int odp_queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	LOCK(&queue->s.lock);
	if (queue->s.status == QUEUE_STATUS_FREE || queue->s.head != NULL) {
		UNLOCK(&queue->s.lock);
		return -1; /* Queue is already free or not empty */
	}

	queue->s.enqueue = queue_enq_dummy;
	queue->s.enqueue_multi = queue_enq_multi_dummy;

	if (queue->s.type == ODP_QUEUE_TYPE_POLL ||
	    queue->s.type == ODP_QUEUE_TYPE_PKTOUT) {
		queue->s.status = QUEUE_STATUS_FREE;
		queue->s.head = NULL;
		queue->s.tail = NULL;
	} else if (queue->s.type == ODP_QUEUE_TYPE_SCHED) {
		if (queue->s.status == QUEUE_STATUS_SCHED)  {
			/*
			 * Override dequeue_multi to destroy queue when it will
			 * be scheduled next time.
			 */
			queue->s.status = QUEUE_STATUS_DESTROYED;
			queue->s.dequeue_multi = queue_deq_multi_destroy;
		} else {
			/* Queue won't be scheduled anymore */
			odp_buffer_free(queue->s.sched_buf);
			queue->s.sched_buf = ODP_BUFFER_INVALID;
			queue->s.status = QUEUE_STATUS_FREE;
			queue->s.head = NULL;
			queue->s.tail = NULL;
		}
	}
	UNLOCK(&queue->s.lock);

	return 0;
}

odp_buffer_t queue_sched_buf(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	return queue->s.sched_buf;
}


int queue_sched_atomic(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC;
}

int odp_queue_set_context(odp_queue_t handle, void *context)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	odp_sync_stores();
	queue->s.param.context = context;
	odp_sync_stores();
	return 0;
}

void *odp_queue_get_context(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	return queue->s.param.context;
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

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int sched = 0;
	int i;
	odp_buffer_hdr_t *tail;

	for (i = 0; i < num - 1; i++)
		buf_hdr[i]->next = buf_hdr[i+1];

	tail = buf_hdr[num-1];
	buf_hdr[num-1]->next = NULL;

	LOCK(&queue->s.lock);
	/* Empty queue */
	if (queue->s.head == NULL)
		queue->s.head = buf_hdr[0];
	else
		queue->s.tail->next = buf_hdr[0];

	queue->s.tail = tail;

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

int queue_enq_dummy(queue_entry_t *queue ODP_UNUSED,
		    odp_buffer_hdr_t *buf_hdr ODP_UNUSED)
{
	return -1;
}

int queue_enq_multi_dummy(queue_entry_t *queue ODP_UNUSED,
			  odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
			  int num ODP_UNUSED)
{
	return -1;
}

int odp_queue_enq_multi(odp_queue_t handle, odp_buffer_t buf[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	for (i = 0; i < num; i++)
		buf_hdr[i] = odp_buf_to_hdr(buf[i]);

	return queue->s.enqueue_multi(queue, buf_hdr, num);
}


int odp_queue_enq(odp_queue_t handle, odp_buffer_t buf)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue   = queue_to_qentry(handle);
	buf_hdr = odp_buf_to_hdr(buf);

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


int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i = 0;

	LOCK(&queue->s.lock);

	if (queue->s.head == NULL) {
		/* Already empty queue */
		if (queue->s.status == QUEUE_STATUS_SCHED &&
		    queue->s.type != ODP_QUEUE_TYPE_PKTIN)
			queue->s.status = QUEUE_STATUS_NOTSCHED;
	} else {
		odp_buffer_hdr_t *hdr = queue->s.head;

		for (; i < num && hdr; i++) {
			buf_hdr[i]       = hdr;
			/* odp_prefetch(hdr->addr); */
			hdr              = hdr->next;
			buf_hdr[i]->next = NULL;
		}

		queue->s.head = hdr;

		if (hdr == NULL) {
			/* Queue is now empty */
			queue->s.tail = NULL;
		}
	}

	UNLOCK(&queue->s.lock);

	return i;
}

int queue_deq_multi_destroy(queue_entry_t *queue,
			    odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
			    int num ODP_UNUSED)
{
	LOCK(&queue->s.lock);

	odp_buffer_free(queue->s.sched_buf);
	queue->s.sched_buf = ODP_BUFFER_INVALID;
	queue->s.status = QUEUE_STATUS_FREE;
	queue->s.head = NULL;
	queue->s.tail = NULL;

	UNLOCK(&queue->s.lock);

	return 0;
}

int odp_queue_deq_multi(odp_queue_t handle, odp_buffer_t buf[], int num)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	int i, ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	ret = queue->s.dequeue_multi(queue, buf_hdr, num);

	for (i = 0; i < ret; i++)
		buf[i] = buf_hdr[i]->handle.handle;

	return ret;
}


odp_buffer_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr;

	queue   = queue_to_qentry(handle);
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
