/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/queue.h>
#include <odp_queue_internal.h>
#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_config_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/sync.h>
#include <odp/api/traffic_mngr.h>

#define NUM_INTERNAL_QUEUES 64

#include <odp/api/plat/ticketlock_inlines.h>
#define LOCK(a)      _odp_ticketlock_lock(a)
#define UNLOCK(a)    _odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)

#include <string.h>
#include <inttypes.h>

typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;

static inline odp_queue_t queue_from_id(uint32_t queue_id)
{
	return _odp_cast_scalar(odp_queue_t, queue_id + 1);
}

static inline int queue_is_atomic(queue_entry_t *qe)
{
	return qe->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC;
}

static inline int queue_is_ordered(queue_entry_t *qe)
{
	return qe->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED;
}

queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	if (name == NULL) {
		queue->s.name[0] = 0;
	} else {
		strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
		queue->s.name[ODP_QUEUE_NAME_LEN - 1] = 0;
	}
	memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	if (queue->s.param.sched.lock_count > sched_fn->max_ordered_locks())
		return -1;

	if (param->type == ODP_QUEUE_TYPE_SCHED) {
		queue->s.param.deq_mode = ODP_QUEUE_OP_DISABLED;

		if (param->sched.sync == ODP_SCHED_SYNC_ORDERED) {
			unsigned i;

			odp_atomic_init_u64(&queue->s.ordered.ctx, 0);
			odp_atomic_init_u64(&queue->s.ordered.next_ctx, 0);

			for (i = 0; i < queue->s.param.sched.lock_count; i++)
				odp_atomic_init_u64(&queue->s.ordered.lock[i],
						    0);
		}
	}
	queue->s.type = queue->s.param.type;

	queue->s.enqueue = queue_enq;
	queue->s.dequeue = queue_deq;
	queue->s.enqueue_multi = queue_enq_multi;
	queue->s.dequeue_multi = queue_deq_multi;

	queue->s.pktin = PKTIN_INVALID;

	queue->s.head = NULL;
	queue->s.tail = NULL;

	return 0;
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
		queue->s.index  = i;
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

int odp_queue_term_global(void)
{
	int ret = 0;
	int rc = 0;
	queue_entry_t *queue;
	int i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];
		LOCK(&queue->s.lock);
		if (queue->s.status != QUEUE_STATUS_FREE) {
			ODP_ERR("Not destroyed queue: %s\n", queue->s.name);
			rc = -1;
		}
		UNLOCK(&queue->s.lock);
	}

	ret = odp_shm_free(odp_shm_lookup("odp_queues"));
	if (ret < 0) {
		ODP_ERR("shm free failed for odp_queues");
		rc = -1;
	}

	return rc;
}

int odp_queue_capability(odp_queue_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = ODP_CONFIG_QUEUES - NUM_INTERNAL_QUEUES;
	capa->max_ordered_locks = sched_fn->max_ordered_locks();
	capa->max_sched_groups  = sched_fn->num_grps();
	capa->sched_prios       = odp_schedule_num_prio();

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

int odp_queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		(int)queue->s.param.sched.lock_count : -1;
}

odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param)
{
	uint32_t i;
	queue_entry_t *queue;
	odp_queue_t handle = ODP_QUEUE_INVALID;
	odp_queue_type_t type = ODP_QUEUE_TYPE_PLAIN;
	odp_queue_param_t default_param;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->s.lock);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(&queue->s.lock);
				return handle;
			}

			type = queue->s.type;

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;
			UNLOCK(&queue->s.lock);
			break;
		}
		UNLOCK(&queue->s.lock);
	}

	if (handle != ODP_QUEUE_INVALID && type == ODP_QUEUE_TYPE_SCHED) {
		if (sched_fn->init_queue(queue->s.index,
					 &queue->s.param.sched)) {
			queue->s.status = QUEUE_STATUS_FREE;
			ODP_ERR("schedule queue init failed\n");
			return ODP_QUEUE_INVALID;
		}
	}

	return handle;
}

void sched_cb_queue_destroy_finalize(uint32_t queue_index)
{
	queue_entry_t *queue = get_qentry(queue_index);

	LOCK(&queue->s.lock);

	if (queue->s.status == QUEUE_STATUS_DESTROYED) {
		queue->s.status = QUEUE_STATUS_FREE;
		sched_fn->destroy_queue(queue_index);
	}
	UNLOCK(&queue->s.lock);
}

int odp_queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	queue = queue_to_qentry(handle);

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	LOCK(&queue->s.lock);
	if (queue->s.status == QUEUE_STATUS_FREE) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" already free\n", queue->s.name);
		return -1;
	}
	if (queue->s.status == QUEUE_STATUS_DESTROYED) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" already destroyed\n", queue->s.name);
		return -1;
	}
	if (queue->s.head != NULL) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" not empty\n", queue->s.name);
		return -1;
	}
	if (queue_is_ordered(queue) &&
	    odp_atomic_load_u64(&queue->s.ordered.ctx) !=
			    odp_atomic_load_u64(&queue->s.ordered.next_ctx)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" reorder incomplete\n", queue->s.name);
		return -1;
	}

	switch (queue->s.status) {
	case QUEUE_STATUS_READY:
		queue->s.status = QUEUE_STATUS_FREE;
		break;
	case QUEUE_STATUS_NOTSCHED:
		queue->s.status = QUEUE_STATUS_FREE;
		sched_fn->destroy_queue(queue->s.index);
		break;
	case QUEUE_STATUS_SCHED:
		/* Queue is still in scheduling */
		queue->s.status = QUEUE_STATUS_DESTROYED;
		break;
	default:
		ODP_ABORT("Unexpected queue status\n");
	}
	UNLOCK(&queue->s.lock);

	return 0;
}

int odp_queue_context_set(odp_queue_t handle, void *context,
			  uint32_t len ODP_UNUSED)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	odp_mb_full();
	queue->s.param.context = context;
	odp_mb_full();
	return 0;
}

void *odp_queue_context(odp_queue_t handle)
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

		if (queue->s.status == QUEUE_STATUS_FREE ||
		    queue->s.status == QUEUE_STATUS_DESTROYED)
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

static inline int enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	int sched = 0;
	int i, ret;
	odp_buffer_hdr_t *hdr, *tail, *next_hdr;

	if (sched_fn->ord_enq_multi(queue->s.index, (void **)buf_hdr, num,
			&ret))
		return ret;

	/* Optimize the common case of single enqueue */
	if (num == 1) {
		tail = buf_hdr[0];
		hdr  = tail;
		hdr->burst_num = 0;
		hdr->next = NULL;
	} else {
		int next;

		/* Start from the last buffer header */
		tail = buf_hdr[num - 1];
		hdr  = tail;
		hdr->next = NULL;
		next = num - 2;

		while (1) {
			/* Build a burst. The buffer header carrying
			 * a burst is the last buffer of the burst. */
			for (i = 0; next >= 0 && i < BUFFER_BURST_SIZE;
			     i++, next--)
				hdr->burst[BUFFER_BURST_SIZE - 1 - i] =
					buf_hdr[next];

			hdr->burst_num   = i;
			hdr->burst_first = BUFFER_BURST_SIZE - i;

			if (odp_likely(next < 0))
				break;

			/* Get another header and link it */
			next_hdr  = hdr;
			hdr       = buf_hdr[next];
			hdr->next = next_hdr;
			next--;
		}
	}

	LOCK(&queue->s.lock);
	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	/* Empty queue */
	if (queue->s.head == NULL)
		queue->s.head = hdr;
	else
		queue->s.tail->next = hdr;

	queue->s.tail = tail;

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1; /* retval: schedule queue */
	}
	UNLOCK(&queue->s.lock);

	/* Add queue to scheduling */
	if (sched && sched_fn->sched_queue(queue->s.index))
		ODP_ABORT("schedule_queue failed\n");

	return num; /* All events enqueued */
}

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	return enq_multi(queue, buf_hdr, num);
}

int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = enq_multi(queue, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

int odp_queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	for (i = 0; i < num; i++)
		buf_hdr[i] = buf_hdl_to_hdr(odp_buffer_from_event(ev[i]));

	return num == 0 ? 0 : queue->s.enqueue_multi(queue, buf_hdr,
						     num);
}

int odp_queue_enq(odp_queue_t handle, odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue   = queue_to_qentry(handle);
	buf_hdr = buf_hdl_to_hdr(odp_buffer_from_event(ev));

	return queue->s.enqueue(queue, buf_hdr);
}

static inline int deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	odp_buffer_hdr_t *hdr, *next;
	int i, j;
	int updated = 0;

	LOCK(&queue->s.lock);
	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed.
		 * Scheduler finalizes queue destroy after this. */
		UNLOCK(&queue->s.lock);
		return -1;
	}

	hdr = queue->s.head;

	if (hdr == NULL) {
		/* Already empty queue */
		if (queue->s.status == QUEUE_STATUS_SCHED) {
			queue->s.status = QUEUE_STATUS_NOTSCHED;
			sched_fn->unsched_queue(queue->s.index);
		}

		UNLOCK(&queue->s.lock);
		return 0;
	}

	for (i = 0; i < num && hdr; ) {
		int burst_num = hdr->burst_num;
		int first     = hdr->burst_first;

		/* First, get bursted buffers */
		for (j = 0; j < burst_num && i < num; j++, i++) {
			buf_hdr[i] = hdr->burst[first + j];
			odp_prefetch(buf_hdr[i]);
		}

		if (burst_num) {
			hdr->burst_num   = burst_num - j;
			hdr->burst_first = first + j;
		}

		if (i == num)
			break;

		/* When burst is empty, consume the current buffer header and
		 * move to the next header */
		buf_hdr[i] = hdr;
		next       = hdr->next;
		hdr->next  = NULL;
		hdr        = next;
		updated++;
		i++;
	}

	/* Write head only if updated */
	if (updated)
		queue->s.head = hdr;

	/* Queue is empty */
	if (hdr == NULL)
		queue->s.tail = NULL;

	if (queue->s.type == ODP_QUEUE_TYPE_SCHED)
		sched_fn->save_context(queue);

	UNLOCK(&queue->s.lock);

	return i;
}

int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	return deq_multi(queue, buf_hdr, num);
}

odp_buffer_hdr_t *queue_deq(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = deq_multi(queue, &buf_hdr, 1);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

int odp_queue_deq_multi(odp_queue_t handle, odp_event_t events[], int num)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	int i, ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	ret = queue->s.dequeue_multi(queue, buf_hdr, num);

	for (i = 0; i < ret; i++)
		events[i] = odp_buffer_to_event(buf_hdr[i]->handle.handle);

	return ret;
}


odp_event_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr;

	queue   = queue_to_qentry(handle);
	buf_hdr = queue->s.dequeue(queue);

	if (buf_hdr)
		return odp_buffer_to_event(buf_hdr->handle.handle);

	return ODP_EVENT_INVALID;
}

void queue_lock(queue_entry_t *queue)
{
	LOCK(&queue->s.lock);
}

void queue_unlock(queue_entry_t *queue)
{
	UNLOCK(&queue->s.lock);
}

void odp_queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	params->sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	params->sched.group = ODP_SCHED_GROUP_ALL;
}

int odp_queue_info(odp_queue_t handle, odp_queue_info_t *info)
{
	uint32_t queue_id;
	queue_entry_t *queue;
	int status;

	if (odp_unlikely(info == NULL)) {
		ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_id(handle);

	if (odp_unlikely(queue_id >= ODP_CONFIG_QUEUES)) {
		ODP_ERR("Invalid queue handle:%" PRIu64 "\n",
			odp_queue_to_u64(handle));
		return -1;
	}

	queue = get_qentry(queue_id);

	LOCK(&queue->s.lock);
	status = queue->s.status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->s.name;
	info->param = queue->s.param;

	UNLOCK(&queue->s.lock);

	return 0;
}

int sched_cb_num_queues(void)
{
	return ODP_CONFIG_QUEUES;
}

int sched_cb_queue_prio(uint32_t queue_index)
{
	queue_entry_t *qe = get_qentry(queue_index);

	return qe->s.param.sched.prio;
}

int sched_cb_queue_grp(uint32_t queue_index)
{
	queue_entry_t *qe = get_qentry(queue_index);

	return qe->s.param.sched.group;
}

int sched_cb_queue_is_ordered(uint32_t queue_index)
{
	return queue_is_ordered(get_qentry(queue_index));
}

int sched_cb_queue_is_atomic(uint32_t queue_index)
{
	return queue_is_atomic(get_qentry(queue_index));
}

odp_queue_t sched_cb_queue_handle(uint32_t queue_index)
{
	return queue_from_id(queue_index);
}

int sched_cb_queue_deq_multi(uint32_t queue_index, odp_event_t ev[], int num)
{
	int i, ret;
	queue_entry_t *qe = get_qentry(queue_index);
	odp_buffer_hdr_t *buf_hdr[num];

	ret = deq_multi(qe, buf_hdr, num);

	if (ret > 0)
		for (i = 0; i < ret; i++)
			ev[i] = odp_buffer_to_event(buf_hdr[i]->handle.handle);

	return ret;
}

int sched_cb_queue_empty(uint32_t queue_index)
{
	queue_entry_t *queue = get_qentry(queue_index);
	int ret = 0;

	LOCK(&queue->s.lock);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		UNLOCK(&queue->s.lock);
		return -1;
	}

	if (queue->s.head == NULL) {
		/* Already empty queue. Update status. */
		if (queue->s.status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		ret = 1;
	}

	UNLOCK(&queue->s.lock);

	return ret;
}

uint64_t odp_queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}
