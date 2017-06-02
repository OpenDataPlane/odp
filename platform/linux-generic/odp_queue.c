/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/queue.h>
#include <odp_queue_internal.h>
#include <odp_queue_if.h>
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

static queue_t queue_from_ext(odp_queue_t handle);
static int _queue_enq(queue_t handle, odp_buffer_hdr_t *buf_hdr);
static odp_buffer_hdr_t *_queue_deq(queue_t handle);

static int _queue_enq_multi(queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num);
static int _queue_deq_multi(queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num);

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

	queue->s.enqueue = _queue_enq;
	queue->s.dequeue = _queue_deq;
	queue->s.enqueue_multi = _queue_enq_multi;
	queue->s.dequeue_multi = _queue_deq_multi;

	queue->s.pktin = PKTIN_INVALID;
	queue->s.pktout = PKTOUT_INVALID;

	queue->s.head = NULL;
	queue->s.tail = NULL;

	return 0;
}


static int queue_init_global(void)
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

static int queue_init_local(void)
{
	return 0;
}

static int queue_term_local(void)
{
	return 0;
}

static int queue_term_global(void)
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

static int queue_capability(odp_queue_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = ODP_CONFIG_QUEUES - NUM_INTERNAL_QUEUES;
	capa->max_ordered_locks = sched_fn->max_ordered_locks();
	capa->max_sched_groups  = sched_fn->num_grps();
	capa->sched_prios       = odp_schedule_num_prio();
	capa->plain.max_num     = capa->max_queues;
	capa->sched.max_num     = capa->max_queues;

	return 0;
}

static odp_queue_type_t queue_type(odp_queue_t handle)
{
	return qentry_from_int(queue_from_ext(handle))->s.type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return qentry_from_int(queue_from_ext(handle))->s.param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return qentry_from_int(queue_from_ext(handle))->s.param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return qentry_from_int(queue_from_ext(handle))->s.param.sched.group;
}

static int queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_int(queue_from_ext(handle));

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		(int)queue->s.param.sched.lock_count : -1;
}

static odp_queue_t queue_create(const char *name,
				const odp_queue_param_t *param)
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

static int queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = qentry_from_int(queue_from_ext(handle));

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

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	qentry_from_int(queue_from_ext(handle))->s.param.context = context;
	odp_mb_full();
	return 0;
}

static void *queue_context(odp_queue_t handle)
{
	return qentry_from_int(queue_from_ext(handle))->s.param.context;
}

static odp_queue_t queue_lookup(const char *name)
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

static inline int enq_multi(queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	int sched = 0;
	int i, ret;
	queue_entry_t *queue;
	odp_buffer_hdr_t *hdr, *tail, *next_hdr;

	queue = qentry_from_int(handle);
	if (sched_fn->ord_enq_multi(handle, (void **)buf_hdr, num, &ret))
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

static int _queue_enq_multi(queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	return enq_multi(handle, buf_hdr, num);
}

static int _queue_enq(queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = enq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = qentry_from_int(queue_from_ext(handle));

	for (i = 0; i < num; i++)
		buf_hdr[i] = buf_hdl_to_hdr(odp_buffer_from_event(ev[i]));

	return num == 0 ? 0 : queue->s.enqueue_multi(qentry_to_int(queue),
						     buf_hdr, num);
}

static int queue_enq(odp_queue_t handle, odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue   = qentry_from_int(queue_from_ext(handle));
	buf_hdr = buf_hdl_to_hdr(odp_buffer_from_event(ev));

	return queue->s.enqueue(qentry_to_int(queue), buf_hdr);
}

static inline int deq_multi(queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	odp_buffer_hdr_t *hdr, *next;
	int i, j;
	queue_entry_t *queue;
	int updated = 0;

	queue = qentry_from_int(handle);
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

static int _queue_deq_multi(queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	return deq_multi(handle, buf_hdr, num);
}

static odp_buffer_hdr_t *_queue_deq(queue_t handle)
{
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = deq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

static int queue_deq_multi(odp_queue_t handle, odp_event_t events[], int num)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	int i, ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = qentry_from_int(queue_from_ext(handle));

	ret = queue->s.dequeue_multi(qentry_to_int(queue), buf_hdr, num);

	for (i = 0; i < ret; i++)
		events[i] = odp_buffer_to_event(buf_hdr[i]->handle.handle);

	return ret;
}


static odp_event_t queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr;

	queue   = qentry_from_int(queue_from_ext(handle));
	buf_hdr = queue->s.dequeue(qentry_to_int(queue));

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

static void queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	params->sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	params->sched.group = ODP_SCHED_GROUP_ALL;
}

static int queue_info(odp_queue_t handle, odp_queue_info_t *info)
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

	ret = deq_multi(qentry_to_int(qe), buf_hdr, num);

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

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(queue_t handle)
{
	return qentry_from_int(handle)->s.pktout;
}

static void queue_set_pktout(queue_t handle, odp_pktio_t pktio, int index)
{
	qentry_from_int(handle)->s.pktout.pktio = pktio;
	qentry_from_int(handle)->s.pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(queue_t handle)
{
	return qentry_from_int(handle)->s.pktin;
}

static void queue_set_pktin(queue_t handle, odp_pktio_t pktio, int index)
{
	qentry_from_int(handle)->s.pktin.pktio = pktio;
	qentry_from_int(handle)->s.pktin.index = index;
}

static void queue_set_enq_func(queue_t handle, queue_enq_fn_t func)
{
	qentry_from_int(handle)->s.enqueue = func;
}

static void queue_set_enq_multi_func(queue_t handle, queue_enq_multi_fn_t func)
{
	qentry_from_int(handle)->s.enqueue_multi = func;
}

static void queue_set_deq_func(queue_t handle, queue_deq_fn_t func)
{
	qentry_from_int(handle)->s.dequeue = func;
}

static void queue_set_deq_multi_func(queue_t handle, queue_deq_multi_fn_t func)
{
	qentry_from_int(handle)->s.dequeue_multi = func;
}

static void queue_set_type(queue_t handle, odp_queue_type_t type)
{
	qentry_from_int(handle)->s.type = type;
}

static queue_t queue_from_ext(odp_queue_t handle)
{
	uint32_t queue_id;

	queue_id = queue_to_id(handle);
	return qentry_to_int(get_qentry(queue_id));
}

static odp_queue_t queue_to_ext(queue_t handle)
{
	return qentry_from_int(handle)->s.handle;
}

/* API functions */
queue_api_t queue_default_api = {
	.queue_create = queue_create,
	.queue_destroy = queue_destroy,
	.queue_lookup = queue_lookup,
	.queue_capability = queue_capability,
	.queue_context_set = queue_context_set,
	.queue_context = queue_context,
	.queue_enq = queue_enq,
	.queue_enq_multi = queue_enq_multi,
	.queue_deq = queue_deq,
	.queue_deq_multi = queue_deq_multi,
	.queue_type = queue_type,
	.queue_sched_type = queue_sched_type,
	.queue_sched_prio = queue_sched_prio,
	.queue_sched_group = queue_sched_group,
	.queue_lock_count = queue_lock_count,
	.queue_to_u64 = queue_to_u64,
	.queue_param_init = queue_param_init,
	.queue_info = queue_info
};

/* Functions towards internal components */
queue_fn_t queue_default_fn = {
	.init_global = queue_init_global,
	.term_global = queue_term_global,
	.init_local = queue_init_local,
	.term_local = queue_term_local,
	.from_ext = queue_from_ext,
	.to_ext = queue_to_ext,
	.enq = _queue_enq,
	.enq_multi = _queue_enq_multi,
	.deq = _queue_deq,
	.deq_multi = _queue_deq_multi,
	.get_pktout = queue_get_pktout,
	.set_pktout = queue_set_pktout,
	.get_pktin = queue_get_pktin,
	.set_pktin = queue_set_pktin,
	.set_enq_fn = queue_set_enq_func,
	.set_enq_multi_fn = queue_set_enq_multi_func,
	.set_deq_fn = queue_set_deq_func,
	.set_deq_multi_fn = queue_set_deq_multi_func,
	.set_type = queue_set_type
};
