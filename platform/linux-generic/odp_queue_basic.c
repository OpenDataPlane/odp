/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/queue.h>
#include <odp_queue_internal.h>
#include <odp_queue_if.h>
#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_config_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/sync.h>
#include <odp/api/traffic_mngr.h>
#include <odp_libconfig_internal.h>

#define NUM_INTERNAL_QUEUES 64

#include <odp/api/plat/ticketlock_inlines.h>
#define LOCK(queue_ptr)      _odp_ticketlock_lock(&((queue_ptr)->s.lock))
#define UNLOCK(queue_ptr)    _odp_ticketlock_unlock(&((queue_ptr)->s.lock))
#define LOCK_INIT(queue_ptr)  odp_ticketlock_init(&((queue_ptr)->s.lock))

#include <string.h>
#include <inttypes.h>

#define MIN_QUEUE_SIZE 8
#define MAX_QUEUE_SIZE (1 * 1024 * 1024)

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param);

queue_global_t *queue_glb;

static inline queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_glb->queue[queue_id];
}

static inline queue_entry_t *handle_to_qentry(odp_queue_t handle)
{
	uint32_t queue_id = queue_to_index(handle);

	return get_qentry(queue_id);
}

static int queue_capa(odp_queue_capability_t *capa, int sched)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = ODP_CONFIG_QUEUES - NUM_INTERNAL_QUEUES;
	capa->plain.max_num     = capa->max_queues;
	capa->plain.max_size    = queue_glb->config.max_queue_size;
	capa->plain.lockfree.max_num  = queue_glb->queue_lf_num;
	capa->plain.lockfree.max_size = queue_glb->queue_lf_size;
	capa->sched.max_num     = capa->max_queues;
	capa->sched.max_size    = queue_glb->config.max_queue_size;

	if (sched) {
		capa->max_ordered_locks = sched_fn->max_ordered_locks();
		capa->max_sched_groups  = sched_fn->num_grps();
		capa->sched_prios       = odp_schedule_num_prio();
	}

	return 0;
}

static int read_config_file(queue_global_t *queue_glb)
{
	const char *str;
	uint32_t val_u32;
	int val = 0;

	ODP_PRINT("Queue config:\n");

	str = "queue_basic.max_queue_size";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	val_u32 = val;

	if (val_u32 > MAX_QUEUE_SIZE || val_u32 < MIN_QUEUE_SIZE ||
	    !CHECK_IS_POWER2(val_u32)) {
		ODP_ERR("Bad value %s = %u\n", str, val_u32);
		return -1;
	}

	queue_glb->config.max_queue_size = val_u32;
	ODP_PRINT("  %s: %u\n", str, val_u32);

	str = "queue_basic.default_queue_size";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	val_u32 = val;

	if (val_u32 > queue_glb->config.max_queue_size ||
	    val_u32 < MIN_QUEUE_SIZE ||
	    !CHECK_IS_POWER2(val_u32)) {
		ODP_ERR("Bad value %s = %u\n", str, val_u32);
		return -1;
	}

	queue_glb->config.default_queue_size = val_u32;
	ODP_PRINT("  %s: %u\n\n", str, val_u32);

	return 0;
}

static int queue_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;
	uint32_t lf_size = 0;
	queue_lf_func_t *lf_func;
	odp_queue_capability_t capa;
	uint64_t mem_size;

	ODP_DBG("Starts...\n");

	shm = odp_shm_reserve("_odp_queue_gbl",
			      sizeof(queue_global_t),
			      sizeof(queue_entry_t), 0);

	queue_glb = odp_shm_addr(shm);

	if (queue_glb == NULL)
		return -1;

	memset(queue_glb, 0, sizeof(queue_global_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);
		LOCK_INIT(queue);
		queue->s.index  = i;
		queue->s.handle = queue_from_index(i);
	}

	if (read_config_file(queue_glb)) {
		odp_shm_free(shm);
		return -1;
	}

	queue_glb->queue_gbl_shm = shm;
	mem_size = sizeof(uint32_t) * ODP_CONFIG_QUEUES *
		   (uint64_t)queue_glb->config.max_queue_size;

	shm = odp_shm_reserve("_odp_queue_rings", mem_size,
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		odp_shm_free(queue_glb->queue_gbl_shm);
		return -1;
	}

	queue_glb->queue_ring_shm = shm;
	queue_glb->ring_data      = odp_shm_addr(shm);

	lf_func = &queue_glb->queue_lf_func;
	queue_glb->queue_lf_num  = queue_lf_init_global(&lf_size, lf_func);
	queue_glb->queue_lf_size = lf_size;

	queue_capa(&capa, 0);

	ODP_DBG("... done.\n");
	ODP_DBG("  queue_entry_t size %u\n", sizeof(queue_entry_t));
	ODP_DBG("  max num queues     %u\n", capa.max_queues);
	ODP_DBG("  max queue size     %u\n", capa.plain.max_size);
	ODP_DBG("  max num lockfree   %u\n", capa.plain.lockfree.max_num);
	ODP_DBG("  max lockfree size  %u\n\n", capa.plain.lockfree.max_size);

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
	queue_entry_t *queue;
	int i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_glb->queue[i];
		LOCK(queue);
		if (queue->s.status != QUEUE_STATUS_FREE) {
			ODP_ERR("Not destroyed queue: %s\n", queue->s.name);
			ret = -1;
		}
		UNLOCK(queue);
	}

	queue_lf_term_global();

	if (odp_shm_free(queue_glb->queue_ring_shm)) {
		ODP_ERR("shm free failed");
		ret = -1;
	}

	if (odp_shm_free(queue_glb->queue_gbl_shm)) {
		ODP_ERR("shm free failed");
		ret = -1;
	}

	return ret;
}

static int queue_capability(odp_queue_capability_t *capa)
{
	return queue_capa(capa, 1);
}

static odp_queue_type_t queue_type(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->s.param.sched.lock_count : 0;
}

static odp_queue_t queue_create(const char *name,
				const odp_queue_param_t *param)
{
	uint32_t i;
	queue_entry_t *queue;
	void *queue_lf;
	odp_queue_t handle = ODP_QUEUE_INVALID;
	odp_queue_type_t type = ODP_QUEUE_TYPE_PLAIN;
	odp_queue_param_t default_param;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}

	if (param->nonblocking == ODP_BLOCKING) {
		if (param->size > queue_glb->config.max_queue_size)
			return ODP_QUEUE_INVALID;
	} else if (param->nonblocking == ODP_NONBLOCKING_LF) {
		/* Only plain type lock-free queues supported */
		if (param->type != ODP_QUEUE_TYPE_PLAIN)
			return ODP_QUEUE_INVALID;
		if (param->size > queue_glb->queue_lf_size)
			return ODP_QUEUE_INVALID;
	} else {
		/* Wait-free queues not supported */
		return ODP_QUEUE_INVALID;
	}

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_glb->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(queue);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(queue);
				return ODP_QUEUE_INVALID;
			}

			if (param->nonblocking == ODP_NONBLOCKING_LF) {
				queue_lf_func_t *lf_func;

				lf_func = &queue_glb->queue_lf_func;

				queue_lf = queue_lf_create(queue);

				if (queue_lf == NULL) {
					UNLOCK(queue);
					return ODP_QUEUE_INVALID;
				}
				queue->s.queue_lf = queue_lf;

				queue->s.enqueue       = lf_func->enq;
				queue->s.enqueue_multi = lf_func->enq_multi;
				queue->s.dequeue       = lf_func->deq;
				queue->s.dequeue_multi = lf_func->deq_multi;
			}

			type = queue->s.type;

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;
			UNLOCK(queue);
			break;
		}
		UNLOCK(queue);
	}

	if (handle == ODP_QUEUE_INVALID)
		return ODP_QUEUE_INVALID;

	if (type == ODP_QUEUE_TYPE_SCHED) {
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

	LOCK(queue);

	if (queue->s.status == QUEUE_STATUS_DESTROYED) {
		queue->s.status = QUEUE_STATUS_FREE;
		sched_fn->destroy_queue(queue_index);
	}
	UNLOCK(queue);
}

void sched_cb_queue_set_status(uint32_t queue_index, int status)
{
	queue_entry_t *queue = get_qentry(queue_index);

	LOCK(queue);

	queue->s.status = status;

	UNLOCK(queue);
}

static int queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = handle_to_qentry(handle);

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	LOCK(queue);
	if (queue->s.status == QUEUE_STATUS_FREE) {
		UNLOCK(queue);
		ODP_ERR("queue \"%s\" already free\n", queue->s.name);
		return -1;
	}
	if (queue->s.status == QUEUE_STATUS_DESTROYED) {
		UNLOCK(queue);
		ODP_ERR("queue \"%s\" already destroyed\n", queue->s.name);
		return -1;
	}
	if (ring_st_is_empty(&queue->s.ring_st) == 0) {
		UNLOCK(queue);
		ODP_ERR("queue \"%s\" not empty\n", queue->s.name);
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

	if (queue->s.param.nonblocking == ODP_NONBLOCKING_LF)
		queue_lf_destroy(queue->s.queue_lf);

	UNLOCK(queue);

	return 0;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	handle_to_qentry(handle)->s.param.context = context;
	odp_mb_full();
	return 0;
}

static void *queue_context(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.context;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_glb->queue[i];

		if (queue->s.status == QUEUE_STATUS_FREE ||
		    queue->s.status == QUEUE_STATUS_DESTROYED)
			continue;

		LOCK(queue);
		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			UNLOCK(queue);
			return queue->s.handle;
		}
		UNLOCK(queue);
	}

	return ODP_QUEUE_INVALID;
}

static inline void buffer_index_from_buf(uint32_t buffer_index[],
					 odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		buffer_index[i] = buf_hdr[i]->index.u32;
}

static inline void buffer_index_to_buf(odp_buffer_hdr_t *buf_hdr[],
				       uint32_t buffer_index[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		buf_hdr[i] = buf_hdr_from_index_u32(buffer_index[i]);
		odp_prefetch(buf_hdr[i]);
	}
}

static inline int enq_multi(queue_t q_int, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	int sched = 0;
	int ret;
	queue_entry_t *queue;
	int num_enq;
	ring_st_t *ring_st;
	uint32_t buf_idx[num];

	queue = qentry_from_int(q_int);
	ring_st = &queue->s.ring_st;

	if (sched_fn->ord_enq_multi(q_int, (void **)buf_hdr, num, &ret))
		return ret;

	buffer_index_from_buf(buf_idx, buf_hdr, num);

	LOCK(queue);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(queue);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	num_enq = ring_st_enq_multi(ring_st, buf_idx, num);

	if (odp_unlikely(num_enq == 0)) {
		UNLOCK(queue);
		return 0;
	}

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1;
	}

	UNLOCK(queue);

	/* Add queue to scheduling */
	if (sched && sched_fn->sched_queue(queue->s.index))
		ODP_ABORT("schedule_queue failed\n");

	return num_enq;
}

static int queue_int_enq_multi(queue_t q_int, odp_buffer_hdr_t *buf_hdr[],
			       int num)
{
	return enq_multi(q_int, buf_hdr, num);
}

static int queue_int_enq(queue_t q_int, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = enq_multi(q_int, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	if (odp_unlikely(num == 0))
		return 0;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	return queue->s.enqueue_multi(qentry_to_int(queue),
				      (odp_buffer_hdr_t **)(uintptr_t)ev, num);
}

static int queue_enq(odp_queue_t handle, odp_event_t ev)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	return queue->s.enqueue(qentry_to_int(queue),
				(odp_buffer_hdr_t *)(uintptr_t)ev);
}

static inline int deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num, int update_status)
{
	int status_sync = sched_fn->status_sync;
	int num_deq;
	ring_st_t *ring_st;
	uint32_t buf_idx[num];

	ring_st = &queue->s.ring_st;

	LOCK(queue);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed.
		 * Scheduler finalizes queue destroy after this. */
		UNLOCK(queue);
		return -1;
	}

	num_deq = ring_st_deq_multi(ring_st, buf_idx, num);

	if (num_deq == 0) {
		/* Already empty queue */
		if (update_status && queue->s.status == QUEUE_STATUS_SCHED) {
			queue->s.status = QUEUE_STATUS_NOTSCHED;

			if (status_sync)
				sched_fn->unsched_queue(queue->s.index);
		}

		UNLOCK(queue);

		return 0;
	}

	if (status_sync && queue->s.type == ODP_QUEUE_TYPE_SCHED)
		sched_fn->save_context(queue->s.index);

	UNLOCK(queue);

	buffer_index_to_buf(buf_hdr, buf_idx, num_deq);

	return num_deq;
}

static int queue_int_deq_multi(queue_t q_int, odp_buffer_hdr_t *buf_hdr[],
			       int num)
{
	queue_entry_t *queue = qentry_from_int(q_int);

	return deq_multi(queue, buf_hdr, num, 0);
}

static odp_buffer_hdr_t *queue_int_deq(queue_t q_int)
{
	queue_entry_t *queue = qentry_from_int(q_int);
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = deq_multi(queue, &buf_hdr, 1, 0);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

static int queue_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	return queue->s.dequeue_multi(qentry_to_int(queue),
				      (odp_buffer_hdr_t **)ev, num);
}

static odp_event_t queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	return (odp_event_t)queue->s.dequeue(qentry_to_int(queue));
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	uint64_t offset;
	uint32_t queue_size;

	if (name == NULL) {
		queue->s.name[0] = 0;
	} else {
		strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
		queue->s.name[ODP_QUEUE_NAME_LEN - 1] = 0;
	}
	memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	if (queue->s.param.sched.lock_count > sched_fn->max_ordered_locks())
		return -1;

	if (param->type == ODP_QUEUE_TYPE_SCHED)
		queue->s.param.deq_mode = ODP_QUEUE_OP_DISABLED;

	queue->s.type = queue->s.param.type;

	queue->s.enqueue = queue_int_enq;
	queue->s.dequeue = queue_int_deq;
	queue->s.enqueue_multi = queue_int_enq_multi;
	queue->s.dequeue_multi = queue_int_deq_multi;

	queue->s.pktin = PKTIN_INVALID;
	queue->s.pktout = PKTOUT_INVALID;

	/* Use default size for all small queues to quarantee performance
	 * level. */
	queue_size = queue_glb->config.default_queue_size;
	if (param->size > queue_glb->config.default_queue_size)
		queue_size = param->size;

	/* Round up if not already a power of two */
	queue_size = ROUNDUP_POWER2_U32(queue_size);

	if (queue_size > queue_glb->config.max_queue_size) {
		ODP_ERR("Too large queue size %u\n", queue_size);
		return -1;
	}

	offset = queue->s.index * (uint64_t)queue_glb->config.max_queue_size;

	ring_st_init(&queue->s.ring_st, &queue_glb->ring_data[offset],
		     queue_size);

	return 0;
}

static void queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->nonblocking = ODP_BLOCKING;
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

	queue_id = queue_to_index(handle);

	if (odp_unlikely(queue_id >= ODP_CONFIG_QUEUES)) {
		ODP_ERR("Invalid queue handle:%" PRIu64 "\n",
			odp_queue_to_u64(handle));
		return -1;
	}

	queue = get_qentry(queue_id);

	LOCK(queue);
	status = queue->s.status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(queue);
		ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->s.name;
	info->param = queue->s.param;

	UNLOCK(queue);

	return 0;
}

int sched_cb_queue_deq_multi(uint32_t queue_index, odp_event_t ev[], int num,
			     int update_status)
{
	queue_entry_t *qe = get_qentry(queue_index);

	return deq_multi(qe, (odp_buffer_hdr_t **)ev, num, update_status);
}

int sched_cb_queue_empty(uint32_t queue_index)
{
	queue_entry_t *queue = get_qentry(queue_index);
	int ret = 0;

	LOCK(queue);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		UNLOCK(queue);
		return -1;
	}

	if (ring_st_is_empty(&queue->s.ring_st)) {
		/* Already empty queue. Update status. */
		if (queue->s.status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		ret = 1;
	}

	UNLOCK(queue);

	return ret;
}

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(queue_t q_int)
{
	return qentry_from_int(q_int)->s.pktout;
}

static void queue_set_pktout(queue_t q_int, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_int(q_int);

	qentry->s.pktout.pktio = pktio;
	qentry->s.pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(queue_t q_int)
{
	return qentry_from_int(q_int)->s.pktin;
}

static void queue_set_pktin(queue_t q_int, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_int(q_int);

	qentry->s.pktin.pktio = pktio;
	qentry->s.pktin.index = index;
}

static void queue_set_enq_deq_func(queue_t q_int,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	queue_entry_t *qentry = qentry_from_int(q_int);

	if (enq)
		qentry->s.enqueue = enq;

	if (enq_multi)
		qentry->s.enqueue_multi = enq_multi;

	if (deq)
		qentry->s.dequeue = deq;

	if (deq_multi)
		qentry->s.dequeue_multi = deq_multi;
}

static queue_t queue_from_ext(odp_queue_t handle)
{
	return qentry_to_int(handle_to_qentry(handle));
}

static odp_queue_t queue_to_ext(queue_t q_int)
{
	return qentry_from_int(q_int)->s.handle;
}

/* API functions */
queue_api_t queue_basic_api = {
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
queue_fn_t queue_basic_fn = {
	.init_global = queue_init_global,
	.term_global = queue_term_global,
	.init_local = queue_init_local,
	.term_local = queue_term_local,
	.from_ext = queue_from_ext,
	.to_ext = queue_to_ext,
	.enq = queue_int_enq,
	.enq_multi = queue_int_enq_multi,
	.deq = queue_int_deq,
	.deq_multi = queue_int_deq_multi,
	.get_pktout = queue_get_pktout,
	.set_pktout = queue_set_pktout,
	.get_pktin = queue_get_pktin,
	.set_pktin = queue_set_pktin,
	.set_enq_deq_fn = queue_set_enq_deq_func
};
