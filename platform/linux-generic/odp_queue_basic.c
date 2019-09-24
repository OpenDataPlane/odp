/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/queue.h>
#include <odp_queue_basic_internal.h>
#include <odp_queue_if.h>
#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_init_internal.h>
#include <odp_timer_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_config_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/sync.h>
#include <odp/api/plat/sync_inlines.h>
#include <odp/api/traffic_mngr.h>
#include <odp_libconfig_internal.h>
#include <odp/api/plat/queue_inline_types.h>
#include <odp_global_data.h>

#include <odp/api/plat/ticketlock_inlines.h>
#define LOCK(queue_ptr)      odp_ticketlock_lock(&((queue_ptr)->s.lock))
#define UNLOCK(queue_ptr)    odp_ticketlock_unlock(&((queue_ptr)->s.lock))
#define LOCK_INIT(queue_ptr) odp_ticketlock_init(&((queue_ptr)->s.lock))

#include <string.h>
#include <inttypes.h>

#define MIN_QUEUE_SIZE 32
#define MAX_QUEUE_SIZE (1 * 1024 * 1024)

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param);

queue_global_t *queue_glb;
extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

static int queue_capa(odp_queue_capability_t *capa, int sched ODP_UNUSED)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = CONFIG_MAX_QUEUES - CONFIG_INTERNAL_QUEUES;
	capa->plain.max_num     = CONFIG_MAX_PLAIN_QUEUES;
	capa->plain.max_size    = queue_glb->config.max_queue_size;
	capa->plain.lockfree.max_num  = queue_glb->queue_lf_num;
	capa->plain.lockfree.max_size = queue_glb->queue_lf_size;
#if ODP_DEPRECATED_API
	capa->sched.max_num     = CONFIG_MAX_SCHED_QUEUES;
	capa->sched.max_size    = queue_glb->config.max_queue_size;

	if (sched) {
		capa->max_ordered_locks = sched_fn->max_ordered_locks();
		capa->max_sched_groups  = sched_fn->num_grps();
		capa->sched_prios       = odp_schedule_num_prio();
	}
#endif

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

	/* Fill in queue entry field offsets for inline functions */
	memset(&_odp_queue_inline_offset, 0,
	       sizeof(_odp_queue_inline_offset_t));
	_odp_queue_inline_offset.context = offsetof(queue_entry_t,
						    s.param.context);

	shm = odp_shm_reserve("_odp_queue_gbl",
			      sizeof(queue_global_t),
			      sizeof(queue_entry_t),
			      0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	queue_glb = odp_shm_addr(shm);

	memset(queue_glb, 0, sizeof(queue_global_t));

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = qentry_from_index(i);
		LOCK_INIT(queue);
		queue->s.index  = i;
		queue->s.handle = (odp_queue_t)queue;
	}

	if (read_config_file(queue_glb)) {
		odp_shm_free(shm);
		return -1;
	}

	queue_glb->queue_gbl_shm = shm;
	mem_size = sizeof(uint32_t) * CONFIG_MAX_QUEUES *
		   (uint64_t)queue_glb->config.max_queue_size;

	shm = odp_shm_reserve("_odp_queue_rings", mem_size,
			      ODP_CACHE_LINE_SIZE,
			      0);

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

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue = qentry_from_index(i);
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
	return qentry_from_handle(handle)->s.type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return qentry_from_handle(handle)->s.param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return qentry_from_handle(handle)->s.param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return qentry_from_handle(handle)->s.param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->s.param.sched.lock_count : 0;
}

static odp_queue_t queue_create(const char *name,
				const odp_queue_param_t *param)
{
	uint32_t i;
	uint32_t max_idx;
	queue_entry_t *queue;
	void *queue_lf;
	odp_queue_type_t type;
	odp_queue_param_t default_param;
	odp_queue_t handle = ODP_QUEUE_INVALID;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}

	type = param->type;

	if (type == ODP_QUEUE_TYPE_SCHED) {
		if (param->sched.prio < odp_schedule_min_prio() ||
		    param->sched.prio > odp_schedule_max_prio()) {
			ODP_ERR("Bad queue priority: %i\n", param->sched.prio);
			return ODP_QUEUE_INVALID;
		}
	}

	if (param->nonblocking == ODP_BLOCKING) {
		if (param->size > queue_glb->config.max_queue_size)
			return ODP_QUEUE_INVALID;
	} else if (param->nonblocking == ODP_NONBLOCKING_LF) {
		/* Only plain type lock-free queues supported */
		if (type != ODP_QUEUE_TYPE_PLAIN)
			return ODP_QUEUE_INVALID;
		if (param->size > queue_glb->queue_lf_size)
			return ODP_QUEUE_INVALID;
	} else {
		/* Wait-free queues not supported */
		return ODP_QUEUE_INVALID;
	}

	if (type == ODP_QUEUE_TYPE_SCHED) {
		/* Start scheduled queue indices from zero to enable direct
		 * mapping to scheduler implementation indices. */
		i = 0;
		max_idx = CONFIG_MAX_SCHED_QUEUES;
	} else {
		i = CONFIG_MAX_SCHED_QUEUES;
		/* All internal queues are of type plain */
		max_idx = CONFIG_MAX_QUEUES;
	}

	for (; i < max_idx; i++) {
		queue = qentry_from_index(i);

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(queue);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(queue);
				return ODP_QUEUE_INVALID;
			}

			if (!queue->s.spsc &&
			    param->nonblocking == ODP_NONBLOCKING_LF) {
				queue_lf_func_t *lf_fn;

				lf_fn = &queue_glb->queue_lf_func;

				queue_lf = queue_lf_create(queue);

				if (queue_lf == NULL) {
					UNLOCK(queue);
					return ODP_QUEUE_INVALID;
				}
				queue->s.queue_lf = queue_lf;

				queue->s.enqueue       = lf_fn->enq;
				queue->s.enqueue_multi = lf_fn->enq_multi;
				queue->s.dequeue       = lf_fn->deq;
				queue->s.dequeue_multi = lf_fn->deq_multi;
				queue->s.orig_dequeue_multi = lf_fn->deq_multi;
			}

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
		if (sched_fn->create_queue(queue->s.index,
					   &queue->s.param.sched)) {
			queue->s.status = QUEUE_STATUS_FREE;
			ODP_ERR("schedule queue init failed\n");
			return ODP_QUEUE_INVALID;
		}
	}

	return handle;
}

void sched_queue_set_status(uint32_t queue_index, int status)
{
	queue_entry_t *queue = qentry_from_index(queue_index);

	LOCK(queue);

	queue->s.status = status;

	UNLOCK(queue);
}

static int queue_destroy(odp_queue_t handle)
{
	int empty;
	queue_entry_t *queue;
	queue = qentry_from_handle(handle);

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

	if (queue->s.spsc)
		empty = ring_spsc_is_empty(&queue->s.ring_spsc);
	else if (queue->s.type == ODP_QUEUE_TYPE_SCHED)
		empty = ring_st_is_empty(&queue->s.ring_st);
	else
		empty = ring_mpmc_is_empty(&queue->s.ring_mpmc);

	if (!empty) {
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

	if (queue->s.queue_lf)
		queue_lf_destroy(queue->s.queue_lf);

	UNLOCK(queue);

	return 0;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	qentry_from_handle(handle)->s.param.context = context;
	odp_mb_full();
	return 0;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue_entry_t *queue = qentry_from_index(i);

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

static inline int _plain_queue_enq_multi(odp_queue_t handle,
					 odp_buffer_hdr_t *buf_hdr[], int num)
{
	queue_entry_t *queue;
	int ret, num_enq;
	ring_mpmc_t *ring_mpmc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_mpmc = &queue->s.ring_mpmc;

	if (sched_fn->ord_enq_multi(handle, (void **)buf_hdr, num, &ret))
		return ret;

	buffer_index_from_buf(buf_idx, buf_hdr, num);

	num_enq = ring_mpmc_enq_multi(ring_mpmc, queue->s.ring_data,
				      queue->s.ring_mask, buf_idx, num);

	return num_enq;
}

static inline int _plain_queue_deq_multi(odp_queue_t handle,
					 odp_buffer_hdr_t *buf_hdr[], int num)
{
	int num_deq;
	queue_entry_t *queue;
	ring_mpmc_t *ring_mpmc;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_mpmc = &queue->s.ring_mpmc;

	num_deq = ring_mpmc_deq_multi(ring_mpmc, queue->s.ring_data,
				      queue->s.ring_mask, buf_idx, num);

	if (num_deq == 0)
		return 0;

	buffer_index_to_buf(buf_hdr, buf_idx, num_deq);

	return num_deq;
}

static int plain_queue_enq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	return _plain_queue_enq_multi(handle, buf_hdr, num);
}

static int plain_queue_enq(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = _plain_queue_enq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int plain_queue_deq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	return _plain_queue_deq_multi(handle, buf_hdr, num);
}

static odp_buffer_hdr_t *plain_queue_deq(odp_queue_t handle)
{
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = _plain_queue_deq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

static int error_enqueue(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	(void)buf_hdr;

	ODP_ERR("Enqueue not supported (0x%" PRIx64 ")\n",
		odp_queue_to_u64(handle));

	return -1;
}

static int error_enqueue_multi(odp_queue_t handle,
			       odp_buffer_hdr_t *buf_hdr[], int num)
{
	(void)buf_hdr;
	(void)num;

	ODP_ERR("Enqueue multi not supported (0x%" PRIx64 ")\n",
		odp_queue_to_u64(handle));

	return -1;
}

static odp_buffer_hdr_t *error_dequeue(odp_queue_t handle)
{
	ODP_ERR("Dequeue not supported (0x%" PRIx64 ")\n",
		odp_queue_to_u64(handle));

	return NULL;
}

static int error_dequeue_multi(odp_queue_t handle,
			       odp_buffer_hdr_t *buf_hdr[], int num)
{
	(void)buf_hdr;
	(void)num;

	ODP_ERR("Dequeue multi not supported (0x%" PRIx64 ")\n",
		odp_queue_to_u64(handle));

	return -1;
}

static void queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->nonblocking = ODP_BLOCKING;
	params->order = ODP_QUEUE_ORDER_KEEP;
	params->sched.prio  = odp_schedule_default_prio();
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

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		ODP_ERR("Invalid queue handle: 0x%" PRIx64 "\n",
			odp_queue_to_u64(handle));
		return -1;
	}

	queue = qentry_from_index(queue_id);

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

static inline int _sched_queue_enq_multi(odp_queue_t handle,
					 odp_buffer_hdr_t *buf_hdr[], int num)
{
	int sched = 0;
	int ret;
	queue_entry_t *queue;
	int num_enq;
	ring_st_t *ring_st;
	uint32_t buf_idx[num];

	queue = qentry_from_handle(handle);
	ring_st = &queue->s.ring_st;

	if (sched_fn->ord_enq_multi(handle, (void **)buf_hdr, num, &ret))
		return ret;

	buffer_index_from_buf(buf_idx, buf_hdr, num);

	LOCK(queue);

	num_enq = ring_st_enq_multi(ring_st, queue->s.ring_data,
				    queue->s.ring_mask, buf_idx, num);

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

int sched_queue_deq(uint32_t queue_index, odp_event_t ev[], int max_num,
		    int update_status)
{
	int num_deq, status;
	ring_st_t *ring_st;
	queue_entry_t *queue = qentry_from_index(queue_index);
	uint32_t buf_idx[max_num];

	ring_st = &queue->s.ring_st;

	LOCK(queue);

	status = queue->s.status;

	if (odp_unlikely(status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed.
		 * Inform scheduler about a destroyed queue. */
		if (queue->s.status == QUEUE_STATUS_DESTROYED) {
			queue->s.status = QUEUE_STATUS_FREE;
			sched_fn->destroy_queue(queue_index);
		}

		UNLOCK(queue);
		return -1;
	}

	num_deq = ring_st_deq_multi(ring_st, queue->s.ring_data,
				    queue->s.ring_mask, buf_idx, max_num);

	if (num_deq == 0) {
		/* Already empty queue */
		if (update_status && status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		UNLOCK(queue);

		return 0;
	}

	UNLOCK(queue);

	buffer_index_to_buf((odp_buffer_hdr_t **)ev, buf_idx, num_deq);

	return num_deq;
}

static int sched_queue_enq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	return _sched_queue_enq_multi(handle, buf_hdr, num);
}

static int sched_queue_enq(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = _sched_queue_enq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

int sched_queue_empty(uint32_t queue_index)
{
	queue_entry_t *queue = qentry_from_index(queue_index);
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

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	uint64_t offset;
	uint32_t queue_size;
	odp_queue_type_t queue_type;
	int spsc;

	queue_type = param->type;

	if (name == NULL) {
		queue->s.name[0] = 0;
	} else {
		strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
		queue->s.name[ODP_QUEUE_NAME_LEN - 1] = 0;
	}
	memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	if (queue->s.param.sched.lock_count > sched_fn->max_ordered_locks())
		return -1;

	if (queue_type == ODP_QUEUE_TYPE_SCHED)
		queue->s.param.deq_mode = ODP_QUEUE_OP_DISABLED;

	queue->s.type = queue_type;
	odp_atomic_init_u64(&queue->s.num_timers, 0);

	queue->s.pktin = PKTIN_INVALID;
	queue->s.pktout = PKTOUT_INVALID;

	queue_size = param->size;
	if (queue_size == 0)
		queue_size = queue_glb->config.default_queue_size;

	if (queue_size < MIN_QUEUE_SIZE)
		queue_size = MIN_QUEUE_SIZE;

	/* Round up if not already a power of two */
	queue_size = ROUNDUP_POWER2_U32(queue_size);

	if (queue_size > queue_glb->config.max_queue_size) {
		ODP_ERR("Too large queue size %u\n", queue_size);
		return -1;
	}

	offset = queue->s.index * (uint64_t)queue_glb->config.max_queue_size;

	/* Single-producer / single-consumer plain queue has simple and
	 * lock-free implementation */
	spsc = (queue_type == ODP_QUEUE_TYPE_PLAIN) &&
	       (param->enq_mode == ODP_QUEUE_OP_MT_UNSAFE) &&
	       (param->deq_mode == ODP_QUEUE_OP_MT_UNSAFE);

	queue->s.spsc = spsc;
	queue->s.queue_lf = NULL;

	/* Default to error functions */
	queue->s.enqueue            = error_enqueue;
	queue->s.enqueue_multi      = error_enqueue_multi;
	queue->s.dequeue            = error_dequeue;
	queue->s.dequeue_multi      = error_dequeue_multi;
	queue->s.orig_dequeue_multi = error_dequeue_multi;

	if (spsc) {
		queue_spsc_init(queue, queue_size);
	} else {
		if (queue_type == ODP_QUEUE_TYPE_PLAIN) {
			queue->s.enqueue            = plain_queue_enq;
			queue->s.enqueue_multi      = plain_queue_enq_multi;
			queue->s.dequeue            = plain_queue_deq;
			queue->s.dequeue_multi      = plain_queue_deq_multi;
			queue->s.orig_dequeue_multi = plain_queue_deq_multi;

			queue->s.ring_data = &queue_glb->ring_data[offset];
			queue->s.ring_mask = queue_size - 1;
			ring_mpmc_init(&queue->s.ring_mpmc);

		} else {
			queue->s.enqueue            = sched_queue_enq;
			queue->s.enqueue_multi      = sched_queue_enq_multi;

			queue->s.ring_data = &queue_glb->ring_data[offset];
			queue->s.ring_mask = queue_size - 1;
			ring_st_init(&queue->s.ring_st);
		}
	}

	return 0;
}

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(odp_queue_t handle)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	return qentry->s.pktout;
}

static void queue_set_pktout(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	qentry->s.pktout.pktio = pktio;
	qentry->s.pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(odp_queue_t handle)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	return qentry->s.pktin;
}

static void queue_set_pktin(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	qentry->s.pktin.pktio = pktio;
	qentry->s.pktin.index = index;
}

static void queue_set_enq_deq_func(odp_queue_t handle,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	if (enq)
		qentry->s.enqueue = enq;

	if (enq_multi)
		qentry->s.enqueue_multi = enq_multi;

	if (deq)
		qentry->s.dequeue = deq;

	if (deq_multi)
		qentry->s.dequeue_multi = deq_multi;
}

static int queue_orig_multi(odp_queue_t handle,
			    odp_buffer_hdr_t **buf_hdr, int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->s.orig_dequeue_multi(handle, buf_hdr, num);
}

static int queue_api_enq_multi(odp_queue_t handle,
			       const odp_event_t ev[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	if (odp_unlikely(num == 0))
		return 0;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	return queue->s.enqueue_multi(handle,
				      (odp_buffer_hdr_t **)(uintptr_t)ev, num);
}

static void queue_timer_add(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	odp_atomic_inc_u64(&queue->s.num_timers);
}

static void queue_timer_rem(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	odp_atomic_dec_u64(&queue->s.num_timers);
}

static int queue_api_enq(odp_queue_t handle, odp_event_t ev)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->s.enqueue(handle,
				(odp_buffer_hdr_t *)(uintptr_t)ev);
}

static int queue_api_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	int ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	ret = queue->s.dequeue_multi(handle, (odp_buffer_hdr_t **)ev, num);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->s.num_timers))
		timer_run(ret ? 2 : 1);

	return ret;
}

static odp_event_t queue_api_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	odp_event_t ev = (odp_event_t)queue->s.dequeue(handle);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->s.num_timers))
		timer_run(ev != ODP_EVENT_INVALID ? 2 : 1);

	return ev;
}

/* API functions */
_odp_queue_api_fn_t queue_basic_api = {
	.queue_create = queue_create,
	.queue_destroy = queue_destroy,
	.queue_lookup = queue_lookup,
	.queue_capability = queue_capability,
	.queue_context_set = queue_context_set,
	.queue_enq = queue_api_enq,
	.queue_enq_multi = queue_api_enq_multi,
	.queue_deq = queue_api_deq,
	.queue_deq_multi = queue_api_deq_multi,
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
	.get_pktout = queue_get_pktout,
	.set_pktout = queue_set_pktout,
	.get_pktin = queue_get_pktin,
	.set_pktin = queue_set_pktin,
	.set_enq_deq_fn = queue_set_enq_deq_func,
	.orig_deq_multi = queue_orig_multi,
	.timer_add = queue_timer_add,
	.timer_rem = queue_timer_rem
};
