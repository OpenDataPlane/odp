/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/packet_io.h>
#include <odp/api/queue.h>
#include <odp/api/schedule.h>
#include <odp/api/shared_memory.h>
#include <odp/api/std_types.h>
#include <odp/api/sync.h>
#include <odp/api/ticketlock.h>
#include <odp/api/traffic_mngr.h>

#include <odp/api/plat/queue_inline_types.h>
#include <odp/api/plat/sync_inlines.h>
#include <odp/api/plat/ticketlock_inlines.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_basic_internal.h>
#include <odp_queue_if.h>
#include <odp_schedule_if.h>
#include <odp_timer_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <string.h>

#define LOCK(queue_ptr)      odp_ticketlock_lock(&((queue_ptr)->lock))
#define UNLOCK(queue_ptr)    odp_ticketlock_unlock(&((queue_ptr)->lock))
#define LOCK_INIT(queue_ptr) odp_ticketlock_init(&((queue_ptr)->lock))

#define MIN_QUEUE_SIZE 32
#define MAX_QUEUE_SIZE (1 * 1024 * 1024)

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param);

queue_global_t *_odp_queue_glb;
extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

static int queue_capa(odp_queue_capability_t *capa, int sched ODP_UNUSED)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = CONFIG_MAX_QUEUES - CONFIG_INTERNAL_QUEUES;
	capa->plain.max_num     = CONFIG_MAX_PLAIN_QUEUES;
	capa->plain.max_size    = _odp_queue_glb->config.max_queue_size;
	capa->plain.lockfree.max_num  = _odp_queue_glb->queue_lf_num;
	capa->plain.lockfree.max_size = _odp_queue_glb->queue_lf_size;

	return 0;
}

static int read_config_file(queue_global_t *_odp_queue_glb)
{
	const char *str;
	uint32_t val_u32;
	int val = 0;

	_ODP_PRINT("Queue config:\n");

	str = "queue_basic.max_queue_size";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	val_u32 = val;

	if (val_u32 > MAX_QUEUE_SIZE || val_u32 < MIN_QUEUE_SIZE ||
	    !_ODP_CHECK_IS_POWER2(val_u32)) {
		_ODP_ERR("Bad value %s = %u\n", str, val_u32);
		return -1;
	}

	_odp_queue_glb->config.max_queue_size = val_u32;
	_ODP_PRINT("  %s: %u\n", str, val_u32);

	str = "queue_basic.default_queue_size";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	val_u32 = val;

	if (val_u32 > _odp_queue_glb->config.max_queue_size ||
	    val_u32 < MIN_QUEUE_SIZE ||
	    !_ODP_CHECK_IS_POWER2(val_u32)) {
		_ODP_ERR("Bad value %s = %u\n", str, val_u32);
		return -1;
	}

	_odp_queue_glb->config.default_queue_size = val_u32;
	_ODP_PRINT("  %s: %u\n\n", str, val_u32);

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

	_ODP_DBG("Starts...\n");

	/* Fill in queue entry field offsets for inline functions */
	memset(&_odp_queue_inline_offset, 0,
	       sizeof(_odp_queue_inline_offset_t));
	_odp_queue_inline_offset.context = offsetof(queue_entry_t,
						    param.context);

	shm = odp_shm_reserve("_odp_queue_basic_global",
			      sizeof(queue_global_t),
			      sizeof(queue_entry_t),
			      0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	_odp_queue_glb = odp_shm_addr(shm);

	memset(_odp_queue_glb, 0, sizeof(queue_global_t));

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = qentry_from_index(i);

		LOCK_INIT(queue);
		queue->index  = i;
		queue->handle = (odp_queue_t)queue;
	}

	if (read_config_file(_odp_queue_glb)) {
		odp_shm_free(shm);
		return -1;
	}

	_odp_queue_glb->queue_gbl_shm = shm;
	mem_size = sizeof(uintptr_t) * CONFIG_MAX_QUEUES *
		   (uint64_t)_odp_queue_glb->config.max_queue_size;

	shm = odp_shm_reserve("_odp_queue_basic_rings", mem_size,
			      ODP_CACHE_LINE_SIZE,
			      0);

	if (shm == ODP_SHM_INVALID) {
		odp_shm_free(_odp_queue_glb->queue_gbl_shm);
		return -1;
	}

	_odp_queue_glb->queue_ring_shm = shm;
	_odp_queue_glb->ring_data      = odp_shm_addr(shm);

	lf_func = &_odp_queue_glb->queue_lf_func;
	_odp_queue_glb->queue_lf_num  = _odp_queue_lf_init_global(&lf_size, lf_func);
	_odp_queue_glb->queue_lf_size = lf_size;

	queue_capa(&capa, 0);

	_ODP_DBG("... done.\n");
	_ODP_DBG("  queue_entry_t size %zu\n", sizeof(queue_entry_t));
	_ODP_DBG("  max num queues     %u\n", capa.max_queues);
	_ODP_DBG("  max queue size     %u\n", capa.plain.max_size);
	_ODP_DBG("  max num lockfree   %u\n", capa.plain.lockfree.max_num);
	_ODP_DBG("  max lockfree size  %u\n\n", capa.plain.lockfree.max_size);

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
		if (queue->status != QUEUE_STATUS_FREE) {
			_ODP_ERR("Not destroyed queue: %s\n", queue->name);
			ret = -1;
		}
		UNLOCK(queue);
	}

	_odp_queue_lf_term_global();

	if (odp_shm_free(_odp_queue_glb->queue_ring_shm)) {
		_ODP_ERR("shm free failed");
		ret = -1;
	}

	if (odp_shm_free(_odp_queue_glb->queue_gbl_shm)) {
		_ODP_ERR("shm free failed");
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
	return qentry_from_handle(handle)->type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return qentry_from_handle(handle)->param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return qentry_from_handle(handle)->param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return qentry_from_handle(handle)->param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->param.sched.lock_count : 0;
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
			_ODP_ERR("Bad queue priority: %i\n", param->sched.prio);
			return ODP_QUEUE_INVALID;
		}
	} else if (type != ODP_QUEUE_TYPE_PLAIN)
		return ODP_QUEUE_INVALID;

	if (param->num_aggr > 0)
		return ODP_QUEUE_INVALID;

	if (param->nonblocking == ODP_BLOCKING) {
		if (param->size > _odp_queue_glb->config.max_queue_size)
			return ODP_QUEUE_INVALID;
	} else if (param->nonblocking == ODP_NONBLOCKING_LF) {
		/* Only plain type lock-free queues supported */
		if (type != ODP_QUEUE_TYPE_PLAIN)
			return ODP_QUEUE_INVALID;
		if (param->size > _odp_queue_glb->queue_lf_size)
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

		if (queue->status != QUEUE_STATUS_FREE)
			continue;

		LOCK(queue);
		if (queue->status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(queue);
				return ODP_QUEUE_INVALID;
			}

			if (!queue->spsc &&
			    param->nonblocking == ODP_NONBLOCKING_LF) {
				queue_lf_func_t *lf_fn;

				lf_fn = &_odp_queue_glb->queue_lf_func;

				queue_lf = _odp_queue_lf_create(queue);

				if (queue_lf == NULL) {
					UNLOCK(queue);
					return ODP_QUEUE_INVALID;
				}
				queue->queue_lf = queue_lf;

				queue->enqueue       = lf_fn->enq;
				queue->enqueue_multi = lf_fn->enq_multi;
				queue->dequeue       = lf_fn->deq;
				queue->dequeue_multi = lf_fn->deq_multi;
				queue->orig_dequeue_multi = lf_fn->deq_multi;
			}

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->status = QUEUE_STATUS_NOTSCHED;
			else
				queue->status = QUEUE_STATUS_READY;

			handle = queue->handle;
			UNLOCK(queue);
			break;
		}
		UNLOCK(queue);
	}

	if (handle == ODP_QUEUE_INVALID)
		return ODP_QUEUE_INVALID;

	if (type == ODP_QUEUE_TYPE_SCHED) {
		if (_odp_sched_fn->create_queue(queue->index,
						&queue->param.sched)) {
			queue->status = QUEUE_STATUS_FREE;
			_ODP_ERR("schedule queue init failed\n");
			return ODP_QUEUE_INVALID;
		}
	}

	return handle;
}

static int queue_create_multi(const char *name[], const odp_queue_param_t param[],
			      odp_bool_t share_param, odp_queue_t queue[], int num)
{
	int i;

	_ODP_ASSERT(param != NULL);
	_ODP_ASSERT(queue != NULL);
	_ODP_ASSERT(num > 0);

	for (i = 0; i < num; i++) {
		odp_queue_t cur_queue;
		const char *cur_name = name != NULL ? name[i] : NULL;
		const odp_queue_param_t *cur_param = share_param ? &param[0] : &param[i];

		cur_queue =  queue_create(cur_name, cur_param);
		if (cur_queue == ODP_QUEUE_INVALID)
			return (i == 0) ? -1 : i;

		queue[i] = cur_queue;
	}
	return i;
}

void _odp_sched_queue_set_status(uint32_t queue_index, int status)
{
	queue_entry_t *queue = qentry_from_index(queue_index);

	LOCK(queue);

	queue->status = status;

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
	if (queue->status == QUEUE_STATUS_FREE) {
		UNLOCK(queue);
		_ODP_ERR("queue \"%s\" already free\n", queue->name);
		return -1;
	}
	if (queue->status == QUEUE_STATUS_DESTROYED) {
		UNLOCK(queue);
		_ODP_ERR("queue \"%s\" already destroyed\n", queue->name);
		return -1;
	}

	if (queue->spsc)
		empty = ring_spsc_ptr_is_empty(&queue->ring_spsc);
	else if (queue->type == ODP_QUEUE_TYPE_SCHED)
		empty = ring_st_ptr_is_empty(&queue->ring_st);
	else
		empty = ring_mpmc_ptr_is_empty(&queue->ring_mpmc);

	if (!empty) {
		UNLOCK(queue);
		_ODP_ERR("queue \"%s\" not empty\n", queue->name);
		return -1;
	}

	switch (queue->status) {
	case QUEUE_STATUS_READY:
		queue->status = QUEUE_STATUS_FREE;
		break;
	case QUEUE_STATUS_NOTSCHED:
		queue->status = QUEUE_STATUS_FREE;
		_odp_sched_fn->destroy_queue(queue->index);
		break;
	case QUEUE_STATUS_SCHED:
		/* Queue is still in scheduling */
		queue->status = QUEUE_STATUS_DESTROYED;
		break;
	default:
		_ODP_ABORT("Unexpected queue status\n");
	}

	if (queue->queue_lf)
		_odp_queue_lf_destroy(queue->queue_lf);

	UNLOCK(queue);

	return 0;
}

static int queue_destroy_multi(odp_queue_t handle[], int num)
{
	int i;

	_ODP_ASSERT(handle != NULL);
	_ODP_ASSERT(num > 0);

	for (i = 0; i < num; i++) {
		int ret = queue_destroy(handle[i]);

		if (ret)
			return (i == 0) ? ret : i;
	}

	return i;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	qentry_from_handle(handle)->param.context = context;
	odp_mb_full();
	return 0;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue_entry_t *queue = qentry_from_index(i);

		if (queue->status == QUEUE_STATUS_FREE ||
		    queue->status == QUEUE_STATUS_DESTROYED)
			continue;

		LOCK(queue);
		if (strcmp(name, queue->name) == 0) {
			/* found it */
			UNLOCK(queue);
			return queue->handle;
		}
		UNLOCK(queue);
	}

	return ODP_QUEUE_INVALID;
}

static int plain_queue_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_mpmc_ptr_t *ring_mpmc = &queue->ring_mpmc;
	int ret;

	if (_odp_sched_fn->ord_enq_multi(handle, (void **)&event_hdr, 1, &ret))
		return ret == 1 ? 0 : -1;

	if (odp_likely(ring_mpmc_ptr_enq(ring_mpmc, queue->ring_data, queue->ring_mask,
					 (uintptr_t)event_hdr)))
		return 0;

	return -1;
}

static inline int plain_queue_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_mpmc_ptr_t *ring_mpmc = &queue->ring_mpmc;
	int ret;

	if (_odp_sched_fn->ord_enq_multi(handle, (void **)event_hdr, num, &ret))
		return ret;

	return ring_mpmc_ptr_enq_multi(ring_mpmc, queue->ring_data, queue->ring_mask,
				       (uintptr_t *)event_hdr, num);
}

static _odp_event_hdr_t *plain_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_mpmc_ptr_t *ring_mpmc = &queue->ring_mpmc;
	_odp_event_hdr_t *event_hdr;

	if (ring_mpmc_ptr_deq(ring_mpmc, queue->ring_data, queue->ring_mask,
			      (uintptr_t *)&event_hdr) == 0)
		return NULL;

	odp_prefetch(event_hdr);

	return event_hdr;
}

static inline int plain_queue_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[], int num)
{
	uint32_t num_deq;
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_mpmc_ptr_t *ring_mpmc = &queue->ring_mpmc;

	num_deq = ring_mpmc_ptr_deq_multi(ring_mpmc, queue->ring_data, queue->ring_mask,
					  (uintptr_t *)event_hdr, num);

	if (num_deq == 0)
		return 0;

	for (uint32_t i = 0; i < num_deq; i++)
		odp_prefetch(event_hdr[i]);

	return num_deq;
}

static int error_enqueue(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	(void)event_hdr;

	_ODP_ERR("Enqueue not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return -1;
}

static int error_enqueue_multi(odp_queue_t handle,
			       _odp_event_hdr_t *event_hdr[], int num)
{
	(void)event_hdr;
	(void)num;

	_ODP_ERR("Enqueue multi not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return -1;
}

static _odp_event_hdr_t *error_dequeue(odp_queue_t handle)
{
	_ODP_ERR("Dequeue not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return NULL;
}

static int error_dequeue_multi(odp_queue_t handle,
			       _odp_event_hdr_t *event_hdr[], int num)
{
	(void)event_hdr;
	(void)num;

	_ODP_ERR("Dequeue multi not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

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
		_ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_index(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		_ODP_ERR("Invalid queue handle: 0x%" PRIx64 "\n", odp_queue_to_u64(handle));
		return -1;
	}

	queue = qentry_from_index(queue_id);

	LOCK(queue);
	status = queue->status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(queue);
		_ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->name;
	info->param = queue->param;

	UNLOCK(queue);

	return 0;
}

static void queue_print(odp_queue_t handle)
{
	odp_pktio_info_t pktio_info;
	queue_entry_t *queue;
	uint32_t queue_id;
	int status, prio;
	int max_prio = odp_schedule_max_prio();

	queue_id = queue_to_index(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		_ODP_ERR("Invalid queue handle: 0x%" PRIx64 "\n", odp_queue_to_u64(handle));
		return;
	}

	queue = qentry_from_index(queue_id);

	LOCK(queue);
	status = queue->status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(queue);
		_ODP_ERR("Invalid queue status:%d\n", status);
		return;
	}
	_ODP_PRINT("\nQueue info\n");
	_ODP_PRINT("----------\n");
	_ODP_PRINT("  handle          %p\n", (void *)queue->handle);
	_ODP_PRINT("  index           %" PRIu32 "\n", queue_id);
	_ODP_PRINT("  name            %s\n", queue->name);
	_ODP_PRINT("  enq mode        %s\n",
		   queue->param.enq_mode == ODP_QUEUE_OP_MT ? "ODP_QUEUE_OP_MT" :
		   (queue->param.enq_mode == ODP_QUEUE_OP_MT_UNSAFE ? "ODP_QUEUE_OP_MT_UNSAFE" :
		    (queue->param.enq_mode == ODP_QUEUE_OP_DISABLED ? "ODP_QUEUE_OP_DISABLED" :
		     "unknown")));
	_ODP_PRINT("  deq mode        %s\n",
		   queue->param.deq_mode == ODP_QUEUE_OP_MT ? "ODP_QUEUE_OP_MT" :
		   (queue->param.deq_mode == ODP_QUEUE_OP_MT_UNSAFE ? "ODP_QUEUE_OP_MT_UNSAFE" :
		    (queue->param.deq_mode == ODP_QUEUE_OP_DISABLED ? "ODP_QUEUE_OP_DISABLED" :
		     "unknown")));
	_ODP_PRINT("  non-blocking    %s\n",
		   queue->param.nonblocking == ODP_BLOCKING ? "ODP_BLOCKING" :
		   (queue->param.nonblocking == ODP_NONBLOCKING_LF ? "ODP_NONBLOCKING_LF" :
		    (queue->param.nonblocking == ODP_NONBLOCKING_WF ? "ODP_NONBLOCKING_WF" :
		     "unknown")));
	_ODP_PRINT("  type            %s\n",
		   queue->type == ODP_QUEUE_TYPE_PLAIN ? "ODP_QUEUE_TYPE_PLAIN" :
		   (queue->type == ODP_QUEUE_TYPE_SCHED ? "ODP_QUEUE_TYPE_SCHED" : "unknown"));
	if (queue->type == ODP_QUEUE_TYPE_SCHED) {
		_ODP_PRINT("    sync          %s\n",
			   queue->param.sched.sync == ODP_SCHED_SYNC_PARALLEL ?
			   "ODP_SCHED_SYNC_PARALLEL" :
			   (queue->param.sched.sync == ODP_SCHED_SYNC_ATOMIC ?
			    "ODP_SCHED_SYNC_ATOMIC" :
			    (queue->param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
			     "ODP_SCHED_SYNC_ORDERED" : "unknown")));
		prio = queue->param.sched.prio;
		_ODP_PRINT("    priority      %i (%i in API)\n", max_prio - prio, prio);
		_ODP_PRINT("    group         %i\n", queue->param.sched.group);
		if (_odp_sched_id == _ODP_SCHED_ID_BASIC)
			_ODP_PRINT("    spread        %i\n", _odp_sched_basic_get_spread(queue_id));
	}
	if (queue->pktin.pktio != ODP_PKTIO_INVALID) {
		if (!odp_pktio_info(queue->pktin.pktio, &pktio_info))
			_ODP_PRINT("  pktin           %s\n", pktio_info.name);
	}
	if (queue->pktout.pktio != ODP_PKTIO_INVALID) {
		if (!odp_pktio_info(queue->pktout.pktio, &pktio_info))
			_ODP_PRINT("  pktout          %s\n", pktio_info.name);
	}
	_ODP_PRINT("  timers          %" PRIu64 "\n", odp_atomic_load_u64(&queue->num_timers));
	_ODP_PRINT("  status          %s\n",
		   queue->status == QUEUE_STATUS_READY ? "ready" :
		   (queue->status == QUEUE_STATUS_NOTSCHED ? "not scheduled" :
		    (queue->status == QUEUE_STATUS_SCHED ? "scheduled" : "unknown")));
	_ODP_PRINT("  param.size      %" PRIu32 "\n", queue->param.size);
	if (queue->queue_lf) {
		_ODP_PRINT("  implementation  queue_lf\n");
		_ODP_PRINT("  length          %" PRIu32 "/%" PRIu32 "\n",
			   _odp_queue_lf_length(queue->queue_lf), _odp_queue_lf_max_length());
	} else if (queue->spsc) {
		_ODP_PRINT("  implementation  ring_spsc\n");
		_ODP_PRINT("  length          %" PRIu32 "/%" PRIu32 "\n",
			   ring_spsc_ptr_len(&queue->ring_spsc), queue->ring_mask + 1);
	} else if (queue->type == ODP_QUEUE_TYPE_SCHED) {
		_ODP_PRINT("  implementation  ring_st\n");
		_ODP_PRINT("  length          %" PRIu32 "/%" PRIu32 "\n",
			   ring_st_ptr_len(&queue->ring_st), queue->ring_mask + 1);
	} else {
		_ODP_PRINT("  implementation  ring_mpmc\n");
		_ODP_PRINT("  length          %" PRIu32 "/%" PRIu32 "\n",
			   ring_mpmc_ptr_len(&queue->ring_mpmc), queue->ring_mask + 1);
	}
	_ODP_PRINT("\n");

	UNLOCK(queue);
}

static void queue_print_all(void)
{
	uint32_t i, index, len, max_len;
	const char *name;
	int status;
	odp_queue_type_t type;
	odp_nonblocking_t blocking;
	odp_queue_op_mode_t enq_mode;
	odp_queue_op_mode_t deq_mode;
	odp_queue_order_t order;
	const char *status_str;
	const char *bl_str;
	char type_c, enq_c, deq_c, order_c, sync_c;
	const int col_width = 24;
	int prio = 0;
	int spr = 0;
	odp_schedule_sync_t sync = ODP_SCHED_SYNC_PARALLEL;
	odp_schedule_group_t grp = ODP_SCHED_GROUP_INVALID;

	_ODP_PRINT("\nList of all queues\n");
	_ODP_PRINT("------------------\n");
	_ODP_PRINT(" idx %-*s type stat blk enq deq ord    len max_len sync prio grp", col_width, "name");
	if (_odp_sched_id == _ODP_SCHED_ID_BASIC)
		_ODP_PRINT(" spr\n");
	else
		_ODP_PRINT("\n");

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue_entry_t *queue = qentry_from_index(i);

		if (queue->status < QUEUE_STATUS_READY)
			continue;

		LOCK(queue);

		status   = queue->status;
		index    = queue->index;
		name     = queue->name;
		type     = queue->type;
		blocking = queue->param.nonblocking;
		enq_mode = queue->param.enq_mode;
		deq_mode = queue->param.deq_mode;
		order    = queue->param.order;

		if (queue->queue_lf) {
			len     = _odp_queue_lf_length(queue->queue_lf);
			max_len = _odp_queue_lf_max_length();
		} else if (queue->spsc) {
			len     = ring_spsc_ptr_len(&queue->ring_spsc);
			max_len = queue->ring_mask + 1;
		} else if (type == ODP_QUEUE_TYPE_SCHED) {
			len     = ring_st_ptr_len(&queue->ring_st);
			max_len = queue->ring_mask + 1;
			prio    = queue->param.sched.prio;
			grp     = queue->param.sched.group;
			sync    = queue->param.sched.sync;
			if (_odp_sched_id == _ODP_SCHED_ID_BASIC)
				spr = _odp_sched_basic_get_spread(index);
		} else {
			len     = ring_mpmc_ptr_len(&queue->ring_mpmc);
			max_len = queue->ring_mask + 1;
		}

		UNLOCK(queue);

		if (status < QUEUE_STATUS_READY)
			continue;

		status_str = (status == QUEUE_STATUS_READY) ? "R" :
			     ((status == QUEUE_STATUS_SCHED) ? "S" : "NS");

		type_c = (type == ODP_QUEUE_TYPE_PLAIN) ? 'P' : 'S';

		bl_str = (blocking == ODP_BLOCKING) ? "B" :
			 ((blocking == ODP_NONBLOCKING_LF) ? "LF" : "WF");

		enq_c = (enq_mode == ODP_QUEUE_OP_MT) ? 'S' :
			((enq_mode == ODP_QUEUE_OP_MT_UNSAFE) ? 'U' : 'D');

		deq_c = (deq_mode == ODP_QUEUE_OP_MT) ? 'S' :
			((deq_mode == ODP_QUEUE_OP_MT_UNSAFE) ? 'U' : 'D');

		order_c = (order == ODP_QUEUE_ORDER_KEEP) ? 'K' : 'I';

		_ODP_PRINT("%4u %-*s    %c   %2s  %2s", index, col_width, name, type_c,
			   status_str, bl_str);
		_ODP_PRINT("   %c   %c   %c %6u  %6u", enq_c, deq_c, order_c, len, max_len);

		if (type == ODP_QUEUE_TYPE_SCHED) {
			sync_c = (sync == ODP_SCHED_SYNC_PARALLEL) ? 'P' :
				 ((sync == ODP_SCHED_SYNC_ATOMIC) ? 'A' : 'O');
			/* Print prio level matching odp_schedule_print() output */
			prio = odp_schedule_max_prio() - prio;

			_ODP_PRINT("    %c %4i %3i", sync_c, prio, grp);

			if (_odp_sched_id == _ODP_SCHED_ID_BASIC)
				_ODP_PRINT(" %3i", spr);
		}

		_ODP_PRINT("\n");
	}

	_ODP_PRINT("\n");
}

static int sched_queue_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_st_ptr_t *ring_st = &queue->ring_st;
	int ret, sched = 0;

	if (_odp_sched_fn->ord_enq_multi(handle, (void **)&event_hdr, 1, &ret))
		return ret == 1 ? 0 : -1;

	LOCK(queue);

	if (odp_unlikely(ring_st_ptr_enq(ring_st, queue->ring_data, queue->ring_mask,
					 (uintptr_t)event_hdr) == 0)) {
		UNLOCK(queue);
		return -1;
	}

	if (queue->status == QUEUE_STATUS_NOTSCHED) {
		queue->status = QUEUE_STATUS_SCHED;
		sched = 1;
	}

	UNLOCK(queue);

	/* Add queue to scheduling */
	if (sched && _odp_sched_fn->sched_queue(queue->index))
		_ODP_ABORT("schedule_queue failed\n");

	return 0;
}

static inline int sched_queue_enq_multi(odp_queue_t handle,
					_odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	ring_st_ptr_t *ring_st = &queue->ring_st;
	int sched = 0;
	int ret;
	uint32_t num_enq;

	if (_odp_sched_fn->ord_enq_multi(handle, (void **)event_hdr, num, &ret))
		return ret;

	LOCK(queue);

	num_enq = ring_st_ptr_enq_multi(ring_st, queue->ring_data, queue->ring_mask,
					(uintptr_t *)event_hdr, num);

	if (odp_unlikely(num_enq == 0)) {
		UNLOCK(queue);
		return 0;
	}

	if (queue->status == QUEUE_STATUS_NOTSCHED) {
		queue->status = QUEUE_STATUS_SCHED;
		sched = 1;
	}

	UNLOCK(queue);

	/* Add queue to scheduling */
	if (sched && _odp_sched_fn->sched_queue(queue->index))
		_ODP_ABORT("schedule_queue failed\n");

	return num_enq;
}

int _odp_sched_queue_deq(uint32_t queue_index, odp_event_t ev[], int max_num,
			 int update_status)
{
	queue_entry_t *queue = qentry_from_index(queue_index);
	ring_st_ptr_t *ring_st = &queue->ring_st;
	uint32_t num_deq;
	int status;

	LOCK(queue);

	status = queue->status;

	if (odp_unlikely(status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed.
		 * Inform scheduler about a destroyed queue. */
		if (queue->status == QUEUE_STATUS_DESTROYED) {
			queue->status = QUEUE_STATUS_FREE;
			_odp_sched_fn->destroy_queue(queue_index);
		}

		UNLOCK(queue);
		return -1;
	}

	num_deq = ring_st_ptr_deq_multi(ring_st, queue->ring_data, queue->ring_mask,
					(uintptr_t *)ev, max_num);

	if (num_deq == 0) {
		/* Already empty queue */
		if (update_status && status == QUEUE_STATUS_SCHED)
			queue->status = QUEUE_STATUS_NOTSCHED;

		UNLOCK(queue);

		return 0;
	}

	UNLOCK(queue);

	for (uint32_t i = 0; i < num_deq; i++)
		odp_prefetch((void *)ev[i]);

	return num_deq;
}

int _odp_sched_queue_empty(uint32_t queue_index)
{
	queue_entry_t *queue = qentry_from_index(queue_index);
	int ret = 0;

	LOCK(queue);

	if (odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		UNLOCK(queue);
		return -1;
	}

	if (ring_st_ptr_is_empty(&queue->ring_st)) {
		/* Already empty queue. Update status. */
		if (queue->status == QUEUE_STATUS_SCHED)
			queue->status = QUEUE_STATUS_NOTSCHED;

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

	if (name == NULL)
		queue->name[0] = 0;
	else
		_odp_strcpy(queue->name, name, ODP_QUEUE_NAME_LEN);
	memcpy(&queue->param, param, sizeof(odp_queue_param_t));
	if (queue->param.sched.lock_count > _odp_sched_fn->max_ordered_locks())
		return -1;

	if (queue_type == ODP_QUEUE_TYPE_SCHED)
		queue->param.deq_mode = ODP_QUEUE_OP_DISABLED;

	queue->type = queue_type;
	odp_atomic_init_u64(&queue->num_timers, 0);

	queue->pktin = PKTIN_INVALID;
	queue->pktout = PKTOUT_INVALID;

	queue_size = param->size;
	if (queue_size == 0)
		queue_size = _odp_queue_glb->config.default_queue_size;

	if (queue_size < MIN_QUEUE_SIZE)
		queue_size = MIN_QUEUE_SIZE;

	/* Round up if not already a power of two */
	queue_size = _ODP_ROUNDUP_POWER2_U32(queue_size);

	if (queue_size > _odp_queue_glb->config.max_queue_size) {
		_ODP_ERR("Too large queue size %u\n", queue_size);
		return -1;
	}

	offset = queue->index * (uint64_t)_odp_queue_glb->config.max_queue_size;

	/* Single-producer / single-consumer plain queue has simple and
	 * lock-free implementation */
	spsc = (queue_type == ODP_QUEUE_TYPE_PLAIN) &&
	       (param->enq_mode == ODP_QUEUE_OP_MT_UNSAFE) &&
	       (param->deq_mode == ODP_QUEUE_OP_MT_UNSAFE);

	queue->spsc = spsc;
	queue->queue_lf = NULL;

	/* Default to error functions */
	queue->enqueue            = error_enqueue;
	queue->enqueue_multi      = error_enqueue_multi;
	queue->dequeue            = error_dequeue;
	queue->dequeue_multi      = error_dequeue_multi;
	queue->orig_dequeue_multi = error_dequeue_multi;

	if (spsc) {
		_odp_queue_spsc_init(queue, queue_size);
	} else {
		if (queue_type == ODP_QUEUE_TYPE_PLAIN) {
			queue->enqueue            = plain_queue_enq;
			queue->enqueue_multi      = plain_queue_enq_multi;
			queue->dequeue            = plain_queue_deq;
			queue->dequeue_multi      = plain_queue_deq_multi;
			queue->orig_dequeue_multi = plain_queue_deq_multi;

			queue->ring_data = &_odp_queue_glb->ring_data[offset];
			queue->ring_mask = queue_size - 1;
			ring_mpmc_ptr_init(&queue->ring_mpmc);

		} else {
			queue->enqueue            = sched_queue_enq;
			queue->enqueue_multi      = sched_queue_enq_multi;

			queue->ring_data = &_odp_queue_glb->ring_data[offset];
			queue->ring_mask = queue_size - 1;
			ring_st_ptr_init(&queue->ring_st);
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

	return qentry->pktout;
}

static void queue_set_pktout(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	qentry->pktout.pktio = pktio;
	qentry->pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(odp_queue_t handle)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	return qentry->pktin;
}

static void queue_set_pktin(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	qentry->pktin.pktio = pktio;
	qentry->pktin.index = index;
}

static void queue_set_enq_deq_func(odp_queue_t handle,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	if (enq)
		qentry->enqueue = enq;

	if (enq_multi)
		qentry->enqueue_multi = enq_multi;

	if (deq)
		qentry->dequeue = deq;

	if (deq_multi)
		qentry->dequeue_multi = deq_multi;
}

static int queue_orig_multi(odp_queue_t handle,
			    _odp_event_hdr_t **event_hdr, int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->orig_dequeue_multi(handle, event_hdr, num);
}

static int queue_api_enq_multi(odp_queue_t handle,
			       const odp_event_t ev[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	if (odp_unlikely(num == 0))
		return 0;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	return queue->enqueue_multi(handle,
				      (_odp_event_hdr_t **)(uintptr_t)ev, num);
}

static void queue_timer_add(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	odp_atomic_inc_u64(&queue->num_timers);
}

static void queue_timer_rem(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	odp_atomic_dec_u64(&queue->num_timers);
}

static int queue_api_enq(odp_queue_t handle, odp_event_t ev)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->enqueue(handle,
				(_odp_event_hdr_t *)(uintptr_t)ev);
}

static int queue_api_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	int ret;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	ret = queue->dequeue_multi(handle, (_odp_event_hdr_t **)ev, num);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->num_timers))
		timer_run(ret ? 2 : 1);

	return ret;
}

static odp_event_t queue_api_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	odp_event_t ev = (odp_event_t)queue->dequeue(handle);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->num_timers))
		timer_run(ev != ODP_EVENT_INVALID ? 2 : 1);

	return ev;
}

/* API functions */
_odp_queue_api_fn_t _odp_queue_basic_api = {
	.queue_create = queue_create,
	.queue_create_multi = queue_create_multi,
	.queue_destroy = queue_destroy,
	.queue_destroy_multi = queue_destroy_multi,
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
	.queue_info = queue_info,
	.queue_print = queue_print,
	.queue_print_all = queue_print_all

};

/* Functions towards internal components */
queue_fn_t _odp_queue_basic_fn = {
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
