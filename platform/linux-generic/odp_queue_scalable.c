/* Copyright (c) 2017, ARM Limited
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp/api/plat/ticketlock_inlines.h>
#include <odp/api/queue.h>
#include <odp/api/schedule.h>
#include <odp/api/shared_memory.h>
#include <odp/api/sync.h>
#include <odp/api/plat/sync_inlines.h>
#include <odp/api/traffic_mngr.h>
#include <odp/api/cpu.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>

#include <odp_event_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_scalable_internal.h>
#include <odp_schedule_if.h>
#include <odp_timer_internal.h>
#include <odp_shm_internal.h>
#include <odp_ishmpool_internal.h>
#include <odp/api/plat/queue_inline_types.h>
#include <odp_global_data.h>
#include <odp_macros_internal.h>

#include <string.h>
#include <inttypes.h>

#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)

extern __thread sched_scalable_thread_state_t *_odp_sched_ts;
extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

typedef struct queue_table_t {
	queue_entry_t  queue[CONFIG_MAX_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;
static _odp_ishm_pool_t *queue_shm_pool;

static int _queue_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr);
static _odp_event_hdr_t *_queue_deq(odp_queue_t handle);
static int _queue_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
			    int num);
static int _queue_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
			    int num);

static queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

queue_entry_t *_odp_qentry_from_ext(odp_queue_t handle)
{
	return (queue_entry_t *)(uintptr_t)handle;
}

static int _odp_queue_disable_enq(sched_elem_t *q)
{
	ringidx_t old_read, old_write, new_write;
	uint32_t size;

	old_write = q->prod_write;
	size = q->prod_mask + 1;
	do {
		/* Need __atomic_load to avoid compiler reordering */
		old_read = __atomic_load_n(&q->prod_read, __ATOMIC_ACQUIRE);
		if (old_write != old_read) {
			/* Queue is not empty, cannot claim all elements
			* Cannot disable enqueue.
			*/
			return -1;
		}
		/* Claim all elements in ring */
		new_write = old_write + size;
	} while (!__atomic_compare_exchange_n(&q->prod_write,
				&old_write, /* Updated on failure */
				new_write,
				true,
				__ATOMIC_RELAXED,
				__ATOMIC_RELAXED));
	/* All remaining elements claimed, no one else can enqueue */
	return 0;
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	ringidx_t ring_idx;
	sched_elem_t *sched_elem;
	uint32_t ring_size;
	_odp_event_hdr_t **ring;
	uint32_t size;

	sched_elem = &queue->sched_elem;
	ring_size = param->size > 0 ?
		_ODP_ROUNDUP_POWER2_U32(param->size) : CONFIG_SCAL_QUEUE_SIZE;
	strncpy(queue->name, name ? name : "", ODP_QUEUE_NAME_LEN - 1);
	queue->name[ODP_QUEUE_NAME_LEN - 1] = 0;
	memcpy(&queue->param, param, sizeof(odp_queue_param_t));

	size = ring_size * sizeof(_odp_event_hdr_t *);
	ring = (_odp_event_hdr_t **)shm_pool_alloc_align(queue_shm_pool, size);
	if (NULL == ring)
		return -1;

	for (ring_idx = 0; ring_idx < ring_size; ring_idx++)
		ring[ring_idx] = NULL;

	queue->type = queue->param.type;

	if (queue->type == ODP_QUEUE_TYPE_SCHED)
		queue->param.deq_mode = ODP_QUEUE_OP_DISABLED;

	odp_atomic_init_u64(&queue->num_timers, 0);

	queue->enqueue = _queue_enq;
	queue->dequeue = _queue_deq;
	queue->enqueue_multi = _queue_enq_multi;
	queue->dequeue_multi = _queue_deq_multi;
	queue->orig_dequeue_multi = _queue_deq_multi;
	queue->pktin = PKTIN_INVALID;

	sched_elem->node.next = NULL;
#ifdef CONFIG_QSCHST_LOCK
	LOCK_INIT(&sched_elem->qschlock);
#endif
	sched_elem->qschst.numevts = 0;
	sched_elem->qschst.wrr_budget = CONFIG_WRR_WEIGHT;
	sched_elem->qschst.cur_ticket = 0;
	sched_elem->qschst.nxt_ticket = 0;
	sched_elem->pop_deficit = 0;
	if (queue->type == ODP_QUEUE_TYPE_SCHED)
		sched_elem->qschst_type = queue->param.sched.sync;
	else
		sched_elem->qschst_type = ODP_NO_SCHED_QUEUE;
	/* 2nd cache line - enqueue */
	sched_elem->prod_read = 0;
	sched_elem->prod_write = 0;
	sched_elem->prod_ring = ring;
	sched_elem->prod_mask = ring_size - 1;
	/* 3rd cache line - dequeue */
	sched_elem->cons_read = 0;
	sched_elem->cons_write = 0;
	sched_elem->rwin = NULL;
	sched_elem->schedq = NULL;
	sched_elem->user_ctx = queue->param.context;
#ifdef CONFIG_SPLIT_PRODCONS
	sched_elem->cons_ring = ring;
	sched_elem->cons_mask = ring_size - 1;
	sched_elem->cons_type = sched_elem->qschst_type;
#endif

	/* Queue initialized successfully, add it to the sched group */
	if (queue->type == ODP_QUEUE_TYPE_SCHED) {
		int prio = odp_schedule_max_prio() - param->sched.prio;

		if (queue->param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
			sched_elem->rwin =
				_odp_rwin_alloc(queue_shm_pool,
						queue->param.sched.lock_count);
			if (sched_elem->rwin == NULL) {
				_ODP_ERR("Reorder window not created\n");
				goto rwin_create_failed;
			}
		}
		sched_elem->sched_grp = param->sched.group;
		sched_elem->sched_prio = prio;
		sched_elem->schedq =
			_odp_sched_queue_add(param->sched.group, prio);
		_ODP_ASSERT(sched_elem->schedq != NULL);
	}

	return 0;

rwin_create_failed:
	_odp_ishm_pool_free(queue_shm_pool, ring);

	return -1;
}

static int queue_init_global(void)
{
	uint32_t i;
	uint64_t pool_size;
	uint64_t min_alloc;
	uint64_t max_alloc;

	_ODP_DBG("Queue init ... ");

	/* Fill in queue entry field offsets for inline functions */
	memset(&_odp_queue_inline_offset, 0,
	       sizeof(_odp_queue_inline_offset_t));
	_odp_queue_inline_offset.context = offsetof(queue_entry_t,
						    param.context);

	/* Create shared memory pool to allocate shared memory for the
	 * queues. Use the default queue size.
	 */
	/* Add size of the array holding the queues */
	pool_size = sizeof(queue_table_t);
	/* Add storage required for queues */
	pool_size += (CONFIG_SCAL_QUEUE_SIZE *
		      sizeof(_odp_event_hdr_t *)) * CONFIG_MAX_QUEUES;

	/* Add the reorder window size */
	pool_size += sizeof(reorder_window_t) * CONFIG_MAX_QUEUES;
	/* Choose min_alloc and max_alloc such that buddy allocator is selected. */
	min_alloc = 0;
	max_alloc = CONFIG_SCAL_QUEUE_SIZE * sizeof(_odp_event_hdr_t *);
	queue_shm_pool = _odp_ishm_pool_create("queue_shm_pool",
					       pool_size,
					       min_alloc, max_alloc, 0);
	if (queue_shm_pool == NULL) {
		_ODP_ERR("Failed to allocate shared memory pool for"
			" queues\n");
		goto queue_shm_pool_create_failed;
	}

	queue_tbl = (queue_table_t *)
		    shm_pool_alloc_align(queue_shm_pool,
					 sizeof(queue_table_t));
	if (queue_tbl == NULL) {
		_ODP_ERR("Failed to reserve shared memory for queue table\n");
		goto queue_tbl_ishm_alloc_failed;
	}

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue;

		queue = get_qentry(i);
		LOCK_INIT(&queue->lock);
		queue->index  = i;
		queue->handle = (odp_queue_t)queue;
	}

	_ODP_DBG("done\n");
	_ODP_DBG("Queue init global\n");
	_ODP_DBG("  struct queue_entry_s size %zu\n", sizeof(struct queue_entry_s));
	_ODP_DBG("  queue_entry_t size        %zu\n", sizeof(queue_entry_t));
	_ODP_DBG("\n");

	return 0;

queue_shm_pool_create_failed:

queue_tbl_ishm_alloc_failed:
	_odp_ishm_pool_destroy(queue_shm_pool);

	return -1;
}

static int queue_term_global(void)
{
	int ret = 0;
	int rc = 0;
	queue_entry_t *queue;
	int i;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue = &queue_tbl->queue[i];
		if (__atomic_load_n(&queue->status,
				    __ATOMIC_RELAXED) != QUEUE_STATUS_FREE) {
			_ODP_ERR("Not destroyed queue: %s\n", queue->name);
			rc = -1;
		}
	}

	_odp_ishm_pool_free(queue_shm_pool, queue_tbl);

	ret = _odp_ishm_pool_destroy(queue_shm_pool);
	if (ret < 0) {
		_ODP_ERR("Failed to destroy shared memory pool for queues\n");
		rc = -1;
	}

	return rc;
}

static int queue_init_local(void)
{
	return 0;
}

static int queue_term_local(void)
{
	return 0;
}

static int queue_capability(odp_queue_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = CONFIG_MAX_QUEUES - CONFIG_INTERNAL_QUEUES;

	capa->plain.max_num     = CONFIG_MAX_PLAIN_QUEUES;
	capa->plain.max_size    = 0;

	return 0;
}

static odp_queue_type_t queue_type(odp_queue_t handle)
{
	return _odp_qentry_from_ext(handle)->type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return _odp_qentry_from_ext(handle)->param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return _odp_qentry_from_ext(handle)->param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return _odp_qentry_from_ext(handle)->param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = _odp_qentry_from_ext(handle);

	return queue->param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->param.sched.lock_count : 0;
}

static odp_queue_t queue_create(const char *name,
				const odp_queue_param_t *param)
{
	int queue_idx;
	int max_idx;
	queue_entry_t *queue;
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
	}

	if (type == ODP_QUEUE_TYPE_SCHED) {
		/* Start scheduled queue indices from zero to enable direct
		 * mapping to scheduler implementation indices. */
		queue_idx = 0;
		max_idx = CONFIG_MAX_SCHED_QUEUES;
	} else {
		queue_idx = CONFIG_MAX_SCHED_QUEUES;
		/* All internal queues are of type plain */
		max_idx = CONFIG_MAX_QUEUES;
	}

	for (; queue_idx < max_idx; queue_idx++) {
		queue = &queue_tbl->queue[queue_idx];

		if (queue->status != QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->lock);
		if (queue->status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(&queue->lock);
				return handle;
			}
			queue->status = QUEUE_STATUS_READY;
			handle = queue->handle;
			UNLOCK(&queue->lock);
			break;
		}
		UNLOCK(&queue->lock);
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

static int queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;
	sched_elem_t *q;

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	queue = _odp_qentry_from_ext(handle);
	LOCK(&queue->lock);
	if (queue->status != QUEUE_STATUS_READY) {
		UNLOCK(&queue->lock);
		return -1;
	}
	q = &queue->sched_elem;

#ifdef CONFIG_QSCHST_LOCK
	LOCK(&q->qschlock);
#endif
	if (_odp_queue_disable_enq(q)) {
		/* Producer side not empty */
#ifdef CONFIG_QSCHST_LOCK
		UNLOCK(&q->qschlock);
#endif
		UNLOCK(&queue->lock);
		return -1;
	}
	/* Enqueue is now disabled */
	if (q->cons_read != q->cons_write) {
		/* Consumer side is not empty
		 * Roll back previous change, enable enqueue again.
		 */
		uint32_t size;

		size = q->prod_mask + 1;
		__atomic_fetch_sub(&q->prod_write, size, __ATOMIC_RELAXED);
#ifdef CONFIG_QSCHST_LOCK
		UNLOCK(&q->qschlock);
#endif
		UNLOCK(&queue->lock);
		return -1;
	}
#ifdef CONFIG_QSCHST_LOCK
	UNLOCK(&q->qschlock);
#endif
	/* Producer and consumer sides empty, enqueue disabled
	 * Now wait until schedq state is empty and no outstanding tickets
	 */
	while (__atomic_load_n(&q->qschst.numevts, __ATOMIC_RELAXED) != 0 ||
	       __atomic_load_n(&q->qschst.cur_ticket, __ATOMIC_RELAXED) !=
	       __atomic_load_n(&q->qschst.nxt_ticket, __ATOMIC_RELAXED)) {
		sevl();
		while (wfe() && monitor32((uint32_t *)&q->qschst.numevts,
					  __ATOMIC_RELAXED) != 0)
			odp_cpu_pause();
	}

	if (q->schedq != NULL) {
		_odp_sched_queue_rem(q->sched_grp, q->sched_prio);
		q->schedq = NULL;
	}

	_odp_ishm_pool_free(queue_shm_pool, q->prod_ring);

	if (q->rwin != NULL) {
		if (_odp_rwin_free(queue_shm_pool, q->rwin) < 0) {
			_ODP_ERR("Failed to free reorder window\n");
			UNLOCK(&queue->lock);
			return -1;
		}
		q->rwin = NULL;
	}
	queue->status = QUEUE_STATUS_FREE;
	UNLOCK(&queue->lock);
	return 0;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	_odp_qentry_from_ext(handle)->param.context = context;
	odp_mb_full();
	return 0;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->status == QUEUE_STATUS_FREE ||
		    queue->status == QUEUE_STATUS_DESTROYED)
			continue;

		LOCK(&queue->lock);
		if (strcmp(name, queue->name) == 0) {
			/* found it */
			UNLOCK(&queue->lock);
			return queue->handle;
		}
		UNLOCK(&queue->lock);
	}

	return ODP_QUEUE_INVALID;
}

#ifndef CONFIG_QSCHST_LOCK
static inline int _odp_queue_enq(sched_elem_t *q,
				 _odp_event_hdr_t *event_hdr[],
				 int num)
{
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_write;
	int actual;
	uint32_t mask;
	_odp_event_hdr_t **ring;

	mask = q->prod_mask;
	ring = q->prod_ring;

	/* Load producer ring state (read & write index) */
	old_write = __atomic_load_n(&q->prod_write, __ATOMIC_RELAXED);
	do {
		/* Consumer does store-release prod_read, we need
		 * load-acquire.
		 */
		old_read = __atomic_load_n(&q->prod_read, __ATOMIC_ACQUIRE);

		actual = _ODP_MIN(num, (int)((mask + 1) - (old_write - old_read)));
		if (odp_unlikely(actual <= 0))
			return 0;

		new_write = old_write + actual;
	} while (!__atomic_compare_exchange_n(&q->prod_write,
					&old_write, /* Updated on failure */
					new_write,
					true,
					__ATOMIC_RELAXED,
					__ATOMIC_RELAXED));

#ifdef CONFIG_SPLIT_PRODCONS
	__builtin_prefetch(&q->cons_write, 0, 0);
#endif
	/* Store our event(s) in the ring */
	do {
		ring[old_write & mask] = *event_hdr++;
	} while (++old_write != new_write);
	old_write -= actual;

#ifdef CONFIG_SPLIT_PRODCONS
	__builtin_prefetch(&q->node, 1, 0);
#endif
	/* Wait for our turn to signal consumers */
	if (odp_unlikely(__atomic_load_n(&q->cons_write,
					 __ATOMIC_RELAXED) != old_write)) {
		sevl();
		while (wfe() && monitor32(&q->cons_write,
					  __ATOMIC_RELAXED) != old_write)
			odp_cpu_pause();
	}

	/* Signal consumers that events are available (release events)
	 * Enable other producers to continue
	 */
	/* Wait for writes (to ring slots) to complete */
	atomic_store_release(&q->cons_write, new_write, /*readonly=*/false);

	return actual;
}

#endif

int _odp_queue_enq_sp(sched_elem_t *q,
		      _odp_event_hdr_t *event_hdr[],
		      int num)
{
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_write;
	int actual;
	uint32_t mask;
	_odp_event_hdr_t **ring;

	mask = q->prod_mask;
	ring = q->prod_ring;

	/* Load producer ring state (read & write index) */
	old_write = q->prod_write;
	/* Consumer does store-release prod_read, we need load-acquire */
	old_read = __atomic_load_n(&q->prod_read, __ATOMIC_ACQUIRE);
	actual = _ODP_MIN(num, (int)((mask + 1) - (old_write - old_read)));
	if (odp_unlikely(actual <= 0))
		return 0;

	new_write = old_write + actual;
	q->prod_write = new_write;

	/* Store our event(s) in the ring */
	do {
		ring[old_write & mask] = *event_hdr++;
	} while (++old_write != new_write);
	old_write -= actual;

#ifdef CONFIG_SPLIT_PRODCONS
	__builtin_prefetch(&q->node, 1, 0);
#endif

	/* Signal consumers that events are available (release events)
	 * Enable other producers to continue
	 */
#ifdef CONFIG_QSCHST_LOCK
	q->cons_write = new_write;
#else
	atomic_store_release(&q->cons_write, new_write, /*readonly=*/false);
#endif

	return actual;
}

static int _queue_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
			    int num)
{
	int actual;
	queue_entry_t *queue;
	sched_scalable_thread_state_t *ts;

	queue = qentry_from_int(handle);
	ts = _odp_sched_ts;
	if (ts && odp_unlikely(ts->out_of_order) &&
	    (queue->param.order == ODP_QUEUE_ORDER_KEEP)) {
		actual = _odp_rctx_save(queue, event_hdr, num);
		return actual;
	}

#ifdef CONFIG_QSCHST_LOCK
	LOCK(&queue->sched_elem.qschlock);
	actual = _odp_queue_enq_sp(&queue->sched_elem, event_hdr, num);
#else
	actual = _odp_queue_enq(&queue->sched_elem, event_hdr, num);
#endif

	if (odp_likely(queue->sched_elem.schedq != NULL && actual != 0)) {
		/* Perform scheduler related updates. */
#ifdef CONFIG_QSCHST_LOCK
		_odp_sched_update_enq_sp(&queue->sched_elem, actual);
#else
		_odp_sched_update_enq(&queue->sched_elem, actual);
#endif
	}

#ifdef CONFIG_QSCHST_LOCK
	UNLOCK(&queue->sched_elem.qschlock);
#endif
	return actual;
}

static int _queue_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	return odp_likely(_queue_enq_multi(handle, &event_hdr, 1) == 1) ? 0 : -1;
}

static int queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	_odp_event_hdr_t *event_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = _odp_qentry_from_ext(handle);

	for (i = 0; i < num; i++)
		event_hdr[i] = _odp_event_hdr(ev[i]);

	return queue->enqueue_multi(handle, event_hdr, num);
}

static int queue_enq(odp_queue_t handle, odp_event_t ev)
{
	_odp_event_hdr_t *event_hdr;
	queue_entry_t *queue;

	queue   = _odp_qentry_from_ext(handle);
	event_hdr = _odp_event_hdr(ev);

	return queue->enqueue(handle, event_hdr);
}

/* Single-consumer dequeue. */
int _odp_queue_deq_sc(sched_elem_t *q, odp_event_t *evp, int num)
{
	int actual;
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_read;
	uint32_t mask;
	_odp_event_hdr_t **ring;

	/* Load consumer ring state (read & write index). */
	old_read  = q->cons_read;
	/* Producer does store-release cons_write, we need load-acquire */
	old_write = __atomic_load_n(&q->cons_write, __ATOMIC_ACQUIRE);
	actual    = _ODP_MIN(num, (int)(old_write - old_read));

	if (odp_unlikely(actual <= 0))
		return 0;

#ifdef CONFIG_SPLIT_PRODCONS
	__builtin_prefetch(&q->node, 1, 0);
#endif
	new_read = old_read + actual;
	q->cons_read = new_read;

	mask = q->cons_mask;
	ring = q->cons_ring;
	do {
		*evp++ = _odp_event_from_hdr(ring[old_read & mask]);
	} while (++old_read != new_read);

	/* Signal producers that empty slots are available
	 * (release ring slots). Enable other consumers to continue.
	 */
#ifdef CONFIG_QSCHST_LOCK
	q->prod_read = new_read;
#else
	/* Wait for loads (from ring slots) to complete. */
	atomic_store_release(&q->prod_read, new_read, /*readonly=*/true);
#endif
	return actual;
}

int _odp_queue_deq(sched_elem_t *q, _odp_event_hdr_t *event_hdr[], int num)
{
	int actual;
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_read;
	uint32_t mask;
	_odp_event_hdr_t **ring;
	_odp_event_hdr_t **p_event_hdr;

	mask = q->cons_mask;
	ring = q->cons_ring;

	/* Load consumer ring state (read & write index) */
	old_read = __atomic_load_n(&q->cons_read, __ATOMIC_RELAXED);
	do {
		/* Need __atomic_load to avoid compiler reordering
		 * Producer does store-release cons_write, we need
		 * load-acquire.
		 */
		old_write = __atomic_load_n(&q->cons_write, __ATOMIC_ACQUIRE);
		/* Prefetch ring buffer array */
		__builtin_prefetch(&q->cons_ring[old_read & mask], 0, 0);

		actual = _ODP_MIN(num, (int)(old_write - old_read));
		if (odp_unlikely(actual <= 0))
			return 0;

		/* Attempt to free ring slot(s) */
		new_read = old_read + actual;
	} while (!__atomic_compare_exchange_n(&q->cons_read,
					&old_read, /* Updated on failure */
					new_read,
					true,
					__ATOMIC_RELAXED,
					__ATOMIC_RELAXED));
#ifdef CONFIG_SPLIT_PRODCONS
	__builtin_prefetch(&q->prod_read, 0, 0);
#endif
	p_event_hdr = event_hdr;
	do {
		*p_event_hdr++ = ring[old_read & mask];
	} while (++old_read != new_read);
	old_read -= actual;

#ifdef CONFIG_SPLIT_PRODCONS
	__builtin_prefetch(&q->node, 1, 0);
#endif
	/* Wait for our turn to signal producers */
	if (odp_unlikely(__atomic_load_n(&q->prod_read, __ATOMIC_RELAXED) !=
		old_read)) {
		sevl();
		while (wfe() && monitor32(&q->prod_read,
					  __ATOMIC_RELAXED) != old_read)
			odp_cpu_pause();
	}

	/* Signal producers that empty slots are available
	 * (release ring slots)
	 * Enable other consumers to continue
	 */
	/* Wait for loads (from ring slots) to complete */
	atomic_store_release(&q->prod_read, new_read, /*readonly=*/true);

	return actual;
}

int _odp_queue_deq_mc(sched_elem_t *q, odp_event_t *evp, int num)
{
	int ret, evt_idx;
	_odp_event_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	ret = _odp_queue_deq(q, hdr_tbl, num);
	if (odp_likely(ret != 0)) {
		for (evt_idx = 0; evt_idx < num; evt_idx++)
			evp[evt_idx] = _odp_event_from_hdr(hdr_tbl[evt_idx]);
	}

	return ret;
}

static int _queue_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
			    int num)
{
	sched_elem_t *q;
	queue_entry_t *queue;

	queue = qentry_from_int(handle);
	q = &queue->sched_elem;
	return _odp_queue_deq(q, event_hdr, num);
}

static _odp_event_hdr_t *_queue_deq(odp_queue_t handle)
{
	sched_elem_t *q;
	_odp_event_hdr_t *event_hdr;
	queue_entry_t *queue;

	queue = qentry_from_int(handle);
	q = &queue->sched_elem;
	if (_odp_queue_deq(q, &event_hdr, 1) == 1)
		return event_hdr;
	else
		return NULL;
}

static int queue_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue;
	int ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = _odp_qentry_from_ext(handle);

	ret = queue->dequeue_multi(handle, (_odp_event_hdr_t **)ev, num);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->num_timers))
		timer_run(ret ? 2 : 1);

	return ret;
}

static odp_event_t queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue = _odp_qentry_from_ext(handle);
	odp_event_t ev = (odp_event_t)queue->dequeue(handle);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->num_timers))
		timer_run(ev != ODP_EVENT_INVALID ? 2 : 1);

	return ev;
}

static void queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->nonblocking = ODP_BLOCKING;
	params->sched.prio = odp_schedule_default_prio();
	params->sched.sync = ODP_SCHED_SYNC_PARALLEL;
	params->sched.group = ODP_SCHED_GROUP_ALL;
	params->order = ODP_QUEUE_ORDER_KEEP;
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

	queue_id = queue_to_id(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		_ODP_ERR("Invalid queue handle:%" PRIu64 "\n", odp_queue_to_u64(handle));
		return -1;
	}

	queue = get_qentry(queue_id);

	LOCK(&queue->lock);
	status = queue->status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(&queue->lock);
		_ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->name;
	info->param = queue->param;

	UNLOCK(&queue->lock);

	return 0;
}

static void queue_print(odp_queue_t handle)
{
	odp_pktio_info_t pktio_info;
	queue_entry_t *queue;
	uint32_t queue_id;
	int status;

	queue_id = queue_to_id(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		_ODP_ERR("Invalid queue handle: 0x%" PRIx64 "\n", odp_queue_to_u64(handle));
		return;
	}

	queue = get_qentry(queue_id);

	LOCK(&queue->lock);
	status = queue->status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(&queue->lock);
		_ODP_ERR("Invalid queue status:%d\n", status);
		return;
	}
	_ODP_PRINT("\nQueue info\n");
	_ODP_PRINT("----------\n");
	_ODP_PRINT("  handle          %p\n", (void *)queue->handle);
	_ODP_PRINT("  index           %" PRIu32 "\n", queue->index);
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
		_ODP_PRINT("    priority      %d\n", queue->param.sched.prio);
		_ODP_PRINT("    group         %d\n", queue->param.sched.group);
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
	_ODP_PRINT("  param.size      %" PRIu32 "\n", queue->param.size);
	_ODP_PRINT("\n");

	UNLOCK(&queue->lock);
}

static void queue_print_all(void)
{
	uint32_t i, index;
	const char *name;
	int status;
	odp_queue_type_t type;
	odp_nonblocking_t blocking;
	odp_queue_op_mode_t enq_mode;
	odp_queue_op_mode_t deq_mode;
	odp_queue_order_t order;
	odp_schedule_sync_t sync;
	int prio;
	const char *bl_str;
	char type_c, enq_c, deq_c, order_c, sync_c;
	const int col_width = 24;

	_ODP_PRINT("\nList of all queues\n");
	_ODP_PRINT("------------------\n");
	_ODP_PRINT(" idx %-*s type blk enq deq ord sync prio\n", col_width, "name");

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->status != QUEUE_STATUS_READY)
			continue;

		LOCK(&queue->lock);

		status   = queue->status;
		index    = queue->index;
		name     = queue->name;
		type     = queue->type;
		blocking = queue->param.nonblocking;
		enq_mode = queue->param.enq_mode;
		deq_mode = queue->param.deq_mode;
		order    = queue->param.order;
		prio     = queue->param.sched.prio;
		sync     = queue->param.sched.sync;

		UNLOCK(&queue->lock);

		if (status != QUEUE_STATUS_READY)
			continue;

		type_c = (type == ODP_QUEUE_TYPE_PLAIN) ? 'P' : 'S';

		bl_str = (blocking == ODP_BLOCKING) ? "B" :
			 ((blocking == ODP_NONBLOCKING_LF) ? "LF" : "WF");

		enq_c = (enq_mode == ODP_QUEUE_OP_MT) ? 'S' :
			((enq_mode == ODP_QUEUE_OP_MT_UNSAFE) ? 'U' : 'D');

		deq_c = (deq_mode == ODP_QUEUE_OP_MT) ? 'S' :
			((deq_mode == ODP_QUEUE_OP_MT_UNSAFE) ? 'U' : 'D');

		order_c = (order == ODP_QUEUE_ORDER_KEEP) ? 'K' : 'I';

		_ODP_PRINT("%4u %-*s    %c  %2s", index, col_width, name, type_c, bl_str);
		_ODP_PRINT("   %c   %c   %c", enq_c, deq_c, order_c);

		if (type == ODP_QUEUE_TYPE_SCHED) {
			sync_c = (sync == ODP_SCHED_SYNC_PARALLEL) ? 'P' :
				 ((sync == ODP_SCHED_SYNC_ATOMIC) ? 'A' : 'O');
			_ODP_PRINT("    %c %4i", sync_c, prio);
		}

		_ODP_PRINT("\n");
	}

	_ODP_PRINT("\n");
}

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(odp_queue_t handle)
{
	return qentry_from_int(handle)->pktout;
}

static void queue_set_pktout(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	qentry_from_int(handle)->pktout.pktio = pktio;
	qentry_from_int(handle)->pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(odp_queue_t handle)
{
	return qentry_from_int(handle)->pktin;
}

static void queue_set_pktin(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	qentry_from_int(handle)->pktin.pktio = pktio;
	qentry_from_int(handle)->pktin.index = index;
}

static void queue_set_enq_deq_func(odp_queue_t handle,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	if (enq)
		qentry_from_int(handle)->enqueue = enq;

	if (enq_multi)
		qentry_from_int(handle)->enqueue_multi = enq_multi;

	if (deq)
		qentry_from_int(handle)->dequeue = deq;

	if (deq_multi)
		qentry_from_int(handle)->dequeue_multi = deq_multi;
}

static int queue_orig_multi(odp_queue_t handle,
			    _odp_event_hdr_t **event_hdr, int num)
{
	return qentry_from_int(handle)->orig_dequeue_multi(handle,
							     event_hdr, num);
}

static void queue_timer_add(odp_queue_t handle)
{
	queue_entry_t *queue = _odp_qentry_from_ext(handle);

	odp_atomic_inc_u64(&queue->num_timers);
}

static void queue_timer_rem(odp_queue_t handle)
{
	queue_entry_t *queue = _odp_qentry_from_ext(handle);

	odp_atomic_dec_u64(&queue->num_timers);
}

/* API functions */
_odp_queue_api_fn_t _odp_queue_scalable_api = {
	.queue_create = queue_create,
	.queue_create_multi = queue_create_multi,
	.queue_destroy = queue_destroy,
	.queue_lookup = queue_lookup,
	.queue_capability = queue_capability,
	.queue_context_set = queue_context_set,
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
	.queue_info = queue_info,
	.queue_print = queue_print,
	.queue_print_all = queue_print_all
};

/* Functions towards internal components */
queue_fn_t _odp_queue_scalable_fn = {
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
