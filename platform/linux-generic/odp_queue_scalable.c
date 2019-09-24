/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
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

#include <odp_config_internal.h>
#include <odp_debug_internal.h>

#include <odp_packet_io_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_scalable_internal.h>
#include <odp_schedule_if.h>
#include <odp_timer_internal.h>
#include <odp_shm_internal.h>
#include <odp_ishmpool_internal.h>
#include <odp/api/plat/queue_inline_types.h>
#include <odp_global_data.h>

#include <string.h>
#include <inttypes.h>

#define MIN(a, b) \
	({ \
		__typeof__(a) tmp_a = (a); \
		__typeof__(b) tmp_b = (b); \
		tmp_a < tmp_b ? tmp_a : tmp_b; \
	})

#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)

extern __thread sched_scalable_thread_state_t *sched_ts;
extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

typedef struct queue_table_t {
	queue_entry_t  queue[CONFIG_MAX_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;
static _odp_ishm_pool_t *queue_shm_pool;

static int _queue_enq(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr);
static odp_buffer_hdr_t *_queue_deq(odp_queue_t handle);
static int _queue_enq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num);
static int _queue_deq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num);

static queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

queue_entry_t *qentry_from_ext(odp_queue_t handle)
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
	odp_buffer_hdr_t **ring;
	uint32_t size;

	sched_elem = &queue->s.sched_elem;
	ring_size = param->size > 0 ?
		ROUNDUP_POWER2_U32(param->size) : CONFIG_SCAL_QUEUE_SIZE;
	strncpy(queue->s.name, name ? name : "", ODP_QUEUE_NAME_LEN - 1);
	queue->s.name[ODP_QUEUE_NAME_LEN - 1] = 0;
	memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));

	size = ring_size * sizeof(odp_buffer_hdr_t *);
	ring = (odp_buffer_hdr_t **)shm_pool_alloc_align(queue_shm_pool, size);
	if (NULL == ring)
		return -1;

	for (ring_idx = 0; ring_idx < ring_size; ring_idx++)
		ring[ring_idx] = NULL;

	queue->s.type = queue->s.param.type;
	odp_atomic_init_u64(&queue->s.num_timers, 0);

	queue->s.enqueue = _queue_enq;
	queue->s.dequeue = _queue_deq;
	queue->s.enqueue_multi = _queue_enq_multi;
	queue->s.dequeue_multi = _queue_deq_multi;
	queue->s.orig_dequeue_multi = _queue_deq_multi;
	queue->s.pktin = PKTIN_INVALID;

	sched_elem->node.next = NULL;
#ifdef CONFIG_QSCHST_LOCK
	LOCK_INIT(&sched_elem->qschlock);
#endif
	sched_elem->qschst.numevts = 0;
	sched_elem->qschst.wrr_budget = CONFIG_WRR_WEIGHT;
	sched_elem->qschst.cur_ticket = 0;
	sched_elem->qschst.nxt_ticket = 0;
	sched_elem->pop_deficit = 0;
	if (queue->s.type == ODP_QUEUE_TYPE_SCHED)
		sched_elem->qschst_type = queue->s.param.sched.sync;
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
	sched_elem->user_ctx = queue->s.param.context;
#ifdef CONFIG_SPLIT_PRODCONS
	sched_elem->cons_ring = ring;
	sched_elem->cons_mask = ring_size - 1;
	sched_elem->cons_type = sched_elem->qschst_type;
#endif

	/* Queue initialized successfully, add it to the sched group */
	if (queue->s.type == ODP_QUEUE_TYPE_SCHED) {
		int prio = odp_schedule_max_prio() - param->sched.prio;

		if (queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
			sched_elem->rwin =
				rwin_alloc(queue_shm_pool,
					   queue->s.param.sched.lock_count);
			if (sched_elem->rwin == NULL) {
				ODP_ERR("Reorder window not created\n");
				goto rwin_create_failed;
			}
		}
		sched_elem->sched_grp = param->sched.group;
		sched_elem->sched_prio = prio;
		sched_elem->schedq =
			sched_queue_add(param->sched.group, prio);
		ODP_ASSERT(sched_elem->schedq != NULL);

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

	ODP_DBG("Queue init ... ");

	/* Fill in queue entry field offsets for inline functions */
	memset(&_odp_queue_inline_offset, 0,
	       sizeof(_odp_queue_inline_offset_t));
	_odp_queue_inline_offset.context = offsetof(queue_entry_t,
						    s.param.context);

	/* Create shared memory pool to allocate shared memory for the
	 * queues. Use the default queue size.
	 */
	/* Add size of the array holding the queues */
	pool_size = sizeof(queue_table_t);
	/* Add storage required for queues */
	pool_size += (CONFIG_SCAL_QUEUE_SIZE *
		      sizeof(odp_buffer_hdr_t *)) * CONFIG_MAX_QUEUES;

	/* Add the reorder window size */
	pool_size += sizeof(reorder_window_t) * CONFIG_MAX_QUEUES;
	/* Choose min_alloc and max_alloc such that buddy allocator is
	 * is selected.
	 */
	min_alloc = 0;
	max_alloc = CONFIG_SCAL_QUEUE_SIZE * sizeof(odp_buffer_hdr_t *);
	queue_shm_pool = _odp_ishm_pool_create("queue_shm_pool",
					       pool_size,
					       min_alloc, max_alloc, 0);
	if (queue_shm_pool == NULL) {
		ODP_ERR("Failed to allocate shared memory pool for"
			" queues\n");
		goto queue_shm_pool_create_failed;
	}

	queue_tbl = (queue_table_t *)
		    shm_pool_alloc_align(queue_shm_pool,
					 sizeof(queue_table_t));
	if (queue_tbl == NULL) {
		ODP_ERR("Failed to reserve shared memory for queue table\n");
		goto queue_tbl_ishm_alloc_failed;
	}

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue;

		queue = get_qentry(i);
		LOCK_INIT(&queue->s.lock);
		queue->s.index  = i;
		queue->s.handle = (odp_queue_t)queue;
	}

	ODP_DBG("done\n");
	ODP_DBG("Queue init global\n");
	ODP_DBG("  struct queue_entry_s size %zu\n",
		sizeof(struct queue_entry_s));
	ODP_DBG("  queue_entry_t size        %zu\n",
		sizeof(queue_entry_t));
	ODP_DBG("\n");

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
		if (__atomic_load_n(&queue->s.status,
				    __ATOMIC_RELAXED) != QUEUE_STATUS_FREE) {
			ODP_ERR("Not destroyed queue: %s\n", queue->s.name);
			rc = -1;
		}
	}

	_odp_ishm_pool_free(queue_shm_pool, queue_tbl);

	ret = _odp_ishm_pool_destroy(queue_shm_pool);
	if (ret < 0) {
		ODP_ERR("Failed to destroy shared memory pool for queues\n");
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
#if ODP_DEPRECATED_API
	capa->max_ordered_locks = sched_fn->max_ordered_locks();
	capa->max_sched_groups  = sched_fn->num_grps();
	capa->sched_prios       = odp_schedule_num_prio();
	capa->sched.max_num     = CONFIG_MAX_SCHED_QUEUES;
	capa->sched.max_size    = 0;
#endif
	capa->plain.max_num     = CONFIG_MAX_PLAIN_QUEUES;
	capa->plain.max_size    = 0;

	return 0;
}

static odp_queue_type_t queue_type(odp_queue_t handle)
{
	return qentry_from_ext(handle)->s.type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return qentry_from_ext(handle)->s.param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return qentry_from_ext(handle)->s.param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return qentry_from_ext(handle)->s.param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_ext(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->s.param.sched.lock_count : 0;
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
			ODP_ERR("Bad queue priority: %i\n", param->sched.prio);
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

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->s.lock);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(&queue->s.lock);
				return handle;
			}
			queue->s.status = QUEUE_STATUS_READY;
			handle = queue->s.handle;
			UNLOCK(&queue->s.lock);
			break;
		}
		UNLOCK(&queue->s.lock);
	}
	return handle;
}

static int queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;
	sched_elem_t *q;

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	queue = qentry_from_ext(handle);
	LOCK(&queue->s.lock);
	if (queue->s.status != QUEUE_STATUS_READY) {
		UNLOCK(&queue->s.lock);
		return -1;
	}
	q = &queue->s.sched_elem;

#ifdef CONFIG_QSCHST_LOCK
	LOCK(&q->qschlock);
#endif
	if (_odp_queue_disable_enq(q)) {
		/* Producer side not empty */
#ifdef CONFIG_QSCHST_LOCK
		UNLOCK(&q->qschlock);
#endif
		UNLOCK(&queue->s.lock);
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
		UNLOCK(&queue->s.lock);
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
			doze();
	}

	if (q->schedq != NULL) {
		sched_queue_rem(q->sched_grp, q->sched_prio);
		q->schedq = NULL;
	}

	_odp_ishm_pool_free(queue_shm_pool, q->prod_ring);

	if (q->rwin != NULL) {
		if (rwin_free(queue_shm_pool, q->rwin) < 0) {
			ODP_ERR("Failed to free reorder window\n");
			UNLOCK(&queue->s.lock);
			return -1;
		}
		q->rwin = NULL;
	}
	queue->s.status = QUEUE_STATUS_FREE;
	UNLOCK(&queue->s.lock);
	return 0;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	qentry_from_ext(handle)->s.param.context = context;
	odp_mb_full();
	return 0;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
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

#ifndef CONFIG_QSCHST_LOCK
static inline int _odp_queue_enq(sched_elem_t *q,
				 odp_buffer_hdr_t *buf_hdr[],
				 int num)
{
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_write;
	int actual;
	uint32_t mask;
	odp_buffer_hdr_t **ring;

	mask = q->prod_mask;
	ring = q->prod_ring;

	/* Load producer ring state (read & write index) */
	old_write = __atomic_load_n(&q->prod_write, __ATOMIC_RELAXED);
	do {
		/* Consumer does store-release prod_read, we need
		 * load-acquire.
		 */
		old_read = __atomic_load_n(&q->prod_read, __ATOMIC_ACQUIRE);

		actual = MIN(num, (int)((mask + 1) - (old_write - old_read)));
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
		ring[old_write & mask] = *buf_hdr++;
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
			doze();
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
		      odp_buffer_hdr_t *buf_hdr[],
		      int num)
{
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_write;
	int actual;
	uint32_t mask;
	odp_buffer_hdr_t **ring;

	mask = q->prod_mask;
	ring = q->prod_ring;

	/* Load producer ring state (read & write index) */
	old_write = q->prod_write;
	/* Consumer does store-release prod_read, we need load-acquire */
	old_read = __atomic_load_n(&q->prod_read, __ATOMIC_ACQUIRE);
	actual = MIN(num, (int)((mask + 1) - (old_write - old_read)));
	if (odp_unlikely(actual <= 0))
		return 0;

	new_write = old_write + actual;
	q->prod_write = new_write;

	/* Store our event(s) in the ring */
	do {
		ring[old_write & mask] = *buf_hdr++;
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

static int _queue_enq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	int actual;
	queue_entry_t *queue;
	sched_scalable_thread_state_t *ts;

	queue = qentry_from_int(handle);
	ts = sched_ts;
	if (ts && odp_unlikely(ts->out_of_order) &&
	    (queue->s.param.order == ODP_QUEUE_ORDER_KEEP)) {
		actual = rctx_save(queue, buf_hdr, num);
		return actual;
	}

#ifdef CONFIG_QSCHST_LOCK
	LOCK(&queue->s.sched_elem.qschlock);
	actual = _odp_queue_enq_sp(&queue->s.sched_elem, buf_hdr, num);
#else
	actual = _odp_queue_enq(&queue->s.sched_elem, buf_hdr, num);
#endif

	if (odp_likely(queue->s.sched_elem.schedq != NULL && actual != 0)) {
		/* Perform scheduler related updates. */
#ifdef CONFIG_QSCHST_LOCK
		sched_update_enq_sp(&queue->s.sched_elem, actual);
#else
		sched_update_enq(&queue->s.sched_elem, actual);
#endif
	}

#ifdef CONFIG_QSCHST_LOCK
	UNLOCK(&queue->s.sched_elem.qschlock);
#endif
	return actual;
}

static int _queue_enq(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	return odp_likely(
		_queue_enq_multi(handle, &buf_hdr, 1) == 1) ? 0 : -1;
}

static int queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = qentry_from_ext(handle);

	for (i = 0; i < num; i++)
		buf_hdr[i] = buf_hdl_to_hdr(odp_buffer_from_event(ev[i]));

	return queue->s.enqueue_multi(handle, buf_hdr, num);
}

static int queue_enq(odp_queue_t handle, odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue   = qentry_from_ext(handle);
	buf_hdr = buf_hdl_to_hdr(odp_buffer_from_event(ev));

	return queue->s.enqueue(handle, buf_hdr);
}

/* Single-consumer dequeue. */
int _odp_queue_deq_sc(sched_elem_t *q, odp_event_t *evp, int num)
{
	int actual;
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_read;
	uint32_t mask;
	odp_buffer_hdr_t **ring;

	/* Load consumer ring state (read & write index). */
	old_read  = q->cons_read;
	/* Producer does store-release cons_write, we need load-acquire */
	old_write = __atomic_load_n(&q->cons_write, __ATOMIC_ACQUIRE);
	actual    = MIN(num, (int)(old_write - old_read));

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
		*evp++ = odp_buffer_to_event(
				buf_from_buf_hdr(ring[old_read & mask]));
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

inline int _odp_queue_deq(sched_elem_t *q, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int actual;
	ringidx_t old_read;
	ringidx_t old_write;
	ringidx_t new_read;
	uint32_t mask;
	odp_buffer_hdr_t **ring;
	odp_buffer_hdr_t **p_buf_hdr;

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

		actual = MIN(num, (int)(old_write - old_read));
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
	p_buf_hdr = buf_hdr;
	do {
		*p_buf_hdr++ = ring[old_read & mask];
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
			doze();
	}

	/* Signal producers that empty slots are available
	 * (release ring slots)
	 * Enable other consumers to continue
	 */
	/* Wait for loads (from ring slots) to complete */
	atomic_store_release(&q->prod_read, new_read, /*readonly=*/true);

	return actual;
}

inline int _odp_queue_deq_mc(sched_elem_t *q, odp_event_t *evp, int num)
{
	int ret, evt_idx;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	ret = _odp_queue_deq(q, hdr_tbl, num);
	if (odp_likely(ret != 0)) {
		for (evt_idx = 0; evt_idx < num; evt_idx++)
			evp[evt_idx] = odp_buffer_to_event(
					buf_from_buf_hdr(hdr_tbl[evt_idx]));
	}

	return ret;
}

static int _queue_deq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	sched_elem_t *q;
	queue_entry_t *queue;

	queue = qentry_from_int(handle);
	q = &queue->s.sched_elem;
	return _odp_queue_deq(q, buf_hdr, num);
}

static odp_buffer_hdr_t *_queue_deq(odp_queue_t handle)
{
	sched_elem_t *q;
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue = qentry_from_int(handle);
	q = &queue->s.sched_elem;
	if (_odp_queue_deq(q, &buf_hdr, 1) == 1)
		return buf_hdr;
	else
		return NULL;
}

static int queue_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue;
	int ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = qentry_from_ext(handle);

	ret = queue->s.dequeue_multi(handle, (odp_buffer_hdr_t **)ev, num);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->s.num_timers))
		timer_run(ret ? 2 : 1);

	return ret;
}

static odp_event_t queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_ext(handle);
	odp_event_t ev = (odp_event_t)queue->s.dequeue(handle);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->s.num_timers))
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
		ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_id(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
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

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(odp_queue_t handle)
{
	return qentry_from_int(handle)->s.pktout;
}

static void queue_set_pktout(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	qentry_from_int(handle)->s.pktout.pktio = pktio;
	qentry_from_int(handle)->s.pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(odp_queue_t handle)
{
	return qentry_from_int(handle)->s.pktin;
}

static void queue_set_pktin(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	qentry_from_int(handle)->s.pktin.pktio = pktio;
	qentry_from_int(handle)->s.pktin.index = index;
}

static void queue_set_enq_deq_func(odp_queue_t handle,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	if (enq)
		qentry_from_int(handle)->s.enqueue = enq;

	if (enq_multi)
		qentry_from_int(handle)->s.enqueue_multi = enq_multi;

	if (deq)
		qentry_from_int(handle)->s.dequeue = deq;

	if (deq_multi)
		qentry_from_int(handle)->s.dequeue_multi = deq_multi;
}

static int queue_orig_multi(odp_queue_t handle,
			    odp_buffer_hdr_t **buf_hdr, int num)
{
	return qentry_from_int(handle)->s.orig_dequeue_multi(handle,
							     buf_hdr, num);
}

static void queue_timer_add(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_ext(handle);

	odp_atomic_inc_u64(&queue->s.num_timers);
}

static void queue_timer_rem(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_ext(handle);

	odp_atomic_dec_u64(&queue->s.num_timers);
}

/* API functions */
_odp_queue_api_fn_t queue_scalable_api = {
	.queue_create = queue_create,
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
	.queue_info = queue_info
};

/* Functions towards internal components */
queue_fn_t queue_scalable_fn = {
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
