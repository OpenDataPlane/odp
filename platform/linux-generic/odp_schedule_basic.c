/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <string.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/api/time.h>
#include <odp/api/spinlock.h>
#include <odp/api/hints.h>
#include <odp/api/cpu.h>
#include <odp/api/thrmask.h>
#include <odp_config_internal.h>
#include <odp_align_internal.h>
#include <odp/api/sync.h>
#include <odp/api/packet_io.h>
#include <odp_ring_internal.h>
#include <odp_timer_internal.h>
#include <odp_queue_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_libconfig_internal.h>

/* Number of priority levels  */
#define NUM_PRIO 8

ODP_STATIC_ASSERT(ODP_SCHED_PRIO_LOWEST == (NUM_PRIO - 1),
		  "lowest_prio_does_not_match_with_num_prios");

ODP_STATIC_ASSERT((ODP_SCHED_PRIO_NORMAL > 0) &&
		  (ODP_SCHED_PRIO_NORMAL < (NUM_PRIO - 1)),
		  "normal_prio_is_not_between_highest_and_lowest");

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 32

/* Group weight table size */
#define GRP_WEIGHT_TBL_SIZE NUM_SCHED_GRPS

/* Maximum priority queue spread */
#define MAX_SPREAD 8

/* Minimum priority queue spread */
#define MIN_SPREAD 1

/* A thread polls a non preferred sched queue every this many polls
 * of the prefer queue. */
#define PREFER_RATIO 64

/* Spread weight table */
#define SPREAD_TBL_SIZE ((MAX_SPREAD - 1) * PREFER_RATIO)

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO ODP_CONFIG_PKTIO_ENTRIES

/* Maximum pktin index. Needs to fit into 8 bits. */
#define MAX_PKTIN_INDEX 255

/* Not a valid index */
#define NULL_INDEX ((uint32_t)-1)

/* Maximum priority queue ring size. A ring must be large enough to store all
 * queues in the worst case (all queues are scheduled, have the same priority
 * and no spreading). */
#define MAX_RING_SIZE ODP_CONFIG_QUEUES

/* Priority queue empty, not a valid queue index. */
#define PRIO_QUEUE_EMPTY NULL_INDEX

/* For best performance, the number of queues should be a power of two. */
ODP_STATIC_ASSERT(CHECK_IS_POWER2(ODP_CONFIG_QUEUES),
		  "Number_of_queues_is_not_power_of_two");

/* Ring size must be power of two, so that mask can be used. */
ODP_STATIC_ASSERT(CHECK_IS_POWER2(MAX_RING_SIZE),
		  "Ring_size_is_not_power_of_two");

/* Mask of queues per priority */
typedef uint8_t pri_mask_t;

ODP_STATIC_ASSERT((8 * sizeof(pri_mask_t)) >= MAX_SPREAD,
		  "pri_mask_t_is_too_small");

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Maximum number of dequeues */
#define MAX_DEQ CONFIG_BURST_SIZE

/* Ordered stash size */
#define MAX_ORDERED_STASH 512

/* Storage for stashed enqueue operation arguments */
typedef struct {
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue_entry;
	int num;
} ordered_stash_t;

/* Ordered lock states */
typedef union {
	uint8_t u8[CONFIG_QUEUE_MAX_ORD_LOCKS];
	uint32_t all;
} lock_called_t;

ODP_STATIC_ASSERT(sizeof(lock_called_t) == sizeof(uint32_t),
		  "Lock_called_values_do_not_fit_in_uint32");

/* Scheduler local data */
typedef struct {
	int thr;
	uint16_t stash_num;
	uint16_t stash_index;
	uint16_t grp_round;
	uint16_t spread_round;
	uint32_t stash_qi;
	odp_queue_t stash_queue;
	odp_event_t stash_ev[MAX_DEQ];

	uint32_t grp_epoch;
	uint16_t num_grp;
	uint16_t pause;
	uint8_t grp[NUM_SCHED_GRPS];
	uint8_t spread_tbl[SPREAD_TBL_SIZE];
	uint8_t grp_weight[GRP_WEIGHT_TBL_SIZE];

	struct {
		/* Source queue index */
		uint32_t src_queue;
		uint64_t ctx; /**< Ordered context id */
		int stash_num; /**< Number of stashed enqueue operations */
		uint8_t in_order; /**< Order status */
		lock_called_t lock_called; /**< States of ordered locks */
		/** Storage for stashed enqueue operations */
		ordered_stash_t stash[MAX_ORDERED_STASH];
	} ordered;

} sched_local_t;

/* Priority queue */
typedef struct ODP_ALIGNED_CACHE {
	/* Ring header */
	ring_t ring;

	/* Ring data: queue indexes */
	uint32_t queue_index[MAX_RING_SIZE];

} prio_queue_t;

/* Order context of a queue */
typedef struct ODP_ALIGNED_CACHE {
	/* Current ordered context id */
	odp_atomic_u64_t ODP_ALIGNED_CACHE ctx;

	/* Next unallocated context id */
	odp_atomic_u64_t next_ctx;

	/* Array of ordered locks */
	odp_atomic_u64_t lock[CONFIG_QUEUE_MAX_ORD_LOCKS];

} order_context_t;

typedef struct {
	pri_mask_t     pri_mask[NUM_PRIO];
	odp_spinlock_t mask_lock;

	prio_queue_t   prio_q[NUM_SCHED_GRPS][NUM_PRIO][MAX_SPREAD];

	odp_shm_t      shm;

	struct {
		uint8_t num_spread;
	} config;

	uint32_t       pri_count[NUM_PRIO][MAX_SPREAD];

	odp_thrmask_t    mask_all;
	odp_spinlock_t   grp_lock;
	odp_atomic_u32_t grp_epoch;
	uint32_t         ring_mask;
	uint16_t         max_spread;

	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
		int	       allocated;
	} sched_grp[NUM_SCHED_GRPS];

	struct {
		uint8_t grp;
		uint8_t prio;
		uint8_t spread;
		uint8_t sync;
		uint8_t order_lock_count;
		uint8_t poll_pktin;
		uint8_t pktio_index;
		uint8_t pktin_index;
	} queue[ODP_CONFIG_QUEUES];

	struct {
		int num_pktin;
	} pktio[NUM_PKTIO];
	odp_spinlock_t pktio_lock;

	order_context_t order[ODP_CONFIG_QUEUES];

} sched_global_t;

/* Check that queue[] variables are large enough */
ODP_STATIC_ASSERT(NUM_SCHED_GRPS  <= 256, "Group_does_not_fit_8_bits");
ODP_STATIC_ASSERT(NUM_PRIO        <= 256, "Prio_does_not_fit_8_bits");
ODP_STATIC_ASSERT(MAX_SPREAD      <= 256, "Spread_does_not_fit_8_bits");
ODP_STATIC_ASSERT(CONFIG_QUEUE_MAX_ORD_LOCKS <= 256,
		  "Ordered_lock_count_does_not_fit_8_bits");
ODP_STATIC_ASSERT(NUM_PKTIO        <= 256, "Pktio_index_does_not_fit_8_bits");
ODP_STATIC_ASSERT(CHECK_IS_POWER2(GRP_WEIGHT_TBL_SIZE), "Not_power_of_2");

/* Global scheduler context */
static sched_global_t *sched;

/* Thread local scheduler context */
static __thread sched_local_t sched_local;

/* Function prototypes */
static inline void schedule_release_context(void);

static int read_config_file(sched_global_t *sched)
{
	const char *str;
	int val = 0;

	ODP_PRINT("Scheduler config:\n");

	str = "sched_basic.prio_spread";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_SPREAD || val < MIN_SPREAD) {
		ODP_ERR("Bad value %s = %u\n", str, val);
		return -1;
	}

	sched->config.num_spread = val;
	ODP_PRINT("  %s: %i\n\n", str, val);

	return 0;
}

static inline uint8_t prio_spread_index(uint32_t index)
{
	return index % sched->config.num_spread;
}

static void sched_local_init(void)
{
	int i;
	uint8_t spread;
	uint8_t num_spread = sched->config.num_spread;
	uint8_t offset = 1;

	memset(&sched_local, 0, sizeof(sched_local_t));

	sched_local.thr         = odp_thread_id();
	sched_local.stash_queue = ODP_QUEUE_INVALID;
	sched_local.stash_qi    = PRIO_QUEUE_EMPTY;
	sched_local.ordered.src_queue = NULL_INDEX;

	spread = prio_spread_index(sched_local.thr);

	for (i = 0; i < SPREAD_TBL_SIZE; i++) {
		sched_local.spread_tbl[i] = spread;

		if (num_spread > 1 && (i % PREFER_RATIO) == 0) {
			sched_local.spread_tbl[i] = prio_spread_index(spread +
								      offset);
			offset++;
			if (offset == num_spread)
				offset = 1;
		}
	}
}

static int schedule_init_global(void)
{
	odp_shm_t shm;
	int i, j, grp;

	ODP_DBG("Schedule init ... ");

	shm = odp_shm_reserve("odp_scheduler",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	sched = odp_shm_addr(shm);

	if (sched == NULL) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	memset(sched, 0, sizeof(sched_global_t));

	if (read_config_file(sched)) {
		odp_shm_free(shm);
		return -1;
	}

	/* When num_spread == 1, only spread_tbl[0] is used. */
	sched->max_spread = (sched->config.num_spread - 1) * PREFER_RATIO;
	sched->shm  = shm;
	odp_spinlock_init(&sched->mask_lock);

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		for (i = 0; i < NUM_PRIO; i++) {
			for (j = 0; j < MAX_SPREAD; j++) {
				prio_queue_t *prio_q;
				int k;

				prio_q = &sched->prio_q[grp][i][j];
				ring_init(&prio_q->ring);

				for (k = 0; k < MAX_RING_SIZE; k++) {
					prio_q->queue_index[k] =
					PRIO_QUEUE_EMPTY;
				}
			}
		}
	}

	odp_spinlock_init(&sched->pktio_lock);
	for (i = 0; i < NUM_PKTIO; i++)
		sched->pktio[i].num_pktin = 0;

	odp_spinlock_init(&sched->grp_lock);
	odp_atomic_init_u32(&sched->grp_epoch, 0);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&sched->sched_grp[i].mask);
	}

	sched->sched_grp[ODP_SCHED_GROUP_ALL].allocated = 1;
	sched->sched_grp[ODP_SCHED_GROUP_WORKER].allocated = 1;
	sched->sched_grp[ODP_SCHED_GROUP_CONTROL].allocated = 1;

	odp_thrmask_setall(&sched->mask_all);

	ODP_DBG("done\n");

	return 0;
}

static inline void queue_destroy_finalize(uint32_t qi)
{
	sched_cb_queue_destroy_finalize(qi);
}

static int schedule_term_global(void)
{
	int ret = 0;
	int rc = 0;
	int i, j, grp;
	uint32_t ring_mask = sched->ring_mask;

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		for (i = 0; i < NUM_PRIO; i++) {
			for (j = 0; j < MAX_SPREAD; j++) {
				ring_t *ring = &sched->prio_q[grp][i][j].ring;
				uint32_t qi;

				while ((qi = ring_deq(ring, ring_mask)) !=
				       RING_EMPTY) {
					odp_event_t events[1];
					int num;

					num = sched_cb_queue_deq_multi(qi,
								       events,
								       1, 1);

					if (num < 0)
						queue_destroy_finalize(qi);

					if (num > 0)
						ODP_ERR("Queue not empty\n");
				}
			}
		}
	}

	ret = odp_shm_free(sched->shm);
	if (ret < 0) {
		ODP_ERR("Shm free failed for odp_scheduler");
		rc = -1;
	}

	return rc;
}

static int schedule_init_local(void)
{
	sched_local_init();
	return 0;
}

static int schedule_term_local(void)
{
	if (sched_local.stash_num) {
		ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	schedule_release_context();
	return 0;
}

static inline void grp_update_mask(int grp, const odp_thrmask_t *new_mask)
{
	odp_thrmask_copy(&sched->sched_grp[grp].mask, new_mask);
	odp_atomic_add_rel_u32(&sched->grp_epoch, 1);
}

static inline int grp_update_tbl(void)
{
	int i;
	int num = 0;
	int thr = sched_local.thr;

	odp_spinlock_lock(&sched->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		if (sched->sched_grp[i].allocated == 0)
			continue;

		if (odp_thrmask_isset(&sched->sched_grp[i].mask, thr)) {
			sched_local.grp[num] = i;
			num++;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);

	/* Update group weights. Round robin over all thread's groups. */
	for (i = 0; i < GRP_WEIGHT_TBL_SIZE; i++)
		sched_local.grp_weight[i] = i % num;

	sched_local.num_grp = num;
	return num;
}

static uint32_t schedule_max_ordered_locks(void)
{
	return CONFIG_QUEUE_MAX_ORD_LOCKS;
}

static void pri_set(int id, int prio)
{
	odp_spinlock_lock(&sched->mask_lock);
	sched->pri_mask[prio] |= 1 << id;
	sched->pri_count[prio][id]++;
	odp_spinlock_unlock(&sched->mask_lock);
}

static void pri_clr(int id, int prio)
{
	odp_spinlock_lock(&sched->mask_lock);

	/* Clear mask bit when last queue is removed*/
	sched->pri_count[prio][id]--;

	if (sched->pri_count[prio][id] == 0)
		sched->pri_mask[prio] &= (uint8_t)(~(1 << id));

	odp_spinlock_unlock(&sched->mask_lock);
}

static void pri_set_queue(uint32_t queue_index, int prio)
{
	uint8_t id = prio_spread_index(queue_index);

	return pri_set(id, prio);
}

static void pri_clr_queue(uint32_t queue_index, int prio)
{
	uint8_t id = prio_spread_index(queue_index);
	pri_clr(id, prio);
}

static int schedule_init_queue(uint32_t queue_index,
			       const odp_schedule_param_t *sched_param)
{
	uint32_t ring_size;
	int i;
	int prio = sched_param->prio;

	pri_set_queue(queue_index, prio);
	sched->queue[queue_index].grp  = sched_param->group;
	sched->queue[queue_index].prio = prio;
	sched->queue[queue_index].spread = prio_spread_index(queue_index);
	sched->queue[queue_index].sync = sched_param->sync;
	sched->queue[queue_index].order_lock_count = sched_param->lock_count;
	sched->queue[queue_index].poll_pktin  = 0;
	sched->queue[queue_index].pktio_index = 0;
	sched->queue[queue_index].pktin_index = 0;

	ring_size = MAX_RING_SIZE / sched->config.num_spread;
	ring_size = ROUNDUP_POWER2_U32(ring_size);
	ODP_ASSERT(ring_size <= MAX_RING_SIZE);
	sched->ring_mask = ring_size - 1;

	odp_atomic_init_u64(&sched->order[queue_index].ctx, 0);
	odp_atomic_init_u64(&sched->order[queue_index].next_ctx, 0);

	for (i = 0; i < CONFIG_QUEUE_MAX_ORD_LOCKS; i++)
		odp_atomic_init_u64(&sched->order[queue_index].lock[i], 0);

	return 0;
}

static inline int queue_is_atomic(uint32_t queue_index)
{
	return sched->queue[queue_index].sync == ODP_SCHED_SYNC_ATOMIC;
}

static inline int queue_is_ordered(uint32_t queue_index)
{
	return sched->queue[queue_index].sync == ODP_SCHED_SYNC_ORDERED;
}

static void schedule_destroy_queue(uint32_t queue_index)
{
	int prio = sched->queue[queue_index].prio;

	pri_clr_queue(queue_index, prio);
	sched->queue[queue_index].grp    = 0;
	sched->queue[queue_index].prio   = 0;
	sched->queue[queue_index].spread = 0;

	if (queue_is_ordered(queue_index) &&
	    odp_atomic_load_u64(&sched->order[queue_index].ctx) !=
	    odp_atomic_load_u64(&sched->order[queue_index].next_ctx))
		ODP_ERR("queue reorder incomplete\n");
}

static int schedule_sched_queue(uint32_t queue_index)
{
	int grp      = sched->queue[queue_index].grp;
	int prio     = sched->queue[queue_index].prio;
	int spread   = sched->queue[queue_index].spread;
	ring_t *ring = &sched->prio_q[grp][prio][spread].ring;

	ring_enq(ring, sched->ring_mask, queue_index);
	return 0;
}

static void schedule_pktio_start(int pktio_index, int num_pktin,
				 int pktin_idx[], odp_queue_t queue[])
{
	int i;
	uint32_t qi;

	sched->pktio[pktio_index].num_pktin = num_pktin;

	for (i = 0; i < num_pktin; i++) {
		qi = queue_to_index(queue[i]);
		sched->queue[qi].poll_pktin  = 1;
		sched->queue[qi].pktio_index = pktio_index;
		sched->queue[qi].pktin_index = pktin_idx[i];

		ODP_ASSERT(pktin_idx[i] <= MAX_PKTIN_INDEX);

		/* Start polling */
		sched_cb_queue_set_status(qi, QUEUE_STATUS_SCHED);
		schedule_sched_queue(qi);
	}
}

static void schedule_release_atomic(void)
{
	uint32_t qi = sched_local.stash_qi;

	if (qi != PRIO_QUEUE_EMPTY && sched_local.stash_num  == 0) {
		int grp      = sched->queue[qi].grp;
		int prio     = sched->queue[qi].prio;
		int spread   = sched->queue[qi].spread;
		ring_t *ring = &sched->prio_q[grp][prio][spread].ring;

		/* Release current atomic queue */
		ring_enq(ring, sched->ring_mask, qi);

		sched_local.stash_qi = PRIO_QUEUE_EMPTY;
	}
}

static inline int ordered_own_turn(uint32_t queue_index)
{
	uint64_t ctx;

	ctx = odp_atomic_load_acq_u64(&sched->order[queue_index].ctx);

	return ctx == sched_local.ordered.ctx;
}

static inline void wait_for_order(uint32_t queue_index)
{
	/* Busy loop to synchronize ordered processing */
	while (1) {
		if (ordered_own_turn(queue_index))
			break;
		odp_cpu_pause();
	}
}

/**
 * Perform stashed enqueue operations
 *
 * Should be called only when already in order.
 */
static inline void ordered_stash_release(void)
{
	int i;

	for (i = 0; i < sched_local.ordered.stash_num; i++) {
		queue_entry_t *queue_entry;
		odp_buffer_hdr_t **buf_hdr;
		int num, num_enq;

		queue_entry = sched_local.ordered.stash[i].queue_entry;
		buf_hdr = sched_local.ordered.stash[i].buf_hdr;
		num = sched_local.ordered.stash[i].num;

		num_enq = queue_fn->enq_multi(qentry_to_int(queue_entry),
					      buf_hdr, num);

		/* Drop packets that were not enqueued */
		if (odp_unlikely(num_enq < num)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			ODP_DBG("Dropped %i packets\n", num - num_enq);
			buffer_free_multi(&buf_hdr[num_enq], num - num_enq);
		}
	}
	sched_local.ordered.stash_num = 0;
}

static inline void release_ordered(void)
{
	uint32_t qi;
	uint32_t i;

	qi = sched_local.ordered.src_queue;

	wait_for_order(qi);

	/* Release all ordered locks */
	for (i = 0; i < sched->queue[qi].order_lock_count; i++) {
		if (!sched_local.ordered.lock_called.u8[i])
			odp_atomic_store_rel_u64(&sched->order[qi].lock[i],
						 sched_local.ordered.ctx + 1);
	}

	sched_local.ordered.lock_called.all = 0;
	sched_local.ordered.src_queue = NULL_INDEX;
	sched_local.ordered.in_order = 0;

	ordered_stash_release();

	/* Next thread can continue processing */
	odp_atomic_add_rel_u64(&sched->order[qi].ctx, 1);
}

static void schedule_release_ordered(void)
{
	uint32_t queue_index;

	queue_index = sched_local.ordered.src_queue;

	if (odp_unlikely((queue_index == NULL_INDEX) || sched_local.stash_num))
		return;

	release_ordered();
}

static inline void schedule_release_context(void)
{
	if (sched_local.ordered.src_queue != NULL_INDEX)
		release_ordered();
	else
		schedule_release_atomic();
}

static inline int copy_from_stash(odp_event_t out_ev[], unsigned int max)
{
	int i = 0;

	while (sched_local.stash_num && max) {
		out_ev[i] = sched_local.stash_ev[sched_local.stash_index];
		sched_local.stash_index++;
		sched_local.stash_num--;
		max--;
		i++;
	}

	return i;
}

static int schedule_ord_enq_multi(queue_t q_int, void *buf_hdr[],
				  int num, int *ret)
{
	int i;
	uint32_t stash_num = sched_local.ordered.stash_num;
	queue_entry_t *dst_queue = qentry_from_int(q_int);
	uint32_t src_queue = sched_local.ordered.src_queue;

	if ((src_queue == NULL_INDEX) || sched_local.ordered.in_order)
		return 0;

	if (ordered_own_turn(src_queue)) {
		/* Own turn, so can do enqueue directly. */
		sched_local.ordered.in_order = 1;
		ordered_stash_release();
		return 0;
	}

	/* Pktout may drop packets, so the operation cannot be stashed. */
	if (dst_queue->s.pktout.pktio != ODP_PKTIO_INVALID ||
	    odp_unlikely(stash_num >=  MAX_ORDERED_STASH)) {
		/* If the local stash is full, wait until it is our turn and
		 * then release the stash and do enqueue directly. */
		wait_for_order(src_queue);

		sched_local.ordered.in_order = 1;

		ordered_stash_release();
		return 0;
	}

	sched_local.ordered.stash[stash_num].queue_entry = dst_queue;
	sched_local.ordered.stash[stash_num].num = num;
	for (i = 0; i < num; i++)
		sched_local.ordered.stash[stash_num].buf_hdr[i] = buf_hdr[i];

	sched_local.ordered.stash_num++;

	*ret = num;
	return 1;
}

static inline int queue_is_pktin(uint32_t queue_index)
{
	return sched->queue[queue_index].poll_pktin;
}

static inline int poll_pktin(uint32_t qi, int stash)
{
	odp_buffer_hdr_t *b_hdr[MAX_DEQ];
	int pktio_index, pktin_index, num, num_pktin, i;
	int ret;
	queue_t qint;

	pktio_index = sched->queue[qi].pktio_index;
	pktin_index = sched->queue[qi].pktin_index;

	num = sched_cb_pktin_poll(pktio_index, pktin_index, b_hdr, MAX_DEQ);

	if (num == 0)
		return 0;

	/* Pktio stopped or closed. Call stop_finalize when we have stopped
	 * polling all pktin queues of the pktio. */
	if (odp_unlikely(num < 0)) {
		odp_spinlock_lock(&sched->pktio_lock);
		sched->pktio[pktio_index].num_pktin--;
		num_pktin = sched->pktio[pktio_index].num_pktin;
		odp_spinlock_unlock(&sched->pktio_lock);

		sched_cb_queue_set_status(qi, QUEUE_STATUS_NOTSCHED);

		if (num_pktin == 0)
			sched_cb_pktio_stop_finalize(pktio_index);

		return num;
	}

	if (stash) {
		for (i = 0; i < num; i++)
			sched_local.stash_ev[i] = event_from_buf_hdr(b_hdr[i]);

		return num;
	}

	qint = queue_index_to_qint(qi);

	ret = queue_fn->enq_multi(qint, b_hdr, num);

	/* Drop packets that were not enqueued */
	if (odp_unlikely(ret < num)) {
		int num_enq = ret;

		if (odp_unlikely(ret < 0))
			num_enq = 0;

		ODP_DBG("Dropped %i packets\n", num - num_enq);
		buffer_free_multi(&b_hdr[num_enq], num - num_enq);
	}

	return ret;
}

static inline int do_schedule_grp(odp_queue_t *out_queue, odp_event_t out_ev[],
				  unsigned int max_num, int grp, int first)
{
	int prio, i;
	int ret;
	int id;
	uint32_t qi;
	unsigned int max_deq = MAX_DEQ;
	int num_spread = sched->config.num_spread;
	uint32_t ring_mask = sched->ring_mask;

	/* Schedule events */
	for (prio = 0; prio < NUM_PRIO; prio++) {

		if (sched->pri_mask[prio] == 0)
			continue;

		/* Select the first ring based on weights */
		id = first;

		for (i = 0; i < num_spread;) {
			int num;
			int ordered;
			odp_queue_t handle;
			ring_t *ring;
			int pktin;

			if (id >= num_spread)
				id = 0;

			/* No queues created for this priority queue */
			if (odp_unlikely((sched->pri_mask[prio] & (1 << id))
			    == 0)) {
				i++;
				id++;
				continue;
			}

			/* Get queue index from the priority queue */
			ring = &sched->prio_q[grp][prio][id].ring;
			qi   = ring_deq(ring, ring_mask);

			/* Priority queue empty */
			if (qi == RING_EMPTY) {
				i++;
				id++;
				continue;
			}

			/* Low priorities have smaller batch size to limit
			 * head of line blocking latency. */
			if (odp_unlikely(MAX_DEQ > 1 &&
					 prio > ODP_SCHED_PRIO_DEFAULT))
				max_deq = MAX_DEQ / 2;

			ordered = queue_is_ordered(qi);

			/* Do not cache ordered events locally to improve
			 * parallelism. Ordered context can only be released
			 * when the local cache is empty. */
			if (ordered && max_num < MAX_DEQ)
				max_deq = max_num;

			pktin = queue_is_pktin(qi);

			num = sched_cb_queue_deq_multi(qi, sched_local.stash_ev,
						       max_deq, !pktin);

			if (num < 0) {
				/* Destroyed queue. Continue scheduling the same
				 * priority queue. */
				sched_cb_queue_destroy_finalize(qi);
				continue;
			}

			if (num == 0) {
				/* Poll packet input. Continue scheduling queue
				 * connected to a packet input. Move to the next
				 * priority to avoid starvation of other
				 * priorities. Stop scheduling queue when pktio
				 * has been stopped. */
				if (pktin) {
					int stash = !ordered;
					int num_pkt = poll_pktin(qi, stash);

					if (odp_unlikely(num_pkt < 0))
						continue;

					if (num_pkt == 0 || !stash) {
						ring_enq(ring, ring_mask, qi);
						break;
					}

					/* Process packets from an atomic or
					 * parallel queue right away. */
					num = num_pkt;
				} else {
					/* Remove empty queue from scheduling.
					 * Continue scheduling the same priority
					 * queue. */
					continue;
				}
			}

			if (ordered) {
				uint64_t ctx;
				odp_atomic_u64_t *next_ctx;

				next_ctx = &sched->order[qi].next_ctx;
				ctx = odp_atomic_fetch_inc_u64(next_ctx);

				sched_local.ordered.ctx = ctx;
				sched_local.ordered.src_queue = qi;

				/* Continue scheduling ordered queues */
				ring_enq(ring, ring_mask, qi);

			} else if (queue_is_atomic(qi)) {
				/* Hold queue during atomic access */
				sched_local.stash_qi = qi;
			} else {
				/* Continue scheduling the queue */
				ring_enq(ring, ring_mask, qi);
			}

			handle = queue_from_index(qi);
			sched_local.stash_num   = num;
			sched_local.stash_index = 0;
			sched_local.stash_queue = handle;
			ret = copy_from_stash(out_ev, max_num);

			/* Output the source queue handle */
			if (out_queue)
				*out_queue = handle;

			return ret;
		}
	}

	return 0;
}

/*
 * Schedule queues
 */
static inline int do_schedule(odp_queue_t *out_queue, odp_event_t out_ev[],
			      unsigned int max_num)
{
	int i, num_grp;
	int ret;
	int first, grp_id;
	uint16_t spread_round, grp_round;
	uint32_t epoch;

	if (sched_local.stash_num) {
		ret = copy_from_stash(out_ev, max_num);

		if (out_queue)
			*out_queue = sched_local.stash_queue;

		return ret;
	}

	schedule_release_context();

	if (odp_unlikely(sched_local.pause))
		return 0;

	/* Each thread prefers a priority queue. Spread weight table avoids
	 * starvation of other priority queues on low thread counts. */
	spread_round = sched_local.spread_round;
	grp_round    = (sched_local.grp_round++) & (GRP_WEIGHT_TBL_SIZE - 1);

	if (odp_unlikely(spread_round + 1 >= sched->max_spread))
		sched_local.spread_round = 0;
	else
		sched_local.spread_round = spread_round + 1;

	first = sched_local.spread_tbl[spread_round];

	epoch = odp_atomic_load_acq_u32(&sched->grp_epoch);
	num_grp = sched_local.num_grp;

	if (odp_unlikely(sched_local.grp_epoch != epoch)) {
		num_grp = grp_update_tbl();
		sched_local.grp_epoch = epoch;
	}

	grp_id = sched_local.grp_weight[grp_round];

	/* Schedule queues per group and priority */
	for (i = 0; i < num_grp; i++) {
		int grp;

		grp = sched_local.grp[grp_id];
		ret = do_schedule_grp(out_queue, out_ev, max_num, grp, first);

		if (odp_likely(ret))
			return ret;

		grp_id++;
		if (odp_unlikely(grp_id >= num_grp))
			grp_id = 0;
	}

	return 0;
}

static inline int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
				odp_event_t out_ev[], unsigned int max_num)
{
	odp_time_t next, wtime;
	int first = 1;
	int ret;

	while (1) {
		timer_run();

		ret = do_schedule(out_queue, out_ev, max_num);

		if (ret)
			break;

		if (wait == ODP_SCHED_WAIT)
			continue;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (first) {
			wtime = odp_time_local_from_ns(wait);
			next = odp_time_sum(odp_time_local(), wtime);
			first = 0;
			continue;
		}

		if (odp_time_cmp(next, odp_time_local()) < 0)
			break;
	}

	return ret;
}

static odp_event_t schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_event_t ev;

	ev = ODP_EVENT_INVALID;

	schedule_loop(out_queue, wait, &ev, 1);

	return ev;
}

static int schedule_multi(odp_queue_t *out_queue, uint64_t wait,
			  odp_event_t events[], int num)
{
	return schedule_loop(out_queue, wait, events, num);
}

static inline void order_lock(void)
{
	uint32_t queue_index;

	queue_index = sched_local.ordered.src_queue;

	if (queue_index == NULL_INDEX)
		return;

	wait_for_order(queue_index);
}

static void order_unlock(void)
{
}

static void schedule_order_lock(uint32_t lock_index)
{
	odp_atomic_u64_t *ord_lock;
	uint32_t queue_index;

	queue_index = sched_local.ordered.src_queue;

	ODP_ASSERT(queue_index != NULL_INDEX &&
		   lock_index <= sched->queue[queue_index].order_lock_count &&
		   !sched_local.ordered.lock_called.u8[lock_index]);

	ord_lock = &sched->order[queue_index].lock[lock_index];

	/* Busy loop to synchronize ordered processing */
	while (1) {
		uint64_t lock_seq;

		lock_seq = odp_atomic_load_acq_u64(ord_lock);

		if (lock_seq == sched_local.ordered.ctx) {
			sched_local.ordered.lock_called.u8[lock_index] = 1;
			return;
		}
		odp_cpu_pause();
	}
}

static void schedule_order_unlock(uint32_t lock_index)
{
	odp_atomic_u64_t *ord_lock;
	uint32_t queue_index;

	queue_index = sched_local.ordered.src_queue;

	ODP_ASSERT(queue_index != NULL_INDEX &&
		   lock_index <= sched->queue[queue_index].order_lock_count);

	ord_lock = &sched->order[queue_index].lock[lock_index];

	ODP_ASSERT(sched_local.ordered.ctx == odp_atomic_load_u64(ord_lock));

	odp_atomic_store_rel_u64(ord_lock, sched_local.ordered.ctx + 1);
}

static void schedule_order_unlock_lock(uint32_t unlock_index,
				       uint32_t lock_index)
{
	schedule_order_unlock(unlock_index);
	schedule_order_lock(lock_index);
}

static void schedule_order_lock_start(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_lock_wait(uint32_t lock_index)
{
	schedule_order_lock(lock_index);
}

static void schedule_pause(void)
{
	sched_local.pause = 1;
}

static void schedule_resume(void)
{
	sched_local.pause = 0;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static int schedule_num_prio(void)
{
	return NUM_PRIO;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *mask)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_spinlock_lock(&sched->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (!sched->sched_grp[i].allocated) {
			char *grp_name = sched->sched_grp[i].name;

			if (name == NULL) {
				grp_name[0] = 0;
			} else {
				strncpy(grp_name, name,
					ODP_SCHED_GROUP_NAME_LEN - 1);
				grp_name[ODP_SCHED_GROUP_NAME_LEN - 1] = 0;
			}

			grp_update_mask(i, mask);
			group = (odp_schedule_group_t)i;
			sched->sched_grp[i].allocated = 1;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	odp_thrmask_t zero;
	int ret;

	odp_thrmask_zero(&zero);

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		grp_update_mask(group, &zero);
		memset(sched->sched_grp[group].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
		sched->sched_grp[group].allocated = 0;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_spinlock_lock(&sched->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (strcmp(name, sched->sched_grp[i].name) == 0) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return group;
}

static int schedule_group_join(odp_schedule_group_t group,
			       const odp_thrmask_t *mask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		odp_thrmask_t new_mask;

		odp_thrmask_or(&new_mask, &sched->sched_grp[group].mask, mask);
		grp_update_mask(group, &new_mask);

		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *mask)
{
	odp_thrmask_t new_mask;
	int ret;

	odp_thrmask_xor(&new_mask, mask, &sched->mask_all);

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		odp_thrmask_and(&new_mask, &sched->sched_grp[group].mask,
				&new_mask);
		grp_update_mask(group, &new_mask);

		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		*thrmask = sched->sched_grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		info->name    = sched->sched_grp[group].name;
		info->thrmask = sched->sched_grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_thr_add(odp_schedule_group_t group, int thr)
{
	odp_thrmask_t mask;
	odp_thrmask_t new_mask;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);

	odp_spinlock_lock(&sched->grp_lock);

	odp_thrmask_or(&new_mask, &sched->sched_grp[group].mask, &mask);
	grp_update_mask(group, &new_mask);

	odp_spinlock_unlock(&sched->grp_lock);

	return 0;
}

static int schedule_thr_rem(odp_schedule_group_t group, int thr)
{
	odp_thrmask_t mask;
	odp_thrmask_t new_mask;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);
	odp_thrmask_xor(&new_mask, &mask, &sched->mask_all);

	odp_spinlock_lock(&sched->grp_lock);

	odp_thrmask_and(&new_mask, &sched->sched_grp[group].mask, &new_mask);
	grp_update_mask(group, &new_mask);

	odp_spinlock_unlock(&sched->grp_lock);

	return 0;
}

/* This function is a no-op */
static void schedule_prefetch(int num ODP_UNUSED)
{
}

static int schedule_num_grps(void)
{
	return NUM_SCHED_GRPS;
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_basic_fn = {
	.status_sync = 0,
	.pktio_start = schedule_pktio_start,
	.thr_add = schedule_thr_add,
	.thr_rem = schedule_thr_rem,
	.num_grps = schedule_num_grps,
	.init_queue = schedule_init_queue,
	.destroy_queue = schedule_destroy_queue,
	.sched_queue = schedule_sched_queue,
	.ord_enq_multi = schedule_ord_enq_multi,
	.init_global = schedule_init_global,
	.term_global = schedule_term_global,
	.init_local  = schedule_init_local,
	.term_local  = schedule_term_local,
	.order_lock = order_lock,
	.order_unlock = order_unlock,
	.max_ordered_locks = schedule_max_ordered_locks,
	.unsched_queue = NULL,
	.save_context = NULL
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_basic_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_num_prio        = schedule_num_prio,
	.schedule_group_create    = schedule_group_create,
	.schedule_group_destroy   = schedule_group_destroy,
	.schedule_group_lookup    = schedule_group_lookup,
	.schedule_group_join      = schedule_group_join,
	.schedule_group_leave     = schedule_group_leave,
	.schedule_group_thrmask   = schedule_group_thrmask,
	.schedule_group_info      = schedule_group_info,
	.schedule_order_lock      = schedule_order_lock,
	.schedule_order_unlock    = schedule_order_unlock,
	.schedule_order_unlock_lock    = schedule_order_unlock_lock,
	.schedule_order_lock_start	= schedule_order_lock_start,
	.schedule_order_lock_wait      = schedule_order_lock_wait
};
