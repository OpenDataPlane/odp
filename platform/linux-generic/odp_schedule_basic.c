/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>
#include <odp/api/spinlock.h>
#include <odp/api/hints.h>
#include <odp/api/cpu.h>
#include <odp/api/thrmask.h>
#include <odp_config_internal.h>
#include <odp_align_internal.h>
#include <odp/api/sync.h>
#include <odp/api/packet_io.h>
#include <odp_ring_u32_internal.h>
#include <odp_timer_internal.h>
#include <odp_queue_basic_internal.h>
#include <odp_libconfig_internal.h>
#include <odp/api/plat/queue_inlines.h>

#include <string.h>

/* No synchronization context */
#define NO_SYNC_CONTEXT ODP_SCHED_SYNC_PARALLEL

/* Number of priority levels  */
#define NUM_PRIO 8

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
#define MAX_PREFER_WEIGHT 127
#define MIN_PREFER_WEIGHT 1
#define MAX_PREFER_RATIO  (MAX_PREFER_WEIGHT + 1)

/* Spread weight table */
#define SPREAD_TBL_SIZE ((MAX_SPREAD - 1) * MAX_PREFER_RATIO)

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO ODP_CONFIG_PKTIO_ENTRIES

/* Maximum pktin index. Needs to fit into 8 bits. */
#define MAX_PKTIN_INDEX 255

/* Maximum priority queue ring size. A ring must be large enough to store all
 * queues in the worst case (all queues are scheduled, have the same priority
 * and no spreading). */
#define MAX_RING_SIZE CONFIG_MAX_SCHED_QUEUES

/* For best performance, the number of queues should be a power of two. */
ODP_STATIC_ASSERT(CHECK_IS_POWER2(CONFIG_MAX_SCHED_QUEUES),
		  "Number_of_queues_is_not_power_of_two");

/* Ring size must be power of two, so that mask can be used. */
ODP_STATIC_ASSERT(CHECK_IS_POWER2(MAX_RING_SIZE),
		  "Ring_size_is_not_power_of_two");

/* Thread ID is saved into uint16_t variable */
ODP_STATIC_ASSERT(ODP_THREAD_COUNT_MAX < (64 * 1024),
		  "Max_64k_threads_supported");

/* Mask of queues per priority */
typedef uint8_t prio_q_mask_t;

ODP_STATIC_ASSERT((8 * sizeof(prio_q_mask_t)) >= MAX_SPREAD,
		  "prio_q_mask_t_is_too_small");

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Limits for burst size configuration */
#define BURST_MAX  255
#define STASH_SIZE CONFIG_BURST_SIZE

/* Ordered stash size */
#define MAX_ORDERED_STASH 512

/* Storage for stashed enqueue operation arguments */
typedef struct {
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	odp_queue_t queue;
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
typedef struct ODP_ALIGNED_CACHE {
	uint16_t thr;
	uint8_t  pause;
	uint8_t  sync_ctx;
	uint16_t grp_round;
	uint16_t spread_round;

	struct {
		uint16_t    num_ev;
		uint16_t    ev_index;
		uint32_t    qi;
		odp_queue_t queue;
		ring_u32_t   *ring;
		odp_event_t ev[STASH_SIZE];
	} stash;

	uint32_t grp_epoch;
	uint16_t num_grp;
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
	ring_u32_t ring;

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
	struct {
		uint8_t burst_default[NUM_PRIO];
		uint8_t burst_max[NUM_PRIO];
		uint8_t num_spread;
		uint8_t prefer_ratio;
	} config;

	uint16_t         max_spread;
	uint32_t         ring_mask;
	prio_q_mask_t    prio_q_mask[NUM_PRIO];
	odp_spinlock_t   mask_lock;
	odp_atomic_u32_t grp_epoch;
	odp_shm_t        shm;

	struct {
		uint8_t grp;
		/* Inverted prio value (max = 0) vs API (min = 0)*/
		uint8_t prio;
		uint8_t spread;
		uint8_t sync;
		uint8_t order_lock_count;
		uint8_t poll_pktin;
		uint8_t pktio_index;
		uint8_t pktin_index;
	} queue[CONFIG_MAX_SCHED_QUEUES];

	/* Scheduler priority queues */
	prio_queue_t prio_q[NUM_SCHED_GRPS][NUM_PRIO][MAX_SPREAD];

	uint32_t prio_q_count[NUM_PRIO][MAX_SPREAD];

	odp_thrmask_t  mask_all;
	odp_spinlock_t grp_lock;

	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
		int	       allocated;
	} sched_grp[NUM_SCHED_GRPS];

	struct {
		int num_pktin;
	} pktio[NUM_PKTIO];
	odp_spinlock_t pktio_lock;

	order_context_t order[CONFIG_MAX_SCHED_QUEUES];

	/* Scheduler interface config options (not used in fast path) */
	schedule_config_t config_if;

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

static int read_config_file(sched_global_t *sched)
{
	const char *str;
	int i;
	int burst_val[NUM_PRIO];
	int val = 0;

	ODP_PRINT("Scheduler config:\n");

	str = "sched_basic.prio_spread";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_SPREAD || val < MIN_SPREAD) {
		ODP_ERR("Bad value %s = %u [min: %u, max: %u]\n", str, val,
			MIN_SPREAD, MAX_SPREAD);
		return -1;
	}

	sched->config.num_spread = val;
	ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.prio_spread_weight";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val > MAX_PREFER_WEIGHT || val < MIN_PREFER_WEIGHT) {
		ODP_ERR("Bad value %s = %u [min: %u, max: %u]\n", str, val,
			MIN_PREFER_WEIGHT, MAX_PREFER_WEIGHT);
		return -1;
	}

	sched->config.prefer_ratio = val + 1;
	ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.burst_size_default";
	if (_odp_libconfig_lookup_array(str, burst_val, NUM_PRIO) !=
	    NUM_PRIO) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	ODP_PRINT("  %s[] =", str);
	for (i = 0; i < NUM_PRIO; i++) {
		val = burst_val[i];
		sched->config.burst_default[i] = val;
		ODP_PRINT(" %3i", val);

		if (val > STASH_SIZE || val < 1) {
			ODP_ERR("Bad value %i\n", val);
			return -1;
		}
	}
	ODP_PRINT("\n");

	str = "sched_basic.burst_size_max";
	if (_odp_libconfig_lookup_array(str, burst_val, NUM_PRIO) !=
	    NUM_PRIO) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	ODP_PRINT("  %s[] =    ", str);
	for (i = 0; i < NUM_PRIO; i++) {
		val = burst_val[i];
		sched->config.burst_max[i] = val;
		ODP_PRINT(" %3i", val);

		if (val > BURST_MAX || val < 1) {
			ODP_ERR("Bad value %i\n", val);
			return -1;
		}
	}

	ODP_PRINT("\n");

	str = "sched_basic.group_enable.all";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->config_if.group_enable.all = val;
	ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.group_enable.worker";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->config_if.group_enable.worker = val;
	ODP_PRINT("  %s: %i\n", str, val);

	str = "sched_basic.group_enable.control";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	sched->config_if.group_enable.control = val;
	ODP_PRINT("  %s: %i\n", str, val);

	ODP_PRINT("\n");

	return 0;
}

static inline uint8_t spread_index(uint32_t index)
{
	/* thread/queue index to spread index */
	return index % sched->config.num_spread;
}

static void sched_local_init(void)
{
	int i;
	uint8_t spread, prefer_ratio;
	uint8_t num_spread = sched->config.num_spread;
	uint8_t offset = 1;

	memset(&sched_local, 0, sizeof(sched_local_t));

	sched_local.thr         = odp_thread_id();
	sched_local.sync_ctx    = NO_SYNC_CONTEXT;
	sched_local.stash.queue = ODP_QUEUE_INVALID;

	spread = spread_index(sched_local.thr);
	prefer_ratio = sched->config.prefer_ratio;

	for (i = 0; i < SPREAD_TBL_SIZE; i++) {
		sched_local.spread_tbl[i] = spread;

		if (num_spread > 1 && (i % prefer_ratio) == 0) {
			sched_local.spread_tbl[i] = spread_index(spread +
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
	int prefer_ratio;

	ODP_DBG("Schedule init ... ");

	shm = odp_shm_reserve("_odp_scheduler",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE,
			      0);
	if (shm == ODP_SHM_INVALID) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	sched = odp_shm_addr(shm);
	memset(sched, 0, sizeof(sched_global_t));

	if (read_config_file(sched)) {
		odp_shm_free(shm);
		return -1;
	}

	prefer_ratio = sched->config.prefer_ratio;

	/* When num_spread == 1, only spread_tbl[0] is used. */
	sched->max_spread = (sched->config.num_spread - 1) * prefer_ratio;
	sched->shm  = shm;
	odp_spinlock_init(&sched->mask_lock);

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		for (i = 0; i < NUM_PRIO; i++) {
			for (j = 0; j < MAX_SPREAD; j++) {
				prio_queue_t *prio_q;

				prio_q = &sched->prio_q[grp][i][j];
				ring_u32_init(&prio_q->ring);
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

static int schedule_term_global(void)
{
	int ret = 0;
	int rc = 0;
	int i, j, grp;
	uint32_t ring_mask = sched->ring_mask;

	for (grp = 0; grp < NUM_SCHED_GRPS; grp++) {
		for (i = 0; i < NUM_PRIO; i++) {
			for (j = 0; j < MAX_SPREAD; j++) {
				ring_u32_t *ring;
				uint32_t qi;

				ring = &sched->prio_q[grp][i][j].ring;

				while (ring_u32_deq(ring, ring_mask, &qi)) {
					odp_event_t events[1];
					int num;

					num = sched_queue_deq(qi, events, 1, 1);

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

static int schedule_min_prio(void)
{
	return 0;
}

static int schedule_max_prio(void)
{
	return NUM_PRIO - 1;
}

static int schedule_default_prio(void)
{
	return schedule_max_prio() / 2;
}

static int schedule_num_prio(void)
{
	return NUM_PRIO;
}

static inline int prio_level_from_api(int api_prio)
{
	return schedule_max_prio() - api_prio;
}

static int schedule_create_queue(uint32_t queue_index,
				 const odp_schedule_param_t *sched_param)
{
	uint32_t ring_size;
	int i;
	int prio = prio_level_from_api(sched_param->prio);
	uint8_t spread = spread_index(queue_index);

	if (_odp_schedule_configured == 0) {
		ODP_ERR("Scheduler has not been configured\n");
		return -1;
	}

	odp_spinlock_lock(&sched->mask_lock);

	/* update scheduler prio queue usage status */
	sched->prio_q_mask[prio] |= 1 << spread;
	sched->prio_q_count[prio][spread]++;

	odp_spinlock_unlock(&sched->mask_lock);

	sched->queue[queue_index].grp  = sched_param->group;
	sched->queue[queue_index].prio = prio;
	sched->queue[queue_index].spread = spread;
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

static inline uint8_t sched_sync_type(uint32_t queue_index)
{
	return sched->queue[queue_index].sync;
}

static void schedule_destroy_queue(uint32_t queue_index)
{
	int prio = sched->queue[queue_index].prio;
	uint8_t spread = spread_index(queue_index);

	odp_spinlock_lock(&sched->mask_lock);

	/* Clear mask bit when last queue is removed*/
	sched->prio_q_count[prio][spread]--;

	if (sched->prio_q_count[prio][spread] == 0)
		sched->prio_q_mask[prio] &= (uint8_t)(~(1 << spread));

	odp_spinlock_unlock(&sched->mask_lock);

	sched->queue[queue_index].grp    = 0;
	sched->queue[queue_index].prio   = 0;
	sched->queue[queue_index].spread = 0;

	if ((sched_sync_type(queue_index) == ODP_SCHED_SYNC_ORDERED) &&
	    odp_atomic_load_u64(&sched->order[queue_index].ctx) !=
	    odp_atomic_load_u64(&sched->order[queue_index].next_ctx))
		ODP_ERR("queue reorder incomplete\n");
}

static int schedule_sched_queue(uint32_t queue_index)
{
	int grp      = sched->queue[queue_index].grp;
	int prio     = sched->queue[queue_index].prio;
	int spread   = sched->queue[queue_index].spread;
	ring_u32_t *ring = &sched->prio_q[grp][prio][spread].ring;

	ring_u32_enq(ring, sched->ring_mask, queue_index);
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
		sched_queue_set_status(qi, QUEUE_STATUS_SCHED);
		schedule_sched_queue(qi);
	}
}

static inline void release_atomic(void)
{
	uint32_t qi  = sched_local.stash.qi;
	ring_u32_t *ring = sched_local.stash.ring;

	/* Release current atomic queue */
	ring_u32_enq(ring, sched->ring_mask, qi);

	/* We don't hold sync context anymore */
	sched_local.sync_ctx = NO_SYNC_CONTEXT;
}

static void schedule_release_atomic(void)
{
	if (sched_local.sync_ctx == ODP_SCHED_SYNC_ATOMIC &&
	    sched_local.stash.num_ev == 0)
		release_atomic();
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
		odp_queue_t queue;
		odp_buffer_hdr_t **buf_hdr;
		int num, num_enq;

		queue = sched_local.ordered.stash[i].queue;
		buf_hdr = sched_local.ordered.stash[i].buf_hdr;
		num = sched_local.ordered.stash[i].num;

		num_enq = odp_queue_enq_multi(queue,
					      (odp_event_t *)buf_hdr, num);

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
	sched_local.ordered.in_order = 0;

	/* We don't hold sync context anymore */
	sched_local.sync_ctx = NO_SYNC_CONTEXT;

	ordered_stash_release();

	/* Next thread can continue processing */
	odp_atomic_add_rel_u64(&sched->order[qi].ctx, 1);
}

static void schedule_release_ordered(void)
{
	if (odp_unlikely((sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED) ||
			 sched_local.stash.num_ev))
		return;

	release_ordered();
}

static int schedule_term_local(void)
{
	if (sched_local.stash.num_ev) {
		ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	if (sched_local.sync_ctx == ODP_SCHED_SYNC_ATOMIC)
		schedule_release_atomic();
	else if (sched_local.sync_ctx == ODP_SCHED_SYNC_ORDERED)
		schedule_release_ordered();

	return 0;
}

static void schedule_config_init(odp_schedule_config_t *config)
{
	config->num_queues = CONFIG_MAX_SCHED_QUEUES;
	config->queue_size = queue_glb->config.max_queue_size;
}

static int schedule_config(const odp_schedule_config_t *config)
{
	(void)config;

	return 0;
}

static inline int copy_from_stash(odp_event_t out_ev[], unsigned int max)
{
	int i = 0;

	while (sched_local.stash.num_ev && max) {
		out_ev[i] = sched_local.stash.ev[sched_local.stash.ev_index];
		sched_local.stash.ev_index++;
		sched_local.stash.num_ev--;
		max--;
		i++;
	}

	return i;
}

static int schedule_ord_enq_multi(odp_queue_t dst_queue, void *buf_hdr[],
				  int num, int *ret)
{
	int i;
	uint32_t stash_num;
	queue_entry_t *dst_qentry;
	uint32_t src_queue;

	/* This check is done for every queue enqueue operation, also for plain
	 * queues. Return fast when not holding a scheduling context. */
	if (odp_likely(sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED))
		return 0;

	if (sched_local.ordered.in_order)
		return 0;

	dst_qentry = qentry_from_handle(dst_queue);

	if (dst_qentry->s.param.order == ODP_QUEUE_ORDER_IGNORE)
		return 0;

	src_queue  = sched_local.ordered.src_queue;
	stash_num  = sched_local.ordered.stash_num;

	if (ordered_own_turn(src_queue)) {
		/* Own turn, so can do enqueue directly. */
		sched_local.ordered.in_order = 1;
		ordered_stash_release();
		return 0;
	}

	/* Pktout may drop packets, so the operation cannot be stashed. */
	if (dst_qentry->s.pktout.pktio != ODP_PKTIO_INVALID ||
	    odp_unlikely(stash_num >=  MAX_ORDERED_STASH)) {
		/* If the local stash is full, wait until it is our turn and
		 * then release the stash and do enqueue directly. */
		wait_for_order(src_queue);

		sched_local.ordered.in_order = 1;

		ordered_stash_release();
		return 0;
	}

	sched_local.ordered.stash[stash_num].queue = dst_queue;
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

static inline int poll_pktin(uint32_t qi, int direct_recv,
			     odp_event_t ev_tbl[], int max_num)
{
	int pktio_index, pktin_index, num, num_pktin;
	odp_buffer_hdr_t **hdr_tbl;
	int ret;
	void *q_int;
	odp_buffer_hdr_t *b_hdr[CONFIG_BURST_SIZE];

	hdr_tbl = (odp_buffer_hdr_t **)ev_tbl;

	if (!direct_recv) {
		hdr_tbl = b_hdr;

		/* Limit burst to max queue enqueue size */
		if (max_num > CONFIG_BURST_SIZE)
			max_num = CONFIG_BURST_SIZE;
	}

	pktio_index = sched->queue[qi].pktio_index;
	pktin_index = sched->queue[qi].pktin_index;

	num = sched_cb_pktin_poll(pktio_index, pktin_index, hdr_tbl, max_num);

	if (num == 0)
		return 0;

	/* Pktio stopped or closed. Call stop_finalize when we have stopped
	 * polling all pktin queues of the pktio. */
	if (odp_unlikely(num < 0)) {
		odp_spinlock_lock(&sched->pktio_lock);
		sched->pktio[pktio_index].num_pktin--;
		num_pktin = sched->pktio[pktio_index].num_pktin;
		odp_spinlock_unlock(&sched->pktio_lock);

		sched_queue_set_status(qi, QUEUE_STATUS_NOTSCHED);

		if (num_pktin == 0)
			sched_cb_pktio_stop_finalize(pktio_index);

		return num;
	}

	if (direct_recv)
		return num;

	q_int = qentry_from_index(qi);

	ret = odp_queue_enq_multi(q_int, (odp_event_t *)b_hdr, num);

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
	uint16_t burst_def;
	int num_spread = sched->config.num_spread;
	uint32_t ring_mask = sched->ring_mask;

	/* Schedule events */
	for (prio = 0; prio < NUM_PRIO; prio++) {

		if (sched->prio_q_mask[prio] == 0)
			continue;

		burst_def = sched->config.burst_default[prio];

		/* Select the first ring based on weights */
		id = first;

		for (i = 0; i < num_spread;) {
			int num;
			uint8_t sync_ctx, ordered;
			odp_queue_t handle;
			ring_u32_t *ring;
			int pktin;
			uint16_t max_deq = burst_def;
			int stashed = 1;
			odp_event_t *ev_tbl = sched_local.stash.ev;

			if (id >= num_spread)
				id = 0;

			/* No queues created for this priority queue */
			if (odp_unlikely((sched->prio_q_mask[prio] & (1 << id))
			    == 0)) {
				i++;
				id++;
				continue;
			}

			/* Get queue index from the priority queue */
			ring = &sched->prio_q[grp][prio][id].ring;

			if (ring_u32_deq(ring, ring_mask, &qi) == 0) {
				/* Priority queue empty */
				i++;
				id++;
				continue;
			}

			sync_ctx = sched_sync_type(qi);
			ordered  = (sync_ctx == ODP_SCHED_SYNC_ORDERED);

			/* When application's array is larger than default burst
			 * size, output all events directly there. Also, ordered
			 * queues are not stashed locally to improve
			 * parallelism. Ordered context can only be released
			 * when the local cache is empty. */
			if (max_num > burst_def || ordered) {
				uint16_t burst_max;

				burst_max = sched->config.burst_max[prio];
				stashed = 0;
				ev_tbl  = out_ev;
				max_deq = max_num;
				if (max_num > burst_max)
					max_deq = burst_max;
			}

			pktin = queue_is_pktin(qi);

			num = sched_queue_deq(qi, ev_tbl, max_deq, !pktin);

			if (odp_unlikely(num < 0)) {
				/* Destroyed queue. Continue scheduling the same
				 * priority queue. */
				continue;
			}

			if (num == 0) {
				/* Poll packet input. Continue scheduling queue
				 * connected to a packet input. Move to the next
				 * priority to avoid starvation of other
				 * priorities. Stop scheduling queue when pktio
				 * has been stopped. */
				if (pktin) {
					int direct_recv = !ordered;
					int num_pkt;

					num_pkt = poll_pktin(qi, direct_recv,
							     ev_tbl, max_deq);

					if (odp_unlikely(num_pkt < 0))
						continue;

					if (num_pkt == 0 || !direct_recv) {
						ring_u32_enq(ring, ring_mask,
							     qi);
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
				ring_u32_enq(ring, ring_mask, qi);
				sched_local.sync_ctx = sync_ctx;

			} else if (sync_ctx == ODP_SCHED_SYNC_ATOMIC) {
				/* Hold queue during atomic access */
				sched_local.stash.qi   = qi;
				sched_local.stash.ring = ring;
				sched_local.sync_ctx   = sync_ctx;
			} else {
				/* Continue scheduling the queue */
				ring_u32_enq(ring, ring_mask, qi);
			}

			handle = queue_from_index(qi);

			if (stashed) {
				sched_local.stash.num_ev   = num;
				sched_local.stash.ev_index = 0;
				sched_local.stash.queue    = handle;
				ret = copy_from_stash(out_ev, max_num);
			} else {
				sched_local.stash.num_ev = 0;
				ret = num;
			}

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

	if (sched_local.stash.num_ev) {
		ret = copy_from_stash(out_ev, max_num);

		if (out_queue)
			*out_queue = sched_local.stash.queue;

		return ret;
	}

	/* Release schedule context */
	if (sched_local.sync_ctx == ODP_SCHED_SYNC_ATOMIC)
		release_atomic();
	else if (sched_local.sync_ctx == ODP_SCHED_SYNC_ORDERED)
		release_ordered();

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

static inline int schedule_run(odp_queue_t *out_queue, odp_event_t out_ev[],
			       unsigned int max_num)
{
	timer_run(1);

	return do_schedule(out_queue, out_ev, max_num);
}

static inline int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
				odp_event_t out_ev[], unsigned int max_num)
{
	odp_time_t next, wtime;
	int first = 1;
	int ret;

	while (1) {

		ret = do_schedule(out_queue, out_ev, max_num);
		if (ret) {
			timer_run(2);
			break;
		}
		timer_run(1);

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

static int schedule_multi_no_wait(odp_queue_t *out_queue, odp_event_t events[],
				  int num)
{
	return schedule_run(out_queue, events, num);
}

static int schedule_multi_wait(odp_queue_t *out_queue, odp_event_t events[],
			       int num)
{
	int ret;

	do {
		ret = schedule_run(out_queue, events, num);
	} while (ret == 0);

	return ret;
}

static inline void order_lock(void)
{
	if (sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	wait_for_order(sched_local.ordered.src_queue);
}

static void order_unlock(void)
{
}

static void schedule_order_lock(uint32_t lock_index)
{
	odp_atomic_u64_t *ord_lock;
	uint32_t queue_index;

	if (sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	queue_index = sched_local.ordered.src_queue;

	ODP_ASSERT(lock_index <= sched->queue[queue_index].order_lock_count &&
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

	if (sched_local.sync_ctx != ODP_SCHED_SYNC_ORDERED)
		return;

	queue_index = sched_local.ordered.src_queue;

	ODP_ASSERT(lock_index <= sched->queue[queue_index].order_lock_count);

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

static void schedule_get_config(schedule_config_t *config)
{
	*config = *(&sched->config_if);
};

static int schedule_capability(odp_schedule_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_schedule_capability_t));

	capa->max_ordered_locks = schedule_max_ordered_locks();
	capa->max_groups = schedule_num_grps();
	capa->max_prios = schedule_num_prio();
	capa->max_queues = CONFIG_MAX_SCHED_QUEUES;
	capa->max_queue_size = queue_glb->config.max_queue_size;
	capa->max_flow_id = BUF_HDR_MAX_FLOW_ID;

	return 0;
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_basic_fn = {
	.pktio_start = schedule_pktio_start,
	.thr_add = schedule_thr_add,
	.thr_rem = schedule_thr_rem,
	.num_grps = schedule_num_grps,
	.create_queue = schedule_create_queue,
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
	.get_config = schedule_get_config
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_basic_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule_capability      = schedule_capability,
	.schedule_config_init     = schedule_config_init,
	.schedule_config          = schedule_config,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_multi_wait      = schedule_multi_wait,
	.schedule_multi_no_wait   = schedule_multi_no_wait,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_min_prio        = schedule_min_prio,
	.schedule_max_prio        = schedule_max_prio,
	.schedule_default_prio    = schedule_default_prio,
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
