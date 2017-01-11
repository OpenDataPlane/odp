/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

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
#include <odp_ring_internal.h>
#include <odp_queue_internal.h>

/* Number of priority levels  */
#define NUM_PRIO 8

ODP_STATIC_ASSERT(ODP_SCHED_PRIO_LOWEST == (NUM_PRIO - 1),
		  "lowest_prio_does_not_match_with_num_prios");

ODP_STATIC_ASSERT((ODP_SCHED_PRIO_NORMAL > 0) &&
		  (ODP_SCHED_PRIO_NORMAL < (NUM_PRIO - 1)),
		  "normal_prio_is_not_between_highest_and_lowest");

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 256

/* Priority queues per priority */
#define QUEUES_PER_PRIO  4

/* Packet input poll cmd queues */
#define PKTIO_CMD_QUEUES  4

/* Mask for wrapping command queues */
#define PKTIO_CMD_QUEUE_MASK (PKTIO_CMD_QUEUES - 1)

/* Maximum number of packet input queues per command */
#define MAX_PKTIN 16

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO ODP_CONFIG_PKTIO_ENTRIES

/* Maximum number of pktio poll commands */
#define NUM_PKTIO_CMD (MAX_PKTIN * NUM_PKTIO)

/* Not a valid poll command */
#define PKTIO_CMD_INVALID ((uint32_t)-1)

/* Pktio command is free */
#define PKTIO_CMD_FREE    PKTIO_CMD_INVALID

/* Packet IO poll queue ring size. In worst case, all pktios have all pktins
 * enabled and one poll command is created per pktin queue. The ring size must
 * be larger than or equal to NUM_PKTIO_CMD / PKTIO_CMD_QUEUES, so that it can
 * hold all poll commands in the worst case. */
#define PKTIO_RING_SIZE (NUM_PKTIO_CMD / PKTIO_CMD_QUEUES)

/* Mask for wrapping around pktio poll command index */
#define PKTIO_RING_MASK (PKTIO_RING_SIZE - 1)

/* Priority queue ring size. In worst case, all event queues are scheduled
 * queues and have the same priority. The ring size must be larger than or
 * equal to ODP_CONFIG_QUEUES / QUEUES_PER_PRIO, so that it can hold all
 * queues in the worst case. */
#define PRIO_QUEUE_RING_SIZE  (ODP_CONFIG_QUEUES / QUEUES_PER_PRIO)

/* Mask for wrapping around priority queue index */
#define PRIO_QUEUE_MASK  (PRIO_QUEUE_RING_SIZE - 1)

/* Priority queue empty, not a valid queue index. */
#define PRIO_QUEUE_EMPTY ((uint32_t)-1)

/* For best performance, the number of queues should be a power of two. */
ODP_STATIC_ASSERT(ODP_VAL_IS_POWER_2(ODP_CONFIG_QUEUES),
		  "Number_of_queues_is_not_power_of_two");

/* Ring size must be power of two, so that MAX_QUEUE_IDX_MASK can be used. */
ODP_STATIC_ASSERT(ODP_VAL_IS_POWER_2(PRIO_QUEUE_RING_SIZE),
		  "Ring_size_is_not_power_of_two");

/* Ring size must be power of two, so that PKTIO_RING_MASK can be used. */
ODP_STATIC_ASSERT(ODP_VAL_IS_POWER_2(PKTIO_RING_SIZE),
		  "pktio_ring_size_is_not_power_of_two");

/* Number of commands queues must be power of two, so that PKTIO_CMD_QUEUE_MASK
 * can be used. */
ODP_STATIC_ASSERT(ODP_VAL_IS_POWER_2(PKTIO_CMD_QUEUES),
		  "pktio_cmd_queues_is_not_power_of_two");

/* Mask of queues per priority */
typedef uint8_t pri_mask_t;

ODP_STATIC_ASSERT((8 * sizeof(pri_mask_t)) >= QUEUES_PER_PRIO,
		  "pri_mask_t_is_too_small");

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Maximum number of dequeues */
#define MAX_DEQ CONFIG_BURST_SIZE

/* Maximum number of ordered locks per queue */
#define MAX_ORDERED_LOCKS_PER_QUEUE 2

ODP_STATIC_ASSERT(MAX_ORDERED_LOCKS_PER_QUEUE <= CONFIG_QUEUE_MAX_ORD_LOCKS,
		  "Too_many_ordered_locks");

/* Ordered stash size */
#define MAX_ORDERED_STASH 512

/* Storage for stashed enqueue operation arguments */
typedef struct {
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
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
	int num;
	int index;
	int pause;
	uint16_t round;
	uint16_t prefer_offset;
	uint16_t pktin_polls;
	uint32_t queue_index;
	odp_queue_t queue;
	odp_event_t ev_stash[MAX_DEQ];
	struct {
		queue_entry_t *src_queue; /**< Source queue entry */
		uint64_t ctx; /**< Ordered context id */
		int stash_num; /**< Number of stashed enqueue operations */
		uint8_t in_order; /**< Order status */
		lock_called_t lock_called; /**< States of ordered locks */
		/** Storage for stashed enqueue operations */
		ordered_stash_t stash[MAX_ORDERED_STASH];
	} ordered;

} sched_local_t;

/* Priority queue */
typedef struct {
	/* Ring header */
	ring_t ring;

	/* Ring data: queue indexes */
	uint32_t queue_index[PRIO_QUEUE_RING_SIZE];

} prio_queue_t ODP_ALIGNED_CACHE;

/* Packet IO queue */
typedef struct {
	/* Ring header */
	ring_t ring;

	/* Ring data: pktio poll command indexes */
	uint32_t cmd_index[PKTIO_RING_SIZE];

} pktio_queue_t ODP_ALIGNED_CACHE;

/* Packet IO poll command */
typedef struct {
	int pktio_index;
	int num_pktin;
	int pktin[MAX_PKTIN];
	uint32_t cmd_index;
} pktio_cmd_t;

typedef struct {
	pri_mask_t     pri_mask[NUM_PRIO];
	odp_spinlock_t mask_lock;

	prio_queue_t   prio_q[NUM_PRIO][QUEUES_PER_PRIO];

	odp_spinlock_t poll_cmd_lock;
	/* Number of commands in a command queue */
	uint16_t       num_pktio_cmd[PKTIO_CMD_QUEUES];

	/* Packet IO command queues */
	pktio_queue_t  pktio_q[PKTIO_CMD_QUEUES];

	/* Packet IO poll commands */
	pktio_cmd_t    pktio_cmd[NUM_PKTIO_CMD];

	odp_shm_t      shm;
	uint32_t       pri_count[NUM_PRIO][QUEUES_PER_PRIO];

	odp_spinlock_t grp_lock;
	odp_thrmask_t mask_all;
	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
		int	       allocated;
	} sched_grp[NUM_SCHED_GRPS];

	struct {
		int         prio;
		int         queue_per_prio;
	} queue[ODP_CONFIG_QUEUES];

	struct {
		/* Number of active commands for a pktio interface */
		int num_cmd;
	} pktio[NUM_PKTIO];

} sched_global_t;

/* Global scheduler context */
static sched_global_t *sched;

/* Thread local scheduler context */
__thread sched_local_t sched_local;

/* Function prototypes */
static inline void schedule_release_context(void);

static void sched_local_init(void)
{
	memset(&sched_local, 0, sizeof(sched_local_t));

	sched_local.thr       = odp_thread_id();
	sched_local.queue     = ODP_QUEUE_INVALID;
	sched_local.queue_index = PRIO_QUEUE_EMPTY;
}

static int schedule_init_global(void)
{
	odp_shm_t shm;
	int i, j;

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

	sched->shm  = shm;
	odp_spinlock_init(&sched->mask_lock);

	for (i = 0; i < NUM_PRIO; i++) {
		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			int k;

			ring_init(&sched->prio_q[i][j].ring);

			for (k = 0; k < PRIO_QUEUE_RING_SIZE; k++)
				sched->prio_q[i][j].queue_index[k] =
				PRIO_QUEUE_EMPTY;
		}
	}

	odp_spinlock_init(&sched->poll_cmd_lock);
	for (i = 0; i < PKTIO_CMD_QUEUES; i++) {
		ring_init(&sched->pktio_q[i].ring);

		for (j = 0; j < PKTIO_RING_SIZE; j++)
			sched->pktio_q[i].cmd_index[j] = PKTIO_CMD_INVALID;
	}

	for (i = 0; i < NUM_PKTIO_CMD; i++)
		sched->pktio_cmd[i].cmd_index = PKTIO_CMD_FREE;

	odp_spinlock_init(&sched->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&sched->sched_grp[i].mask);
	}

	odp_thrmask_setall(&sched->mask_all);

	ODP_DBG("done\n");

	return 0;
}

static int schedule_term_global(void)
{
	int ret = 0;
	int rc = 0;
	int i, j;

	for (i = 0; i < NUM_PRIO; i++) {
		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			ring_t *ring = &sched->prio_q[i][j].ring;
			uint32_t qi;

			while ((qi = ring_deq(ring, PRIO_QUEUE_MASK)) !=
			       RING_EMPTY) {
				odp_event_t events[1];
				int num;

				num = sched_cb_queue_deq_multi(qi, events, 1);

				if (num < 0)
					sched_cb_queue_destroy_finalize(qi);

				if (num > 0)
					ODP_ERR("Queue not empty\n");
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
	if (sched_local.num) {
		ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	schedule_release_context();
	return 0;
}

static unsigned schedule_max_ordered_locks(void)
{
	return MAX_ORDERED_LOCKS_PER_QUEUE;
}

static inline int queue_per_prio(uint32_t queue_index)
{
	return ((QUEUES_PER_PRIO - 1) & queue_index);
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
	int id = queue_per_prio(queue_index);

	return pri_set(id, prio);
}

static void pri_clr_queue(uint32_t queue_index, int prio)
{
	int id = queue_per_prio(queue_index);
	pri_clr(id, prio);
}

static int schedule_init_queue(uint32_t queue_index,
			       const odp_schedule_param_t *sched_param)
{
	int prio = sched_param->prio;

	pri_set_queue(queue_index, prio);
	sched->queue[queue_index].prio = prio;
	sched->queue[queue_index].queue_per_prio = queue_per_prio(queue_index);

	return 0;
}

static void schedule_destroy_queue(uint32_t queue_index)
{
	int prio = sched->queue[queue_index].prio;

	pri_clr_queue(queue_index, prio);
	sched->queue[queue_index].prio = 0;
	sched->queue[queue_index].queue_per_prio = 0;
}

static int poll_cmd_queue_idx(int pktio_index, int pktin_idx)
{
	return PKTIO_CMD_QUEUE_MASK & (pktio_index ^ pktin_idx);
}

static inline pktio_cmd_t *alloc_pktio_cmd(void)
{
	int i;
	pktio_cmd_t *cmd = NULL;

	odp_spinlock_lock(&sched->poll_cmd_lock);

	/* Find next free command */
	for (i = 0; i < NUM_PKTIO_CMD; i++) {
		if (sched->pktio_cmd[i].cmd_index == PKTIO_CMD_FREE) {
			cmd = &sched->pktio_cmd[i];
			cmd->cmd_index = i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->poll_cmd_lock);

	return cmd;
}

static inline void free_pktio_cmd(pktio_cmd_t *cmd)
{
	odp_spinlock_lock(&sched->poll_cmd_lock);

	cmd->cmd_index = PKTIO_CMD_FREE;

	odp_spinlock_unlock(&sched->poll_cmd_lock);
}

static void schedule_pktio_start(int pktio_index, int num_pktin,
				 int pktin_idx[])
{
	int i, idx;
	pktio_cmd_t *cmd;

	if (num_pktin > MAX_PKTIN)
		ODP_ABORT("Too many input queues for scheduler\n");

	sched->pktio[pktio_index].num_cmd = num_pktin;

	/* Create a pktio poll command per queue */
	for (i = 0; i < num_pktin; i++) {

		cmd = alloc_pktio_cmd();

		if (cmd == NULL)
			ODP_ABORT("Scheduler out of pktio commands\n");

		idx = poll_cmd_queue_idx(pktio_index, pktin_idx[i]);

		odp_spinlock_lock(&sched->poll_cmd_lock);
		sched->num_pktio_cmd[idx]++;
		odp_spinlock_unlock(&sched->poll_cmd_lock);

		cmd->pktio_index = pktio_index;
		cmd->num_pktin   = 1;
		cmd->pktin[0]    = pktin_idx[i];
		ring_enq(&sched->pktio_q[idx].ring, PKTIO_RING_MASK,
			 cmd->cmd_index);
	}
}

static int schedule_pktio_stop(int pktio_index, int first_pktin)
{
	int num;
	int idx = poll_cmd_queue_idx(pktio_index, first_pktin);

	odp_spinlock_lock(&sched->poll_cmd_lock);
	sched->num_pktio_cmd[idx]--;
	sched->pktio[pktio_index].num_cmd--;
	num = sched->pktio[pktio_index].num_cmd;
	odp_spinlock_unlock(&sched->poll_cmd_lock);

	return num;
}

static void schedule_release_atomic(void)
{
	uint32_t qi = sched_local.queue_index;

	if (qi != PRIO_QUEUE_EMPTY && sched_local.num  == 0) {
		int prio           = sched->queue[qi].prio;
		int queue_per_prio = sched->queue[qi].queue_per_prio;
		ring_t *ring       = &sched->prio_q[prio][queue_per_prio].ring;

		/* Release current atomic queue */
		ring_enq(ring, PRIO_QUEUE_MASK, qi);
		sched_local.queue_index = PRIO_QUEUE_EMPTY;
	}
}

static inline int ordered_own_turn(queue_entry_t *queue)
{
	uint64_t ctx;

	ctx = odp_atomic_load_acq_u64(&queue->s.ordered.ctx);

	return ctx == sched_local.ordered.ctx;
}

static inline void wait_for_order(queue_entry_t *queue)
{
	/* Busy loop to synchronize ordered processing */
	while (1) {
		if (ordered_own_turn(queue))
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
		queue_entry_t *queue;
		odp_buffer_hdr_t **buf_hdr;
		int num;

		queue = sched_local.ordered.stash[i].queue;
		buf_hdr = sched_local.ordered.stash[i].buf_hdr;
		num = sched_local.ordered.stash[i].num;

		queue_enq_multi(queue, buf_hdr, num);
	}
	sched_local.ordered.stash_num = 0;
}

static inline void release_ordered(void)
{
	unsigned i;
	queue_entry_t *queue;

	queue = sched_local.ordered.src_queue;

	wait_for_order(queue);

	/* Release all ordered locks */
	for (i = 0; i < queue->s.param.sched.lock_count; i++) {
		if (!sched_local.ordered.lock_called.u8[i])
			odp_atomic_store_rel_u64(&queue->s.ordered.lock[i],
						 sched_local.ordered.ctx + 1);
	}

	sched_local.ordered.lock_called.all = 0;
	sched_local.ordered.src_queue = NULL;
	sched_local.ordered.in_order = 0;

	ordered_stash_release();

	/* Next thread can continue processing */
	odp_atomic_add_rel_u64(&queue->s.ordered.ctx, 1);
}

static void schedule_release_ordered(void)
{
	queue_entry_t *queue;

	queue = sched_local.ordered.src_queue;

	if (odp_unlikely(!queue || sched_local.num))
		return;

	release_ordered();
}

static inline void schedule_release_context(void)
{
	if (sched_local.ordered.src_queue != NULL)
		release_ordered();
	else
		schedule_release_atomic();
}

static inline int copy_events(odp_event_t out_ev[], unsigned int max)
{
	int i = 0;

	while (sched_local.num && max) {
		out_ev[i] = sched_local.ev_stash[sched_local.index];
		sched_local.index++;
		sched_local.num--;
		max--;
		i++;
	}

	return i;
}

static int schedule_ord_enq_multi(uint32_t queue_index, void *buf_hdr[],
				  int num, int *ret)
{
	int i;
	uint32_t stash_num = sched_local.ordered.stash_num;
	queue_entry_t *dst_queue = get_qentry(queue_index);
	queue_entry_t *src_queue = sched_local.ordered.src_queue;

	if (!sched_local.ordered.src_queue || sched_local.ordered.in_order)
		return 0;

	if (ordered_own_turn(src_queue)) {
		/* Own turn, so can do enqueue directly. */
		sched_local.ordered.in_order = 1;
		ordered_stash_release();
		return 0;
	}

	if (odp_unlikely(stash_num >=  MAX_ORDERED_STASH)) {
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

/*
 * Schedule queues
 */
static int do_schedule(odp_queue_t *out_queue, odp_event_t out_ev[],
		       unsigned int max_num)
{
	int prio, i;
	int ret;
	int id;
	int offset = 0;
	unsigned int max_deq = MAX_DEQ;
	uint32_t qi;

	if (sched_local.num) {
		ret = copy_events(out_ev, max_num);

		if (out_queue)
			*out_queue = sched_local.queue;

		return ret;
	}

	schedule_release_context();

	if (odp_unlikely(sched_local.pause))
		return 0;

	/* Each thread prefers a priority queue. This offset avoids starvation
	 * of other priority queues on low thread counts. */
	if (odp_unlikely((sched_local.round & 0x3f) == 0)) {
		offset = sched_local.prefer_offset;
		sched_local.prefer_offset = (offset + 1) &
					    (QUEUES_PER_PRIO - 1);
	}

	sched_local.round++;

	/* Schedule events */
	for (prio = 0; prio < NUM_PRIO; prio++) {

		if (sched->pri_mask[prio] == 0)
			continue;

		id = (sched_local.thr + offset) & (QUEUES_PER_PRIO - 1);

		for (i = 0; i < QUEUES_PER_PRIO;) {
			int num;
			int grp;
			int ordered;
			odp_queue_t handle;
			ring_t *ring;

			if (id >= QUEUES_PER_PRIO)
				id = 0;

			/* No queues created for this priority queue */
			if (odp_unlikely((sched->pri_mask[prio] & (1 << id))
			    == 0)) {
				i++;
				id++;
				continue;
			}

			/* Get queue index from the priority queue */
			ring = &sched->prio_q[prio][id].ring;
			qi   = ring_deq(ring, PRIO_QUEUE_MASK);

			/* Priority queue empty */
			if (qi == RING_EMPTY) {
				i++;
				id++;
				continue;
			}

			grp = sched_cb_queue_grp(qi);

			if (grp > ODP_SCHED_GROUP_ALL &&
			    !odp_thrmask_isset(&sched->sched_grp[grp].mask,
					       sched_local.thr)) {
				/* This thread is not eligible for work from
				 * this queue, so continue scheduling it.
				 */
				ring_enq(ring, PRIO_QUEUE_MASK, qi);

				i++;
				id++;
				continue;
			}

			/* Low priorities have smaller batch size to limit
			 * head of line blocking latency. */
			if (odp_unlikely(prio > ODP_SCHED_PRIO_DEFAULT))
				max_deq = MAX_DEQ / 2;

			ordered = sched_cb_queue_is_ordered(qi);

			/* Do not cache ordered events locally to improve
			 * parallelism. Ordered context can only be released
			 * when the local cache is empty. */
			if (ordered && max_num < MAX_DEQ)
				max_deq = max_num;

			num = sched_cb_queue_deq_multi(qi, sched_local.ev_stash,
						       max_deq);

			if (num < 0) {
				/* Destroyed queue. Continue scheduling the same
				 * priority queue. */
				sched_cb_queue_destroy_finalize(qi);
				continue;
			}

			if (num == 0) {
				/* Remove empty queue from scheduling. Continue
				 * scheduling the same priority queue. */
				continue;
			}

			handle            = sched_cb_queue_handle(qi);
			sched_local.num   = num;
			sched_local.index = 0;
			sched_local.queue = handle;
			ret = copy_events(out_ev, max_num);

			if (ordered) {
				uint64_t ctx;
				queue_entry_t *queue;
				odp_atomic_u64_t *next_ctx;

				queue = get_qentry(qi);
				next_ctx = &queue->s.ordered.next_ctx;

				ctx = odp_atomic_fetch_inc_u64(next_ctx);

				sched_local.ordered.ctx = ctx;
				sched_local.ordered.src_queue = queue;

				/* Continue scheduling ordered queues */
				ring_enq(ring, PRIO_QUEUE_MASK, qi);

			} else if (sched_cb_queue_is_atomic(qi)) {
				/* Hold queue during atomic access */
				sched_local.queue_index = qi;
			} else {
				/* Continue scheduling the queue */
				ring_enq(ring, PRIO_QUEUE_MASK, qi);
			}

			/* Output the source queue handle */
			if (out_queue)
				*out_queue = handle;

			return ret;
		}
	}

	/*
	 * Poll packet input when there are no events
	 *   * Each thread starts the search for a poll command from its
	 *     preferred command queue. If the queue is empty, it moves to other
	 *     queues.
	 *   * Most of the times, the search stops on the first command found to
	 *     optimize multi-threaded performance. A small portion of polls
	 *     have to do full iteration to avoid packet input starvation when
	 *     there are less threads than command queues.
	 */
	id = sched_local.thr & PKTIO_CMD_QUEUE_MASK;

	for (i = 0; i < PKTIO_CMD_QUEUES; i++, id = ((id + 1) &
	     PKTIO_CMD_QUEUE_MASK)) {
		ring_t *ring;
		uint32_t cmd_index;
		pktio_cmd_t *cmd;

		if (odp_unlikely(sched->num_pktio_cmd[id] == 0))
			continue;

		ring      = &sched->pktio_q[id].ring;
		cmd_index = ring_deq(ring, PKTIO_RING_MASK);

		if (odp_unlikely(cmd_index == RING_EMPTY))
			continue;

		cmd = &sched->pktio_cmd[cmd_index];

		/* Poll packet input */
		if (odp_unlikely(sched_cb_pktin_poll(cmd->pktio_index,
						     cmd->num_pktin,
						     cmd->pktin))){
			/* Pktio stopped or closed. Remove poll command and call
			 * stop_finalize when all commands of the pktio has
			 * been removed. */
			if (schedule_pktio_stop(cmd->pktio_index,
						cmd->pktin[0]) == 0)
				sched_cb_pktio_stop_finalize(cmd->pktio_index);

			free_pktio_cmd(cmd);
		} else {
			/* Continue scheduling the pktio */
			ring_enq(ring, PKTIO_RING_MASK, cmd_index);

			/* Do not iterate through all pktin poll command queues
			 * every time. */
			if (odp_likely(sched_local.pktin_polls & 0xf))
				break;
		}
	}

	sched_local.pktin_polls++;
	return 0;
}


static int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
			 odp_event_t out_ev[],
			 unsigned int max_num)
{
	odp_time_t next, wtime;
	int first = 1;
	int ret;

	while (1) {
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
	queue_entry_t *queue;

	queue = sched_local.ordered.src_queue;

	if (!queue)
		return;

	wait_for_order(queue);
}

static void order_unlock(void)
{
}

static void schedule_order_lock(unsigned lock_index)
{
	odp_atomic_u64_t *ord_lock;
	queue_entry_t *queue;

	queue = sched_local.ordered.src_queue;

	ODP_ASSERT(queue && lock_index <= queue->s.param.sched.lock_count &&
		   !sched_local.ordered.lock_called.u8[lock_index]);

	ord_lock = &queue->s.ordered.lock[lock_index];

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

static void schedule_order_unlock(unsigned lock_index)
{
	odp_atomic_u64_t *ord_lock;
	queue_entry_t *queue;

	queue = sched_local.ordered.src_queue;

	ODP_ASSERT(queue && lock_index <= queue->s.param.sched.lock_count);

	ord_lock = &queue->s.ordered.lock[lock_index];

	ODP_ASSERT(sched_local.ordered.ctx == odp_atomic_load_u64(ord_lock));

	odp_atomic_store_rel_u64(ord_lock, sched_local.ordered.ctx + 1);
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
			odp_thrmask_copy(&sched->sched_grp[i].mask, mask);
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
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		odp_thrmask_zero(&sched->sched_grp[group].mask);
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
		odp_thrmask_or(&sched->sched_grp[group].mask,
			       &sched->sched_grp[group].mask,
			       mask);
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
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].allocated) {
		odp_thrmask_t leavemask;

		odp_thrmask_xor(&leavemask, mask, &sched->mask_all);
		odp_thrmask_and(&sched->sched_grp[group].mask,
				&sched->sched_grp[group].mask,
				&leavemask);
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
	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_spinlock_lock(&sched->grp_lock);

	odp_thrmask_set(&sched->sched_grp[group].mask, thr);

	odp_spinlock_unlock(&sched->grp_lock);

	return 0;
}

static int schedule_thr_rem(odp_schedule_group_t group, int thr)
{
	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_spinlock_lock(&sched->grp_lock);

	odp_thrmask_clr(&sched->sched_grp[group].mask, thr);

	odp_spinlock_unlock(&sched->grp_lock);

	return 0;
}

/* This function is a no-op */
static void schedule_prefetch(int num ODP_UNUSED)
{
}

static int schedule_sched_queue(uint32_t queue_index)
{
	int prio           = sched->queue[queue_index].prio;
	int queue_per_prio = sched->queue[queue_index].queue_per_prio;
	ring_t *ring       = &sched->prio_q[prio][queue_per_prio].ring;

	ring_enq(ring, PRIO_QUEUE_MASK, queue_index);
	return 0;
}

static int schedule_num_grps(void)
{
	return NUM_SCHED_GRPS;
}

static void schedule_save_context(queue_entry_t *queue ODP_UNUSED)
{
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_default_fn = {
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
	.save_context = schedule_save_context
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_default_api = {
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
	.schedule_order_unlock    = schedule_order_unlock
};
