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
#include <odp/api/atomic.h>
#include <odp_config_internal.h>
#include <odp_align_internal.h>
#include <odp_schedule_internal.h>
#include <odp_schedule_ordered_internal.h>
#include <odp/api/sync.h>

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

/* Ring empty, not a valid index. */
#define RING_EMPTY ((uint32_t)-1)

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

/* Scheduler ring
 *
 * Ring stores head and tail counters. Ring indexes are formed from these
 * counters with a mask (mask = ring_size - 1), which requires that ring size
 * must be a power of two. */
typedef struct {
	/* Writer head and tail */
	odp_atomic_u32_t w_head;
	odp_atomic_u32_t w_tail;
	uint8_t pad[ODP_CACHE_LINE_SIZE - (2 * sizeof(odp_atomic_u32_t))];

	/* Reader head and tail */
	odp_atomic_u32_t r_head;
	odp_atomic_u32_t r_tail;

	uint32_t data[0];
} sched_ring_t ODP_ALIGNED_CACHE;

/* Priority queue */
typedef struct {
	/* Ring header */
	sched_ring_t ring;

	/* Ring data: queue indexes */
	uint32_t queue_index[PRIO_QUEUE_RING_SIZE];

} prio_queue_t ODP_ALIGNED_CACHE;

/* Packet IO queue */
typedef struct {
	/* Ring header */
	sched_ring_t ring;

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

static void ring_init(sched_ring_t *ring)
{
	odp_atomic_init_u32(&ring->w_head, 0);
	odp_atomic_init_u32(&ring->w_tail, 0);
	odp_atomic_init_u32(&ring->r_head, 0);
	odp_atomic_init_u32(&ring->r_tail, 0);
}

/* Dequeue data from the ring head */
static inline uint32_t ring_deq(sched_ring_t *ring, uint32_t mask)
{
	uint32_t head, tail, new_head;
	uint32_t data;

	head = odp_atomic_load_u32(&ring->r_head);

	/* Move reader head. This thread owns data at the new head. */
	do {
		tail = odp_atomic_load_u32(&ring->w_tail);

		if (head == tail)
			return RING_EMPTY;

		new_head = head + 1;

	} while (odp_unlikely(odp_atomic_cas_acq_u32(&ring->r_head, &head,
			      new_head) == 0));

	/* Read queue index */
	data = ring->data[new_head & mask];

	/* Wait until other readers have updated the tail */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->r_tail) != head))
		odp_cpu_pause();

	/* Now update the reader tail */
	odp_atomic_store_rel_u32(&ring->r_tail, new_head);

	return data;
}

/* Enqueue data into the ring tail */
static inline void ring_enq(sched_ring_t *ring, uint32_t mask, uint32_t data)
{
	uint32_t old_head, new_head;

	/* Reserve a slot in the ring for writing */
	old_head = odp_atomic_fetch_inc_u32(&ring->w_head);
	new_head = old_head + 1;

	/* Ring is full. Wait for the last reader to finish. */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->r_tail) == new_head))
		odp_cpu_pause();

	/* Write data */
	ring->data[new_head & mask] = data;

	/* Wait until other writers have updated the tail */
	while (odp_unlikely(odp_atomic_load_acq_u32(&ring->w_tail) != old_head))
		odp_cpu_pause();

	/* Now update the writer tail */
	odp_atomic_store_rel_u32(&ring->w_tail, new_head);
}

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
			sched_ring_t *ring = &sched->prio_q[i][j].ring;
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

static inline void schedule_release_context(void)
{
	if (sched_local.origin_qe != NULL) {
		release_order(sched_local.origin_qe, sched_local.order,
			      sched_local.pool, sched_local.enq_called);
		sched_local.origin_qe = NULL;
	} else
		odp_schedule_release_atomic();
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
		sched_ring_t *ring = &sched->prio_q[prio][queue_per_prio].ring;

		/* Release current atomic queue */
		ring_enq(ring, PRIO_QUEUE_MASK, qi);
		sched_local.queue_index = PRIO_QUEUE_EMPTY;
	}
}

static void schedule_release_ordered(void)
{
	if (sched_local.origin_qe) {
		int rc = release_order(sched_local.origin_qe,
				       sched_local.order,
				       sched_local.pool,
				       sched_local.enq_called);
		if (rc == 0)
			sched_local.origin_qe = NULL;
	}
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
			sched_ring_t *ring;

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

			/* For ordered queues we want consecutive events to
			 * be dispatched to separate threads, so do not cache
			 * them locally.
			 */
			if (ordered)
				max_deq = 1;

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
				/* Continue scheduling ordered queues */
				ring_enq(ring, PRIO_QUEUE_MASK, qi);

				/* Cache order info about this event */
				cache_order_info(qi);
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
		sched_ring_t *ring;
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
		if (sched->sched_grp[i].name[0] == 0) {
			strncpy(sched->sched_grp[i].name, name,
				ODP_SCHED_GROUP_NAME_LEN - 1);
			odp_thrmask_copy(&sched->sched_grp[i].mask, mask);
			group = (odp_schedule_group_t)i;
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
	    sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_zero(&sched->sched_grp[group].mask);
		memset(sched->sched_grp[group].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
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
	    sched->sched_grp[group].name[0] != 0) {
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
	    sched->sched_grp[group].name[0] != 0) {
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
	    sched->sched_grp[group].name[0] != 0) {
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
	    sched->sched_grp[group].name[0] != 0) {
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
	sched_ring_t *ring = &sched->prio_q[prio][queue_per_prio].ring;

	sched_local.ignore_ordered_context = 1;

	ring_enq(ring, PRIO_QUEUE_MASK, queue_index);
	return 0;
}

static int schedule_num_grps(void)
{
	return NUM_SCHED_GRPS;
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
	.ord_enq = schedule_ordered_queue_enq,
	.ord_enq_multi = schedule_ordered_queue_enq_multi,
	.init_global = schedule_init_global,
	.term_global = schedule_term_global,
	.init_local  = schedule_init_local,
	.term_local  = schedule_term_local
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
