/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp/api/align.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp_ring_internal.h>
#include <odp_queue_internal.h>
#include <odp_buffer_internal.h>
#include <odp_bitmap_internal.h>
#include <odp/api/thread.h>
#include <odp/api/time.h>
#include <odp/api/rwlock.h>
#include <odp/api/hints.h>
#include <odp/api/cpu.h>
#include <odp/api/thrmask.h>
#include <odp/api/packet_io.h>
#include <odp_config_internal.h>

/* Number of priority levels */
#define NUM_SCHED_PRIO 8

ODP_STATIC_ASSERT(ODP_SCHED_PRIO_LOWEST == (NUM_SCHED_PRIO - 1),
		  "lowest_prio_does_not_match_with_num_prios");

ODP_STATIC_ASSERT((ODP_SCHED_PRIO_NORMAL > 0) &&
		  (ODP_SCHED_PRIO_NORMAL < (NUM_SCHED_PRIO - 1)),
		  "normal_prio_is_not_between_highest_and_lowest");

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 256

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Instantiate a WAPL bitmap to be used as queue index bitmap */
typedef WAPL_BITMAP(ODP_CONFIG_QUEUES) queue_index_bitmap_t;

typedef struct {
	odp_rwlock_t lock;
	queue_index_bitmap_t queues; /* queues in this priority level */
} sched_prio_t;

typedef struct {
	odp_rwlock_t lock;
	bool allocated;
	odp_thrmask_t threads; /* threads subscribe to this group */
	queue_index_bitmap_t queues; /* queues in this group */
	char name[ODP_SCHED_GROUP_NAME_LEN];
} sched_group_t;

/* Packet input poll command queues */
#define PKTIO_CMD_QUEUES 4

/* Maximum number of packet input queues per command */
#define MAX_PKTIN 16

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO ODP_CONFIG_PKTIO_ENTRIES

/* Maximum number of pktio poll commands */
#define NUM_PKTIO_CMD (MAX_PKTIN * NUM_PKTIO)

/* Pktio command is free */
#define PKTIO_CMD_FREE ((uint32_t)-1)

/* Packet IO poll queue ring size. In worst case, all pktios
 * have all pktins enabled and one poll command is created per
 * pktin queue. The ring size must be larger than or equal to
 * NUM_PKTIO_CMD / PKTIO_CMD_QUEUES, so that it can hold all
 * poll commands in the worst case.
 */
#define PKTIO_RING_SIZE (NUM_PKTIO_CMD / PKTIO_CMD_QUEUES)

/* Mask for wrapping around pktio poll command index */
#define PKTIO_RING_MASK (PKTIO_RING_SIZE - 1)

/* Maximum number of dequeues */
#define MAX_DEQ CONFIG_BURST_SIZE

/* Instantiate a RING data structure as pktio command queue */
typedef struct {
	/* Ring header */
	ring_t ring;

	/* Ring data: pktio poll command indexes */
	uint32_t cmd_index[PKTIO_RING_SIZE];
} pktio_cmd_queue_t ODP_ALIGNED_CACHE;

/* Packet IO poll command */
typedef struct {
	int pktio;
	int count;
	int pktin[MAX_PKTIN];
	uint32_t index;
} pktio_cmd_t;

/* Collect the pktio poll resources */
typedef struct {
	odp_rwlock_t lock;
	/* count active commands per pktio interface */
	int actives[NUM_PKTIO];
	pktio_cmd_t commands[NUM_PKTIO_CMD];
	pktio_cmd_queue_t queues[PKTIO_CMD_QUEUES];
} pktio_poll_t;

/* Forward declaration */
typedef struct sched_thread_local sched_thread_local_t;

typedef struct {
	odp_shm_t selfie;

	/* Schedule priorities */
	sched_prio_t prios[NUM_SCHED_PRIO];

	/* Schedule groups */
	sched_group_t groups[NUM_SCHED_GRPS];

	/* Cache queue parameters for easy reference */
	odp_schedule_param_t queues[ODP_CONFIG_QUEUES];

	/* Poll pktio inputs in spare time */
	pktio_poll_t pktio_poll;

	/* Queues send or unwind their availability indications
	 * for scheduling, the bool value also serves as a focal
	 * point for atomic competition. */
	bool availables[ODP_CONFIG_QUEUES];

	/* Quick reference to per thread context */
	sched_thread_local_t *threads[ODP_THREAD_COUNT_MAX];
} sched_global_t;

/* Per thread events cache */
typedef struct {
	int count;
	odp_queue_t queue;
	odp_event_t stash[MAX_DEQ], *top;
} event_cache_t;

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

/* Instantiate a sparse bitmap to store thread's interested
 * queue indexes per priority.
 */
typedef SPARSE_BITMAP(ODP_CONFIG_QUEUES) queue_index_sparse_t;

struct sched_thread_local {
	int thread;
	bool pause;

	/* Cache events only for atomic queue */
	event_cache_t cache;

	/* Saved atomic context */
	bool *atomic;

	/* Record the pktio polls have done */
	uint16_t pktin_polls;

	/* Interested queue indexes to be checked by thread
	 * at each priority level for scheduling, and a round
	 * robin iterator to improve fairness between queues
	 * in the same priority level.
	 */
	odp_rwlock_t lock;
	queue_index_sparse_t indexes[NUM_SCHED_PRIO];
	sparse_bitmap_iterator_t iterators[NUM_SCHED_PRIO];

	struct {
		queue_entry_t *src_queue; /**< Source queue entry */
		uint64_t ctx; /**< Ordered context id */
		int stash_num; /**< Number of stashed enqueue operations */
		uint8_t in_order; /**< Order status */
		lock_called_t lock_called; /**< States of ordered locks */
		/** Storage for stashed enqueue operations */
		ordered_stash_t stash[MAX_ORDERED_STASH];
	} ordered;
};

/* Global scheduler context */
static sched_global_t *sched;

/* Thread local scheduler context */
__thread sched_thread_local_t thread_local;

static int schedule_init_global(void)
{
	odp_shm_t shm;
	int i, k, prio, group;

	ODP_DBG("Schedule[iquery] init ... ");

	shm = odp_shm_reserve("odp_scheduler_iquery",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	sched = odp_shm_addr(shm);

	if (sched == NULL) {
		ODP_ERR("Schedule[iquery] "
			"init: shm reserve.\n");
		return -1;
	}

	memset(sched, 0, sizeof(sched_global_t));

	sched->selfie = shm;

	for (prio = 0; prio < NUM_SCHED_PRIO; prio++)
		odp_rwlock_init(&sched->prios[prio].lock);

	for (group = 0; group < NUM_SCHED_GRPS; group++) {
		sched->groups[group].allocated = false;
		odp_rwlock_init(&sched->groups[group].lock);
	}

	odp_rwlock_init(&sched->pktio_poll.lock);

	for (i = 0; i < PKTIO_CMD_QUEUES; i++) {
		pktio_cmd_queue_t *queue =
			&sched->pktio_poll.queues[i];

		ring_init(&queue->ring);

		for (k = 0; k < PKTIO_RING_SIZE; k++)
			queue->cmd_index[k] = RING_EMPTY;
	}

	for (i = 0; i < NUM_PKTIO_CMD; i++)
		sched->pktio_poll.commands[i].index = PKTIO_CMD_FREE;

	ODP_DBG("done\n");
	return 0;
}

static int schedule_term_global(void)
{
	uint32_t i;
	odp_shm_t shm = sched->selfie;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		int count = 0;
		odp_event_t events[1];

		if (sched->availables[i])
			count = sched_cb_queue_deq_multi(i, events, 1);

		if (count < 0)
			sched_cb_queue_destroy_finalize(i);
		else if (count > 0)
			ODP_ERR("Queue (%d) not empty\n", i);
	}

	memset(sched, 0, sizeof(sched_global_t));

	if (odp_shm_free(shm) < 0) {
		ODP_ERR("Schedule[iquery] "
			"term: shm release.\n");
		return -1;
	}
	return 0;
}

/*
 * These APIs are used to manipulate thread's interests.
 */
static void thread_set_interest(sched_thread_local_t *thread,
				unsigned int queue_index, int prio);

static void thread_clear_interest(sched_thread_local_t *thread,
				  unsigned int queue_index, int prio);

static void thread_set_interests(sched_thread_local_t *thread,
				 queue_index_bitmap_t *set);

static void thread_clear_interests(sched_thread_local_t *thread,
				   queue_index_bitmap_t *clear);

static void sched_thread_local_reset(void)
{
	int prio;
	queue_index_sparse_t *index;
	sparse_bitmap_iterator_t *iterator;

	memset(&thread_local, 0, sizeof(sched_thread_local_t));

	thread_local.thread = odp_thread_id();
	thread_local.cache.queue = ODP_QUEUE_INVALID;

	odp_rwlock_init(&thread_local.lock);

	for (prio = 0; prio < NUM_SCHED_PRIO; prio++) {
		index = &thread_local.indexes[prio];
		iterator = &thread_local.iterators[prio];

		sparse_bitmap_zero(index);
		sparse_bitmap_iterator(iterator, index);
	}
}

static int schedule_init_local(void)
{
	int group;
	sched_group_t *G;
	queue_index_bitmap_t collect;

	wapl_bitmap_zero(&collect);
	sched_thread_local_reset();

	/* Collect all queue indexes of the schedule groups
	 * which this thread has subscribed
	 */
	for (group = 0; group < NUM_SCHED_GRPS; group++) {
		G = &sched->groups[group];
		odp_rwlock_read_lock(&G->lock);

		if ((group < SCHED_GROUP_NAMED || G->allocated) &&
		    odp_thrmask_isset(&G->threads, thread_local.thread))
			wapl_bitmap_or(&collect, &collect, &G->queues);

		odp_rwlock_read_unlock(&G->lock);
	}

	/* Distribute the above collected queue indexes into
	 * thread local interests per priority level.
	 */
	thread_set_interests(&thread_local, &collect);

	/* "Night gathers, and now my watch begins..." */
	sched->threads[thread_local.thread] = &thread_local;
	return 0;
}

static inline void schedule_release_context(void);

static int schedule_term_local(void)
{
	int group;
	sched_group_t *G;

	if (thread_local.cache.count) {
		ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	schedule_release_context();

	/* Unsubscribe all named schedule groups */
	for (group = SCHED_GROUP_NAMED;
		group < NUM_SCHED_GRPS; group++) {
		G = &sched->groups[group];
		odp_rwlock_write_lock(&G->lock);

		if (G->allocated && odp_thrmask_isset(
			&G->threads, thread_local.thread))
			odp_thrmask_clr(&G->threads, thread_local.thread);

		odp_rwlock_write_unlock(&G->lock);
	}

	/* "...for this night and all the nights to come." */
	sched->threads[thread_local.thread] = NULL;
	sched_thread_local_reset();
	return 0;
}

static int init_sched_queue(uint32_t queue_index,
			    const odp_schedule_param_t *sched_param)
{
	int prio, group, thread;
	sched_prio_t *P;
	sched_group_t *G;
	sched_thread_local_t *local;

	prio = sched_param->prio;
	group = sched_param->group;

	G = &sched->groups[group];
	odp_rwlock_write_lock(&G->lock);

	/* Named schedule group must be created prior
	 * to queue creation to this group.
	 */
	if (group >= SCHED_GROUP_NAMED && !G->allocated) {
		odp_rwlock_write_unlock(&G->lock);
		return -1;
	}

	/* Record the queue in its priority level globally */
	P = &sched->prios[prio];

	odp_rwlock_write_lock(&P->lock);
	wapl_bitmap_set(&P->queues, queue_index);
	odp_rwlock_write_unlock(&P->lock);

	/* Record the queue in its schedule group */
	wapl_bitmap_set(&G->queues, queue_index);

	/* Cache queue parameters for easy reference */
	memcpy(&sched->queues[queue_index],
	       sched_param, sizeof(odp_schedule_param_t));

	/* Update all threads in this schedule group to
	 * start check this queue index upon scheduling.
	 */
	thread = odp_thrmask_first(&G->threads);
	while (thread >= 0) {
		local = sched->threads[thread];
		thread_set_interest(local, queue_index, prio);
		thread = odp_thrmask_next(&G->threads, thread);
	}

	odp_rwlock_write_unlock(&G->lock);
	return 0;
}

/*
 * Must be called with schedule group's rwlock held.
 * This is also being used in destroy_schedule_group()
 * to destroy all orphan queues while destroying a whole
 * schedule group.
 */
static void __destroy_sched_queue(
	sched_group_t *G, uint32_t queue_index)
{
	int prio, thread;
	sched_prio_t *P;
	sched_thread_local_t *local;

	prio = sched->queues[queue_index].prio;

	/* Forget the queue in its schedule group */
	wapl_bitmap_clear(&G->queues, queue_index);

	/* Forget queue schedule parameters */
	memset(&sched->queues[queue_index],
	       0, sizeof(odp_schedule_param_t));

	/* Update all threads in this schedule group to
	 * stop check this queue index upon scheduling.
	 */
	thread = odp_thrmask_first(&G->threads);
	while (thread >= 0) {
		local = sched->threads[thread];
		thread_clear_interest(local, queue_index, prio);
		thread = odp_thrmask_next(&G->threads, thread);
	}

	/* Forget the queue in its priority level globally */
	P = &sched->prios[prio];

	odp_rwlock_write_lock(&P->lock);
	wapl_bitmap_clear(&P->queues, queue_index);
	odp_rwlock_write_unlock(&P->lock);
}

static void destroy_sched_queue(uint32_t queue_index)
{
	int group;
	sched_group_t *G;

	group = sched->queues[queue_index].group;

	G = &sched->groups[group];
	odp_rwlock_write_lock(&G->lock);

	/* Named schedule group could have been destroyed
	 * earlier and left these orphan queues.
	 */
	if (group >= SCHED_GROUP_NAMED && !G->allocated) {
		odp_rwlock_write_unlock(&G->lock);
		return;
	}

	__destroy_sched_queue(G, queue_index);
	odp_rwlock_write_unlock(&G->lock);
}

static int pktio_cmd_queue_hash(int pktio, int pktin)
{
	return (pktio ^ pktin) % PKTIO_CMD_QUEUES;
}

static inline pktio_cmd_t *alloc_pktio_cmd(void)
{
	int i;
	pktio_cmd_t *cmd = NULL;

	odp_rwlock_write_lock(&sched->pktio_poll.lock);

	/* Find next free command */
	for (i = 0; i < NUM_PKTIO_CMD; i++) {
		if (sched->pktio_poll.commands[i].index
				== PKTIO_CMD_FREE) {
			cmd = &sched->pktio_poll.commands[i];
			cmd->index = i;
			break;
		}
	}

	odp_rwlock_write_unlock(&sched->pktio_poll.lock);
	return cmd;
}

static inline void free_pktio_cmd(pktio_cmd_t *cmd)
{
	odp_rwlock_write_lock(&sched->pktio_poll.lock);

	cmd->index = PKTIO_CMD_FREE;

	odp_rwlock_write_unlock(&sched->pktio_poll.lock);
}

static void schedule_pktio_start(int pktio, int count, int pktin[])
{
	int i, index;
	pktio_cmd_t *cmd;

	if (count > MAX_PKTIN)
		ODP_ABORT("Too many input queues for scheduler\n");

	/* Record the active commands count per pktio interface */
	sched->pktio_poll.actives[pktio] = count;

	/* Create a pktio poll command per pktin */
	for (i = 0; i < count; i++) {
		cmd = alloc_pktio_cmd();

		if (cmd == NULL)
			ODP_ABORT("Scheduler out of pktio commands\n");

		index = pktio_cmd_queue_hash(pktio, pktin[i]);

		cmd->pktio = pktio;
		cmd->count = 1;
		cmd->pktin[0] = pktin[i];
		ring_enq(&sched->pktio_poll.queues[index].ring,
			 PKTIO_RING_MASK, cmd->index);
	}
}

static int schedule_pktio_stop(int pktio, int pktin ODP_UNUSED)
{
	int remains;

	odp_rwlock_write_lock(&sched->pktio_poll.lock);

	sched->pktio_poll.actives[pktio]--;
	remains = sched->pktio_poll.actives[pktio];

	odp_rwlock_write_unlock(&sched->pktio_poll.lock);
	return remains;
}

#define DO_SCHED_LOCK() odp_rwlock_read_lock(&thread_local.lock)
#define DO_SCHED_UNLOCK() odp_rwlock_read_unlock(&thread_local.lock)

static inline bool do_schedule_prio(int prio);

static inline int pop_cache_events(odp_event_t ev[], unsigned int max)
{
	int k = 0;
	event_cache_t *cache;

	cache = &thread_local.cache;
	while (cache->count && max) {
		ev[k] = *cache->top++;
		k++;
		max--;
		cache->count--;
	}

	return k;
}

static inline void assign_queue_handle(odp_queue_t *handle)
{
	if (handle)
		*handle = thread_local.cache.queue;
}

static inline void pktio_poll_input(void)
{
	int i, hash;
	uint32_t index;

	ring_t *ring;
	pktio_cmd_t *cmd;

	/*
	 * Each thread starts the search for a poll command
	 * from the hash(threadID) queue to mitigate contentions.
	 * If the queue is empty, it moves to other queues.
	 *
	 * Most of the times, the search stops on the first
	 * command found to optimize multi-threaded performance.
	 * A small portion of polls have to do full iteration to
	 * avoid packet input starvation when there are less
	 * threads than command queues.
	 */
	hash = thread_local.thread % PKTIO_CMD_QUEUES;

	for (i = 0; i < PKTIO_CMD_QUEUES; i++,
	     hash = (hash + 1) % PKTIO_CMD_QUEUES) {
		ring = &sched->pktio_poll.queues[hash].ring;
		index = ring_deq(ring, PKTIO_RING_MASK);

		if (odp_unlikely(index == RING_EMPTY))
			continue;

		cmd = &sched->pktio_poll.commands[index];

		/* Poll packet input */
		if (odp_unlikely(sched_cb_pktin_poll(cmd->pktio,
						     cmd->count,
						     cmd->pktin))) {
			/* Pktio stopped or closed. Remove poll
			 * command and call stop_finalize when all
			 * commands of the pktio has been removed.
			 */
			if (schedule_pktio_stop(cmd->pktio,
						cmd->pktin[0]) == 0)
				sched_cb_pktio_stop_finalize(cmd->pktio);

			free_pktio_cmd(cmd);
		} else {
			/* Continue scheduling the pktio */
			ring_enq(ring, PKTIO_RING_MASK, index);

			/* Do not iterate through all pktin poll
			 * command queues every time.
			 */
			if (odp_likely(thread_local.pktin_polls & 0xF))
				break;
		}
	}

	thread_local.pktin_polls++;
}

/*
 * Schedule queues
 */
static int do_schedule(odp_queue_t *out_queue,
		       odp_event_t out_ev[], unsigned int max_num)
{
	int prio, count;

	/* Consume locally cached events */
	count = pop_cache_events(out_ev, max_num);
	if (count > 0) {
		assign_queue_handle(out_queue);
		return count;
	}

	schedule_release_context();

	if (odp_unlikely(thread_local.pause))
		return count;

	DO_SCHED_LOCK();
	/* Schedule events */
	for (prio = 0; prio < NUM_SCHED_PRIO; prio++) {
		/* Round robin iterate the interested queue
		 * indexes in this priority level to compete
		 * and consume available queues
		 */
		if (!do_schedule_prio(prio))
			continue;

		count = pop_cache_events(out_ev, max_num);
		assign_queue_handle(out_queue);
		DO_SCHED_UNLOCK();
		return count;
	}

	DO_SCHED_UNLOCK();

	/* Poll packet input when there are no events */
	pktio_poll_input();
	return 0;
}

static int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
			 odp_event_t out_ev[], unsigned int max_num)
{
	int count, first = 1;
	odp_time_t next, wtime;

	while (1) {
		count = do_schedule(out_queue, out_ev, max_num);

		if (count)
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

	return count;
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
	thread_local.pause = 1;
}

static void schedule_resume(void)
{
	thread_local.pause = 0;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static int number_of_priorites(void)
{
	return NUM_SCHED_PRIO;
}

/*
 * Create a named schedule group with pre-defined
 * set of subscription threads.
 *
 * Sched queues belonging to this group must be
 * created after the group creation. Upon creation
 * the group holds 0 sched queues.
 */
static odp_schedule_group_t schedule_group_create(
	const char *name, const odp_thrmask_t *mask)
{
	int group;
	sched_group_t *G;

	for (group = SCHED_GROUP_NAMED;
		group < NUM_SCHED_GRPS; group++) {
		G = &sched->groups[group];

		odp_rwlock_write_lock(&G->lock);
		if (!G->allocated) {
			strncpy(G->name, name ? name : "",
				ODP_SCHED_GROUP_NAME_LEN - 1);
			odp_thrmask_copy(&G->threads, mask);
			wapl_bitmap_zero(&G->queues);

			G->allocated = true;
			odp_rwlock_write_unlock(&G->lock);
			return (odp_schedule_group_t)group;
		}
		odp_rwlock_write_unlock(&G->lock);
	}

	return ODP_SCHED_GROUP_INVALID;
}

static inline void __destroy_group_queues(sched_group_t *group)
{
	unsigned int index;
	queue_index_bitmap_t queues;
	wapl_bitmap_iterator_t it;

	/* Constructor */
	wapl_bitmap_zero(&queues);
	wapl_bitmap_copy(&queues, &group->queues);
	wapl_bitmap_iterator(&it, &queues);

	/* Walk through the queue index bitmap */
	for (it.start(&it); it.has_next(&it);) {
		index = it.next(&it);
		__destroy_sched_queue(group, index);
	}
}

/*
 * Destroy a named schedule group.
 */
static int schedule_group_destroy(odp_schedule_group_t group)
{
	int done = -1;
	sched_group_t *G;

	if (group < SCHED_GROUP_NAMED ||
	    group >= NUM_SCHED_GRPS)
		return -1;

	G = &sched->groups[group];
	odp_rwlock_write_lock(&G->lock);

	if (G->allocated) {
		/* Destroy all queues in this schedule group
		 * and leave no orphan queues.
		 */
		__destroy_group_queues(G);

		done = 0;
		G->allocated = false;
		wapl_bitmap_zero(&G->queues);
		odp_thrmask_zero(&G->threads);
		memset(G->name, 0, ODP_SCHED_GROUP_NAME_LEN);
	}

	odp_rwlock_write_unlock(&G->lock);
	return done;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	int group;
	sched_group_t *G;

	for (group = SCHED_GROUP_NAMED;
	     group < NUM_SCHED_GRPS; group++) {
		G = &sched->groups[group];

		odp_rwlock_read_lock(&G->lock);
		if (strcmp(name, G->name) == 0) {
			odp_rwlock_read_unlock(&G->lock);
			return (odp_schedule_group_t)group;
		}
		odp_rwlock_read_unlock(&G->lock);
	}

	return ODP_SCHED_GROUP_INVALID;
}

static int schedule_group_join(odp_schedule_group_t group,
			       const odp_thrmask_t *mask)
{
	int done = -1, thread;
	sched_group_t *G;
	sched_thread_local_t *local;

	/* Named schedule group only */
	if (group < SCHED_GROUP_NAMED ||
	    group >= NUM_SCHED_GRPS)
		return done;

	G = &sched->groups[group];
	odp_rwlock_write_lock(&G->lock);

	if (G->allocated) {
		/* Make new joined threads to start check
		 * queue indexes in this schedule group
		 */
		thread = odp_thrmask_first(mask);
		while (thread >= 0) {
			local = sched->threads[thread];
			thread_set_interests(local, &G->queues);

			odp_thrmask_set(&G->threads, thread);
			thread = odp_thrmask_next(mask, thread);
		}
		done = 0;
	}

	odp_rwlock_write_unlock(&G->lock);
	return done;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *mask)
{
	int done = -1, thread;
	sched_group_t *G;
	sched_thread_local_t *local;

	/* Named schedule group only */
	if (group < SCHED_GROUP_NAMED ||
	    group >= NUM_SCHED_GRPS)
		return done;

	G = &sched->groups[group];
	odp_rwlock_write_lock(&G->lock);

	if (G->allocated) {
		/* Make leaving threads to stop check
		 * queue indexes in this schedule group
		 */
		thread = odp_thrmask_first(mask);
		while (thread >= 0) {
			local = sched->threads[thread];
			thread_clear_interests(local, &G->queues);

			odp_thrmask_clr(&G->threads, thread);
			thread = odp_thrmask_next(mask, thread);
		}
		done = 0;
	}

	odp_rwlock_write_unlock(&G->lock);
	return done;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	int done = -1;
	sched_group_t *G;

	/* Named schedule group only */
	if (group < SCHED_GROUP_NAMED ||
	    group >= NUM_SCHED_GRPS)
		return done;

	G = &sched->groups[group];
	odp_rwlock_read_lock(&G->lock);

	if (G->allocated && thrmask != NULL) {
		done = 0;
		odp_thrmask_copy(thrmask, &G->threads);
	}

	odp_rwlock_read_unlock(&G->lock);
	return done;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	int done = -1;
	sched_group_t *G;

	/* Named schedule group only */
	if (group < SCHED_GROUP_NAMED ||
	    group >= NUM_SCHED_GRPS)
		return done;

	G = &sched->groups[group];
	odp_rwlock_read_lock(&G->lock);

	if (G->allocated && info != NULL) {
		done = 0;
		info->name = G->name;
		odp_thrmask_copy(&info->thrmask, &G->threads);
	}

	odp_rwlock_read_unlock(&G->lock);
	return done;
}

/* This function is a no-op */
static void schedule_prefetch(int num ODP_UNUSED)
{
}

/*
 * Limited to join and leave pre-defined schedule groups
 * before and after thread local initialization or termination.
 */
static int group_add_thread(odp_schedule_group_t group, int thread)
{
	sched_group_t *G;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	G = &sched->groups[group];

	odp_rwlock_write_lock(&G->lock);
	odp_thrmask_set(&G->threads, thread);
	odp_rwlock_write_unlock(&G->lock);
	return 0;
}

static int group_remove_thread(odp_schedule_group_t group, int thread)
{
	sched_group_t *G;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	G = &sched->groups[group];

	odp_rwlock_write_lock(&G->lock);
	odp_thrmask_clr(&G->threads, thread);
	odp_rwlock_write_unlock(&G->lock);
	return 0;
}

static int number_of_groups(void)
{
	return NUM_SCHED_GRPS;
}

static int schedule_sched_queue(uint32_t queue_index)
{
	/* Set available indications globally */
	sched->availables[queue_index] = true;
	return 0;
}

static int schedule_unsched_queue(uint32_t queue_index)
{
	/* Clear available indications globally */
	sched->availables[queue_index] = false;
	return 0;
}

static void schedule_release_atomic(void)
{
	unsigned int queue_index;

	if ((thread_local.atomic != NULL) &&
	    (thread_local.cache.count == 0)) {
		queue_index = thread_local.atomic - sched->availables;
		thread_local.atomic = NULL;
		sched->availables[queue_index] = true;
	}
}

static inline int ordered_own_turn(queue_entry_t *queue)
{
	uint64_t ctx;

	ctx = odp_atomic_load_acq_u64(&queue->s.ordered.ctx);

	return ctx == thread_local.ordered.ctx;
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

	for (i = 0; i < thread_local.ordered.stash_num; i++) {
		queue_entry_t *queue;
		odp_buffer_hdr_t **buf_hdr;
		int num;

		queue = thread_local.ordered.stash[i].queue;
		buf_hdr = thread_local.ordered.stash[i].buf_hdr;
		num = thread_local.ordered.stash[i].num;

		queue_fn->enq_multi(qentry_to_int(queue), buf_hdr, num);
	}
	thread_local.ordered.stash_num = 0;
}

static inline void release_ordered(void)
{
	unsigned i;
	queue_entry_t *queue;

	queue = thread_local.ordered.src_queue;

	wait_for_order(queue);

	/* Release all ordered locks */
	for (i = 0; i < queue->s.param.sched.lock_count; i++) {
		if (!thread_local.ordered.lock_called.u8[i])
			odp_atomic_store_rel_u64(&queue->s.ordered.lock[i],
						 thread_local.ordered.ctx + 1);
	}

	thread_local.ordered.lock_called.all = 0;
	thread_local.ordered.src_queue = NULL;
	thread_local.ordered.in_order = 0;

	ordered_stash_release();

	/* Next thread can continue processing */
	odp_atomic_add_rel_u64(&queue->s.ordered.ctx, 1);
}

static void schedule_release_ordered(void)
{
	queue_entry_t *queue;

	queue = thread_local.ordered.src_queue;

	if (odp_unlikely(!queue || thread_local.cache.count))
		return;

	release_ordered();
}

static inline void schedule_release_context(void)
{
	if (thread_local.ordered.src_queue != NULL)
		release_ordered();
	else
		schedule_release_atomic();
}

static int schedule_ord_enq_multi(queue_t handle, void *buf_hdr[],
				  int num, int *ret)
{
	int i;
	uint32_t stash_num = thread_local.ordered.stash_num;
	queue_entry_t *dst_queue = qentry_from_int(handle);
	queue_entry_t *src_queue = thread_local.ordered.src_queue;

	if (!thread_local.ordered.src_queue || thread_local.ordered.in_order)
		return 0;

	if (ordered_own_turn(src_queue)) {
		/* Own turn, so can do enqueue directly. */
		thread_local.ordered.in_order = 1;
		ordered_stash_release();
		return 0;
	}

	/* Pktout may drop packets, so the operation cannot be stashed. */
	if (dst_queue->s.pktout.pktio != ODP_PKTIO_INVALID ||
	    odp_unlikely(stash_num >=  MAX_ORDERED_STASH)) {
		/* If the local stash is full, wait until it is our turn and
		 * then release the stash and do enqueue directly. */
		wait_for_order(src_queue);

		thread_local.ordered.in_order = 1;

		ordered_stash_release();
		return 0;
	}

	thread_local.ordered.stash[stash_num].queue = dst_queue;
	thread_local.ordered.stash[stash_num].num = num;
	for (i = 0; i < num; i++)
		thread_local.ordered.stash[stash_num].buf_hdr[i] = buf_hdr[i];

	thread_local.ordered.stash_num++;

	*ret = num;
	return 1;
}

static void order_lock(void)
{
	queue_entry_t *queue;

	queue = thread_local.ordered.src_queue;

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

	queue = thread_local.ordered.src_queue;

	ODP_ASSERT(queue && lock_index <= queue->s.param.sched.lock_count &&
		   !thread_local.ordered.lock_called.u8[lock_index]);

	ord_lock = &queue->s.ordered.lock[lock_index];

	/* Busy loop to synchronize ordered processing */
	while (1) {
		uint64_t lock_seq;

		lock_seq = odp_atomic_load_acq_u64(ord_lock);

		if (lock_seq == thread_local.ordered.ctx) {
			thread_local.ordered.lock_called.u8[lock_index] = 1;
			return;
		}
		odp_cpu_pause();
	}
}

static void schedule_order_unlock(unsigned lock_index)
{
	odp_atomic_u64_t *ord_lock;
	queue_entry_t *queue;

	queue = thread_local.ordered.src_queue;

	ODP_ASSERT(queue && lock_index <= queue->s.param.sched.lock_count);

	ord_lock = &queue->s.ordered.lock[lock_index];

	ODP_ASSERT(thread_local.ordered.ctx == odp_atomic_load_u64(ord_lock));

	odp_atomic_store_rel_u64(ord_lock, thread_local.ordered.ctx + 1);
}

static unsigned schedule_max_ordered_locks(void)
{
	return MAX_ORDERED_LOCKS_PER_QUEUE;
}

static void schedule_save_context(queue_entry_t *queue)
{
	if (queue->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
		thread_local.atomic = &sched->availables[queue->s.index];
	} else if (queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		uint64_t ctx;
		odp_atomic_u64_t *next_ctx;

		next_ctx = &queue->s.ordered.next_ctx;
		ctx = odp_atomic_fetch_inc_u64(next_ctx);

		thread_local.ordered.ctx = ctx;
		thread_local.ordered.src_queue = queue;
	}
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_iquery_fn = {
	.pktio_start   = schedule_pktio_start,
	.thr_add       = group_add_thread,
	.thr_rem       = group_remove_thread,
	.num_grps      = number_of_groups,
	.init_queue    = init_sched_queue,
	.destroy_queue = destroy_sched_queue,
	.sched_queue   = schedule_sched_queue,
	.unsched_queue = schedule_unsched_queue,
	.ord_enq_multi = schedule_ord_enq_multi,
	.init_global   = schedule_init_global,
	.term_global   = schedule_term_global,
	.init_local    = schedule_init_local,
	.term_local    = schedule_term_local,
	.order_lock    = order_lock,
	.order_unlock  = order_unlock,
	.max_ordered_locks = schedule_max_ordered_locks,
	.save_context  = schedule_save_context,
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_iquery_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_num_prio        = number_of_priorites,
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

static void thread_set_interest(sched_thread_local_t *thread,
				unsigned int queue_index, int prio)
{
	queue_index_sparse_t *index;

	if (thread == NULL)
		return;

	if (prio >= NUM_SCHED_PRIO)
		return;

	index = &thread->indexes[prio];

	odp_rwlock_write_lock(&thread->lock);
	sparse_bitmap_set(index, queue_index);
	odp_rwlock_write_unlock(&thread->lock);
}

static void thread_clear_interest(sched_thread_local_t *thread,
				  unsigned int queue_index, int prio)
{
	queue_index_sparse_t *index;

	if (thread == NULL)
		return;

	if (prio >= NUM_SCHED_PRIO)
		return;

	index = &thread->indexes[prio];

	odp_rwlock_write_lock(&thread->lock);
	sparse_bitmap_clear(index, queue_index);
	odp_rwlock_write_unlock(&thread->lock);
}

static void thread_set_interests(sched_thread_local_t *thread,
				 queue_index_bitmap_t *set)
{
	int prio;
	sched_prio_t *P;
	unsigned int queue_index;
	queue_index_bitmap_t subset;
	wapl_bitmap_iterator_t it;

	if (thread == NULL || set == NULL)
		return;

	for (prio = 0; prio < NUM_SCHED_PRIO; prio++) {
		P = &sched->prios[prio];
		odp_rwlock_read_lock(&P->lock);

		/* The collection of queue indexes in 'set'
		 * may belong to several priority levels.
		 */
		wapl_bitmap_zero(&subset);
		wapl_bitmap_and(&subset, &P->queues, set);

		odp_rwlock_read_unlock(&P->lock);

		/* Add the subset to local indexes */
		wapl_bitmap_iterator(&it, &subset);
		for (it.start(&it); it.has_next(&it);) {
			queue_index = it.next(&it);
			thread_set_interest(thread, queue_index, prio);
		}
	}
}

static void thread_clear_interests(sched_thread_local_t *thread,
				   queue_index_bitmap_t *clear)
{
	int prio;
	sched_prio_t *P;
	unsigned int queue_index;
	queue_index_bitmap_t subset;
	wapl_bitmap_iterator_t it;

	if (thread == NULL || clear == NULL)
		return;

	for (prio = 0; prio < NUM_SCHED_PRIO; prio++) {
		P = &sched->prios[prio];
		odp_rwlock_read_lock(&P->lock);

		/* The collection of queue indexes in 'clear'
		 * may belong to several priority levels.
		 */
		wapl_bitmap_zero(&subset);
		wapl_bitmap_and(&subset, &P->queues, clear);

		odp_rwlock_read_unlock(&P->lock);

		/* Remove the subset from local indexes */
		wapl_bitmap_iterator(&it, &subset);
		for (it.start(&it); it.has_next(&it);) {
			queue_index = it.next(&it);
			thread_clear_interest(thread, queue_index, prio);
		}
	}
}

static inline bool is_atomic_queue(unsigned int queue_index)
{
	return (sched->queues[queue_index].sync
			== ODP_SCHED_SYNC_ATOMIC);
}

static inline bool is_ordered_queue(unsigned int queue_index)
{
	return (sched->queues[queue_index].sync
			== ODP_SCHED_SYNC_ORDERED);
}

static inline bool compete_atomic_queue(unsigned int queue_index)
{
	bool expected = sched->availables[queue_index];

	if (expected && is_atomic_queue(queue_index)) {
		expected = __atomic_compare_exchange_n(
			&sched->availables[queue_index],
			&expected, false, 0,
			__ATOMIC_RELEASE, __ATOMIC_RELAXED);
	}

	return expected;
}

static inline int consume_queue(int prio, unsigned int queue_index)
{
	int count;
	unsigned int max = MAX_DEQ;
	event_cache_t *cache = &thread_local.cache;

	/* Low priorities have smaller batch size to limit
	 * head of line blocking latency.
	 */
	if (odp_unlikely(MAX_DEQ > 1 && prio > ODP_SCHED_PRIO_DEFAULT))
		max = MAX_DEQ / 2;

	/* For ordered queues we want consecutive events to
	 * be dispatched to separate threads, so do not cache
	 * them locally.
	 */
	if (is_ordered_queue(queue_index))
		max = 1;

	count = sched_cb_queue_deq_multi(
		queue_index, cache->stash, max);

	if (count < 0) {
		DO_SCHED_UNLOCK();
		sched_cb_queue_destroy_finalize(queue_index);
		DO_SCHED_LOCK();
		return 0;
	}

	if (count == 0)
		return 0;

	cache->top = &cache->stash[0];
	cache->count = count;
	cache->queue = sched_cb_queue_handle(queue_index);
	return count;
}

static inline bool do_schedule_prio(int prio)
{
	int nbits, next, end;
	unsigned int queue_index;
	sparse_bitmap_iterator_t *it;

	it = &thread_local.iterators[prio];
	nbits = (int)*it->_base.last;

	/* No interests at all! */
	if (nbits <= 0)
		return false;

	/* In critical path, cannot afford iterator calls,
	 * do it manually with internal knowledge
	 */
	it->_start = (it->_start + 1) % nbits;
	end = it->_start + nbits;

	for (next = it->_start; next < end; next++) {
		queue_index = it->_base.il[next % nbits];

		if (!compete_atomic_queue(queue_index))
			continue;

		if (!consume_queue(prio, queue_index))
			continue;

		return true;
	}

	return false;
}
