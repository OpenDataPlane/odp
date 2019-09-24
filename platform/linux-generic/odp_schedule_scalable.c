/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp/api/align.h>
#include <odp/api/atomic.h>
#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/schedule.h>
#include <odp/api/shared_memory.h>
#include <odp/api/sync.h>
#include <odp/api/thread.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp/api/thrmask.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_shm_internal.h>
#include <odp_ishmpool_internal.h>

#include <odp_align_internal.h>
#include <odp/api/plat/cpu_inlines.h>
#include <odp_llqueue.h>
#include <odp_queue_scalable_internal.h>
#include <odp_schedule_if.h>
#include <odp_bitset.h>
#include <odp_packet_io_internal.h>
#include <odp_timer_internal.h>

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <odp/api/plat/ticketlock_inlines.h>
#define LOCK(a) odp_ticketlock_lock((a))
#define UNLOCK(a) odp_ticketlock_unlock((a))

#define MAXTHREADS ATOM_BITSET_SIZE

#define FLAG_PKTIN 0x80

ODP_STATIC_ASSERT(CHECK_IS_POWER2(CONFIG_MAX_SCHED_QUEUES),
		  "Number_of_queues_is_not_power_of_two");

#define SCHED_GROUP_JOIN 0
#define SCHED_GROUP_LEAVE 1

typedef struct {
	odp_shm_t shm;
	_odp_ishm_pool_t *sched_shm_pool;
	/** Currently used scheduler groups */
	sched_group_mask_t sg_free;
	sched_group_t *sg_vec[MAX_SCHED_GROUP];
	/** Group lock for MT-safe APIs */
	odp_spinlock_t sched_grp_lock;
	/** Per thread state */
	sched_scalable_thread_state_t thread_state[MAXTHREADS];
	uint16_t poll_count[ODP_CONFIG_PKTIO_ENTRIES];
} sched_global_t;

static sched_global_t *global;

__thread sched_scalable_thread_state_t *sched_ts;

static int thread_state_init(int tidx)
{
	sched_scalable_thread_state_t *ts;
	uint32_t i;

	ODP_ASSERT(tidx < MAXTHREADS);
	ts = &global->thread_state[tidx];
	ts->atomq = NULL;
	ts->src_schedq = NULL;
	ts->rctx = NULL;
	ts->pause = false;
	ts->out_of_order = false;
	ts->tidx = tidx;
	ts->dequeued = 0;
	ts->ticket = TICKET_INVALID;
	ts->priv_rvec_free = 0;
	ts->rvec_free = (1ULL << TS_RVEC_SIZE) - 1;
	ts->num_schedq = 0;
	ts->sg_sem = 1; /* Start with sched group semaphore changed */
	memset(ts->sg_actual, 0, sizeof(ts->sg_actual));
	for (i = 0; i < TS_RVEC_SIZE; i++) {
		ts->rvec[i].rvec_free = &ts->rvec_free;
		ts->rvec[i].idx = i;
	}
	sched_ts = ts;

	return 0;
}

static void insert_schedq_in_list(sched_scalable_thread_state_t *ts,
				  sched_queue_t *schedq)
{
	/* Find slot for schedq */
	for (uint32_t i = 0; i < ts->num_schedq; i++) {
		/* Lower value is higher priority and closer to start of list */
		if (schedq->prio <= ts->schedq_list[i]->prio) {
			/* This is the slot! */
			sched_queue_t *tmp;

			tmp = ts->schedq_list[i];
			ts->schedq_list[i] = schedq;
			schedq = tmp;
			/* Continue the insertion procedure with the
			 * new schedq.
			 */
		}
	}
	if (ts->num_schedq == SCHEDQ_PER_THREAD)
		ODP_ABORT("Too many schedqs\n");
	ts->schedq_list[ts->num_schedq++] = schedq;
}

static void remove_schedq_from_list(sched_scalable_thread_state_t *ts,
				    sched_queue_t *schedq)
{
	/* Find schedq */
	for (uint32_t i = 0; i < ts->num_schedq; i++)
		if (ts->schedq_list[i] == schedq) {
			/* Move remaining schedqs */
			for (uint32_t j = i + 1; j < ts->num_schedq; j++)
				ts->schedq_list[j - 1] = ts->schedq_list[j];
			ts->num_schedq--;
			return;
		}
	ODP_ABORT("Cannot find schedq\n");
}

/*******************************************************************************
 * Scheduler queues
 ******************************************************************************/
#ifndef odp_container_of
#define odp_container_of(pointer, type, member) \
	((type *)(void *)(((char *)pointer) - offsetof(type, member)))
#endif

static inline void schedq_init(sched_queue_t *schedq, uint32_t prio)
{
	llqueue_init(&schedq->llq);
	schedq->prio = prio;
}

static inline sched_elem_t *schedq_peek(sched_queue_t *schedq)
{
	struct llnode *ptr;

	ptr = llq_head(&schedq->llq);
	return odp_container_of(ptr, sched_elem_t, node);
}

static inline odp_bool_t schedq_cond_pop(sched_queue_t *schedq,
					 sched_elem_t *elem)
{
	return llq_dequeue_cond(&schedq->llq, &elem->node);
}

static inline void schedq_push(sched_queue_t *schedq, sched_elem_t *elem)
{
	llq_enqueue(&schedq->llq, &elem->node);
}

static inline odp_bool_t schedq_cond_rotate(sched_queue_t *schedq,
					    sched_elem_t *elem)
{
	return llq_cond_rotate(&schedq->llq, &elem->node);
}

static inline bool schedq_elem_on_queue(sched_elem_t *elem)
{
	return llq_on_queue(&elem->node);
}

/*******************************************************************************
 * Shared metadata btwn scheduler and queue
 ******************************************************************************/

void sched_update_enq(sched_elem_t *q, uint32_t actual)
{
	qschedstate_t oss, nss;
	uint32_t ticket;

	oss = q->qschst;
	/* Update event counter, optionally taking a ticket. */
	do {
		ticket = TICKET_INVALID;
		nss = oss;
		nss.numevts += actual;
		if (odp_unlikely(oss.numevts <= 0 && nss.numevts > 0))
			/* E -> NE transition */
			if (q->qschst_type != ODP_SCHED_SYNC_ATOMIC ||
			    oss.cur_ticket == oss.nxt_ticket)
				/* Parallel or ordered queues: always take
				 * ticket.
				 * Atomic queue: only take ticket if one is
				 * immediately available.
				 * Otherwise ticket already taken => queue
				 * processed by some thread.
				 */
				ticket = nss.nxt_ticket++;
		/* Else queue already was non-empty. */
	/* Attempt to update numevts counter and optionally take ticket. */
	} while (!__atomic_compare_exchange(
		       &q->qschst, &oss, &nss,
		       true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	if (odp_unlikely(ticket != TICKET_INVALID)) {
		/* Wait for our turn to update schedq. */
		if (odp_unlikely(
			    __atomic_load_n(&q->qschst.cur_ticket,
					    __ATOMIC_ACQUIRE) != ticket)) {
			sevl();
			while (wfe() &&
			       monitor8(&q->qschst.cur_ticket,
					__ATOMIC_ACQUIRE) != ticket)
				doze();
		}
		/* Enqueue at end of scheduler queue */
		/* We are here because of empty-to-non-empty transition
		 * This means queue must be pushed to schedq if possible
		 * but we can't do that if it already is on the schedq
		 */
		if (odp_likely(!schedq_elem_on_queue(q) &&
			       q->pop_deficit == 0)) {
			/* Queue not already on schedq and no pop deficit means
			 * we can push queue to schedq */
			schedq_push(q->schedq, q);
		} else {
			/* Missed push => cancels one missed pop */
			q->pop_deficit--;
		}
		atomic_store_release(&q->qschst.cur_ticket, ticket + 1,
				     /*readonly=*/false);
	}
	/* Else queue was not empty or atomic queue already busy. */
}

void sched_update_enq_sp(sched_elem_t *q, uint32_t actual)
{
	qschedstate_t oss, nss;
	uint32_t ticket;

	oss = q->qschst;
	/* Update event counter, optionally taking a ticket. */
	ticket = TICKET_INVALID;
	nss = oss;
	nss.numevts += actual;
	if (odp_unlikely(oss.numevts <= 0 && nss.numevts > 0)) {
		/* E -> NE transition */
		if (q->qschst_type != ODP_SCHED_SYNC_ATOMIC ||
		    oss.cur_ticket == oss.nxt_ticket) {
			/* Parallel or ordered queues: always take
			 * ticket.
			 * Atomic queue: only take ticket if one is
			 * immediately available. Otherwise ticket already
			 * taken => queue owned/processed by some thread
			 */
			ticket = nss.nxt_ticket++;
		}
	}
	/* Else queue already was non-empty. */
	/* Attempt to update numevts counter and optionally take ticket. */
	q->qschst = nss;

	if (odp_unlikely(ticket != TICKET_INVALID)) {
		/* Enqueue at end of scheduler queue */
		/* We are here because of empty-to-non-empty transition
		 * This means queue must be pushed to schedq if possible
		 * but we can't do that if it already is on the schedq
		 */
		if (odp_likely(!schedq_elem_on_queue(q) &&
			       q->pop_deficit == 0)) {
			/* Queue not already on schedq and no pop deficit means
			 * we can push queue to schedq */
			schedq_push(q->schedq, q);
		} else {
			/* Missed push => cancels one missed pop */
			q->pop_deficit--;
		}
		q->qschst.cur_ticket = ticket + 1;
	}
	/* Else queue was not empty or atomic queue already busy. */
}

#ifndef CONFIG_QSCHST_LOCK
/* The scheduler is the only entity that performs the dequeue from a queue. */
static void
sched_update_deq(sched_elem_t *q,
		 uint32_t actual,
		 bool atomic) __attribute__((always_inline));
static inline void
sched_update_deq(sched_elem_t *q,
		 uint32_t actual, bool atomic)
{
	qschedstate_t oss, nss;
	uint32_t ticket;

	if (atomic) {
		bool pushed = false;

		/* We own this atomic queue, only we can dequeue from it and
		 * thus decrease numevts. Other threads may enqueue and thus
		 * increase numevts.
		 * This means that numevts can't unexpectedly become 0 and
		 * invalidate a push operation already performed
		 */
		oss = q->qschst;
		do {
			ODP_ASSERT(oss.cur_ticket == sched_ts->ticket);
			nss = oss;
			nss.numevts -= actual;
			if (nss.numevts > 0 && !pushed) {
				schedq_push(q->schedq, q);
				pushed = true;
			}
			/* Attempt to release ticket expecting our view of
			 * numevts to be correct
			 * Unfortunately nxt_ticket will also be included in
			 * the CAS operation
			 */
			nss.cur_ticket = sched_ts->ticket + 1;
		} while (odp_unlikely(!__atomic_compare_exchange(
							  &q->qschst,
							  &oss, &nss,
							  true,
							  __ATOMIC_RELEASE,
							  __ATOMIC_RELAXED)));
		return;
	}

	oss = q->qschst;
	do {
		ticket = TICKET_INVALID;
		nss = oss;
		nss.numevts -= actual;
		nss.wrr_budget -= actual;
		if ((oss.numevts > 0 && nss.numevts <= 0) ||
		    oss.wrr_budget <= actual) {
			/* If we have emptied parallel/ordered queue or
			 * exchausted its WRR budget, we need a ticket
			 * for a later pop.
			 */
			ticket = nss.nxt_ticket++;
			/* Reset wrr_budget as we might also push the
			 * queue to the schedq.
			 */
			nss.wrr_budget = CONFIG_WRR_WEIGHT;
		}
	/* Attempt to update numevts and optionally take ticket. */
	} while (!__atomic_compare_exchange(
		       &q->qschst, &oss, &nss,
		       true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));

	if (odp_unlikely(ticket != TICKET_INVALID)) {
		ODP_ASSERT(q->qschst_type != ODP_SCHED_SYNC_ATOMIC);
		/* Wait for our turn to update schedq. */
		if (odp_unlikely(
			    __atomic_load_n(&q->qschst.cur_ticket,
					    __ATOMIC_ACQUIRE) != ticket)) {
			sevl();
			while (wfe() &&
			       monitor8(&q->qschst.cur_ticket,
					__ATOMIC_ACQUIRE) != ticket)
				doze();
		}
		/* We are here because of non-empty-to-empty transition or
		 * WRR budget exhausted
		 * This means the queue must be popped from the schedq, now or
		 * later
		 * If there was no NE->E transition but instead the WRR budget
		 * was exhausted, the queue needs to be moved (popped and
		 * pushed) to the tail of the schedq
		 */
		if (oss.numevts > 0 && nss.numevts <= 0) {
			/* NE->E transition, need to pop */
			if (!schedq_elem_on_queue(q) ||
			    !schedq_cond_pop(q->schedq, q)) {
				/* Queue not at head, failed to dequeue
				 * Missed a pop.
				 */
				q->pop_deficit++;
			}
		} else {
			/* WRR budget exhausted
			 * Need to move queue to tail of schedq if possible
			 */
			if (odp_likely(schedq_elem_on_queue(q))) {
				/* Queue is on schedq, try to move it to
				 * the tail
				 */
				(void)schedq_cond_rotate(q->schedq, q);
			}
			/* Else queue not on schedq or not at head of schedq
			 * No pop => no push
			 */
		}
		atomic_store_release(&q->qschst.cur_ticket, ticket + 1,
				     /*readonly=*/false);
	}
}
#endif

#ifdef CONFIG_QSCHST_LOCK
static void
sched_update_deq_sc(sched_elem_t *q,
		    uint32_t actual,
		    bool atomic) __attribute__((always_inline));
static inline void
sched_update_deq_sc(sched_elem_t *q,
		    uint32_t actual, bool atomic)
{
	qschedstate_t oss, nss;
	uint32_t ticket;

	if (atomic) {
		ODP_ASSERT(q->qschst.cur_ticket == sched_ts->ticket);
		ODP_ASSERT(q->qschst.cur_ticket != q->qschst.nxt_ticket);
		q->qschst.numevts -= actual;
		q->qschst.cur_ticket = sched_ts->ticket + 1;
		if (q->qschst.numevts > 0)
			schedq_push(q->schedq, q);
		return;
	}

	oss = q->qschst;
	ticket = TICKET_INVALID;
	nss = oss;
	nss.numevts -= actual;
	nss.wrr_budget -= actual;
	if ((oss.numevts > 0 && nss.numevts <= 0) || oss.wrr_budget <= actual) {
		/* If we emptied the queue or
		 * if we have served the maximum number of events
		 * then we need a ticket for a later pop.
		 */
		ticket = nss.nxt_ticket++;
		/* Also reset wrr_budget as we might also push the
		 * queue to the schedq.
		 */
		nss.wrr_budget = CONFIG_WRR_WEIGHT;
	}
	q->qschst = nss;

	if (ticket != TICKET_INVALID) {
		if (oss.numevts > 0 && nss.numevts <= 0) {
			/* NE->E transition, need to pop */
			if (!schedq_elem_on_queue(q) ||
			    !schedq_cond_pop(q->schedq, q)) {
				/* Queue not at head, failed to dequeue.
				 * Missed a pop.
				 */
				q->pop_deficit++;
			}
		} else {
			/* WRR budget exhausted
			 * Need to move queue to tail of schedq if possible
			 */
			if (odp_likely(schedq_elem_on_queue(q))) {
				/* Queue is on schedq, try to move it to
				 * the tail
				 */
				(void)schedq_cond_rotate(q->schedq, q);
			}
			/* Else queue not on schedq or not at head of schedq
			 * No pop => no push
			 */
		}
		q->qschst.cur_ticket = ticket + 1;
	}
}
#endif

static inline void sched_update_popd_sc(sched_elem_t *elem)
{
	if (elem->pop_deficit != 0 &&
	    schedq_elem_on_queue(elem) &&
	    schedq_cond_pop(elem->schedq, elem))
		elem->pop_deficit--;
}

#ifndef CONFIG_QSCHST_LOCK
static inline void sched_update_popd(sched_elem_t *elem)
{
	uint32_t ticket = __atomic_fetch_add(&elem->qschst.nxt_ticket,
					    1,
					    __ATOMIC_RELAXED);
	if (odp_unlikely(__atomic_load_n(&elem->qschst.cur_ticket,
					 __ATOMIC_ACQUIRE) != ticket)) {
		sevl();
		while (wfe() && monitor8(&elem->qschst.cur_ticket,
					 __ATOMIC_ACQUIRE) != ticket)
			doze();
	}
	sched_update_popd_sc(elem);
	atomic_store_release(&elem->qschst.cur_ticket, ticket + 1,
			     /*readonly=*/false);
}
#endif

static void signal_threads_add(sched_group_t *sg, uint32_t sgi, uint32_t prio)
{
	sched_group_mask_t thrds = sg->thr_wanted;
	uint32_t thr;

	while (!bitset_is_null(thrds)) {
		thr = bitset_ffs(thrds) - 1;
		thrds = bitset_clr(thrds, thr);
		/* Notify the thread about membership in this
		 * group/priority.
		 */
		atom_bitset_set(&global->thread_state[thr].sg_wanted[prio],
				sgi, __ATOMIC_RELEASE);
		__atomic_store_n(&global->thread_state[thr].sg_sem, 1,
				 __ATOMIC_RELEASE);
	}
}

sched_queue_t *sched_queue_add(odp_schedule_group_t grp, uint32_t prio)
{
	uint32_t sgi;
	sched_group_t *sg;
	uint32_t x;

	ODP_ASSERT(grp >= 0 && grp < (odp_schedule_group_t)MAX_SCHED_GROUP);
	ODP_ASSERT((global->sg_free & (1ULL << grp)) == 0);
	ODP_ASSERT(prio < ODP_SCHED_PRIO_NUM);

	sgi = grp;
	sg = global->sg_vec[sgi];

	/* Use xcount to spread queues over the xfactor schedq's
	 * per priority.
	 */
	x = __atomic_fetch_add(&sg->xcount[prio], 1, __ATOMIC_RELAXED);
	if (x == 0) {
		/* First ODP queue for this priority
		 * Notify all threads in sg->thr_wanted that they
		 * should join.
		 */
		signal_threads_add(sg, sgi, prio);
	}
	return &sg->schedq[prio * sg->xfactor + x % sg->xfactor];
}

static uint32_t sched_pktin_add(odp_schedule_group_t grp, uint32_t prio)
{
	uint32_t sgi;
	sched_group_t *sg;

	ODP_ASSERT(grp >= 0 && grp < (odp_schedule_group_t)MAX_SCHED_GROUP);
	ODP_ASSERT((global->sg_free & (1ULL << grp)) == 0);
	ODP_ASSERT(prio < ODP_SCHED_PRIO_NUM);

	sgi = grp;
	sg = global->sg_vec[sgi];

	(void)sched_queue_add(grp, ODP_SCHED_PRIO_PKTIN);
	return (ODP_SCHED_PRIO_PKTIN - prio) * sg->xfactor;
}

static void signal_threads_rem(sched_group_t *sg, uint32_t sgi, uint32_t prio)
{
	sched_group_mask_t thrds = sg->thr_wanted;
	uint32_t thr;

	while (!bitset_is_null(thrds)) {
		thr = bitset_ffs(thrds) - 1;
		thrds = bitset_clr(thrds, thr);
		/* Notify the thread about membership in this
		 * group/priority.
		 */
		atom_bitset_clr(&global->thread_state[thr].sg_wanted[prio],
				sgi, __ATOMIC_RELEASE);
		__atomic_store_n(&global->thread_state[thr].sg_sem, 1,
				 __ATOMIC_RELEASE);
	}
}

void sched_queue_rem(odp_schedule_group_t grp, uint32_t prio)
{
	uint32_t sgi;
	sched_group_t *sg;
	uint32_t x;

	ODP_ASSERT(grp >= 0 && grp < (odp_schedule_group_t)MAX_SCHED_GROUP);
	ODP_ASSERT((global->sg_free & (1ULL << grp)) == 0);
	ODP_ASSERT(prio < ODP_SCHED_PRIO_NUM);

	sgi = grp;
	sg = global->sg_vec[sgi];

	x = __atomic_sub_fetch(&sg->xcount[prio], 1, __ATOMIC_RELAXED);
	if (x == 0) {
		/* Last ODP queue for this priority
		 * Notify all threads in sg->thr_wanted that they
		 * should leave.
		 */
		signal_threads_rem(sg, sgi, prio);
	}
}

static void sched_pktin_rem(odp_schedule_group_t grp)
{
	sched_queue_rem(grp, ODP_SCHED_PRIO_PKTIN);
}

static void update_sg_add(sched_scalable_thread_state_t *ts,
			  uint32_t p,
			  sched_group_mask_t sg_wanted)
{
	sched_group_mask_t added;
	uint32_t sgi;
	sched_group_t *sg;
	uint32_t x;

	added = bitset_andn(sg_wanted, ts->sg_actual[p]);
	while (!bitset_is_null(added)) {
		sgi = bitset_ffs(added) - 1;
		sg = global->sg_vec[sgi];
		for (x = 0; x < sg->xfactor; x++) {
			/* Include our thread index to shift
			 * (rotate) the order of schedq's
			 */
			insert_schedq_in_list(ts,
					      &sg->schedq[p * sg->xfactor +
					      (x + ts->tidx) % sg->xfactor]);
		}
		atom_bitset_set(&sg->thr_actual[p], ts->tidx, __ATOMIC_RELAXED);
		added = bitset_clr(added, sgi);
	}
}

static void update_sg_rem(sched_scalable_thread_state_t *ts,
			  uint32_t p,
			  sched_group_mask_t sg_wanted)
{
	sched_group_mask_t removed;
	uint32_t sgi;
	sched_group_t *sg;
	uint32_t x;

	removed = bitset_andn(ts->sg_actual[p], sg_wanted);
	while (!bitset_is_null(removed)) {
		sgi = bitset_ffs(removed) - 1;
		sg = global->sg_vec[sgi];
		for (x = 0; x < sg->xfactor; x++) {
			remove_schedq_from_list(ts,
						&sg->schedq[p *
						sg->xfactor + x]);
		}
		atom_bitset_clr(&sg->thr_actual[p], ts->tidx, __ATOMIC_RELAXED);
		removed = bitset_clr(removed, sgi);
	}
}

static void update_sg_membership(sched_scalable_thread_state_t *ts)
{
	uint32_t p;
	sched_group_mask_t sg_wanted;

	for (p = 0; p < ODP_SCHED_PRIO_NUM; p++) {
		sg_wanted = atom_bitset_load(&ts->sg_wanted[p],
					     __ATOMIC_ACQUIRE);
		if (!bitset_is_eql(ts->sg_actual[p], sg_wanted)) {
			/* Our sched_group membership has changed */
			update_sg_add(ts, p, sg_wanted);
			update_sg_rem(ts, p, sg_wanted);
			ts->sg_actual[p] = sg_wanted;
		}
	}
}

/*******************************************************************************
 * Scheduler
 ******************************************************************************/

static inline void _schedule_release_atomic(sched_scalable_thread_state_t *ts)
{
#ifdef CONFIG_QSCHST_LOCK
	sched_update_deq_sc(ts->atomq, ts->dequeued, true);
	ODP_ASSERT(ts->atomq->qschst.cur_ticket != ts->ticket);
	ODP_ASSERT(ts->atomq->qschst.cur_ticket ==
			ts->atomq->qschst.nxt_ticket);
#else
	sched_update_deq(ts->atomq, ts->dequeued, true);
#endif
	ts->atomq = NULL;
	ts->ticket = TICKET_INVALID;
}

static inline void _schedule_release_ordered(sched_scalable_thread_state_t *ts)
{
	ts->out_of_order = false;
	rctx_release(ts->rctx);
	ts->rctx = NULL;
}

static void pktio_start(int pktio_idx,
			int num_in_queue,
			int in_queue_idx[],
			odp_queue_t odpq[])
{
	int i, rxq;
	queue_entry_t *qentry;
	sched_elem_t *elem;

	ODP_ASSERT(pktio_idx < ODP_CONFIG_PKTIO_ENTRIES);
	for (i = 0; i < num_in_queue; i++) {
		rxq = in_queue_idx[i];
		ODP_ASSERT(rxq < PKTIO_MAX_QUEUES);
		__atomic_fetch_add(&global->poll_count[pktio_idx], 1,
				   __ATOMIC_RELAXED);
		qentry = qentry_from_ext(odpq[i]);
		elem = &qentry->s.sched_elem;
		elem->cons_type |= FLAG_PKTIN; /* Set pktin queue flag */
		elem->pktio_idx = pktio_idx;
		elem->rx_queue = rxq;
		elem->xoffset = sched_pktin_add(elem->sched_grp,
				elem->sched_prio);
		ODP_ASSERT(elem->schedq != NULL);
		schedq_push(elem->schedq, elem);
	}
}

static void pktio_stop(sched_elem_t *elem)
{
	elem->cons_type &= ~FLAG_PKTIN; /* Clear pktin queue flag */
	sched_pktin_rem(elem->sched_grp);
	if (__atomic_sub_fetch(&global->poll_count[elem->pktio_idx],
			       1, __ATOMIC_RELAXED) == 0) {
		/* Call stop_finalize when all queues
		 * of the pktio have been removed */
		sched_cb_pktio_stop_finalize(elem->pktio_idx);
	}
}

static bool have_reorder_ctx(sched_scalable_thread_state_t *ts)
{
	if (odp_unlikely(bitset_is_null(ts->priv_rvec_free))) {
		ts->priv_rvec_free = atom_bitset_xchg(&ts->rvec_free, 0,
						      __ATOMIC_RELAXED);
		if (odp_unlikely(bitset_is_null(ts->priv_rvec_free))) {
			/* No free reorder contexts for this thread */
			return false;
		}
	}
	return true;
}

static inline bool is_pktin(sched_elem_t *elem)
{
	return (elem->cons_type & FLAG_PKTIN) != 0;
}

static inline bool is_atomic(sched_elem_t *elem)
{
	return elem->cons_type == (ODP_SCHED_SYNC_ATOMIC | FLAG_PKTIN);
}

static inline bool is_ordered(sched_elem_t *elem)
{
	return elem->cons_type == (ODP_SCHED_SYNC_ORDERED | FLAG_PKTIN);
}

static int poll_pktin(sched_elem_t *elem, odp_event_t ev[], int num_evts)
{
	sched_scalable_thread_state_t *ts = sched_ts;
	int num, i;
	/* For ordered queues only */
	reorder_context_t *rctx;
	reorder_window_t *rwin = NULL;
	uint32_t sn = 0;
	uint32_t idx;

	if (is_ordered(elem)) {
		/* Need reorder context and slot in reorder window */
		rwin = queue_get_rwin((queue_entry_t *)elem);
		ODP_ASSERT(rwin != NULL);
		if (odp_unlikely(!have_reorder_ctx(ts) ||
				 !rwin_reserve_sc(rwin, &sn))) {
			/* Put back queue on source schedq */
			schedq_push(ts->src_schedq, elem);
			return 0;
		}
		/* Slot in reorder window reserved! */
	}

	/* Try to dequeue events from the ingress queue itself */
	num = _odp_queue_deq_sc(elem, ev, num_evts);
	if (odp_likely(num > 0)) {
events_dequeued:
		if (is_atomic(elem)) {
			ts->atomq = elem; /* Remember */
			ts->dequeued += num;
			/* Don't push atomic queue on schedq */
		} else /* Parallel or ordered */ {
			if (is_ordered(elem)) {
				/* Find and initialise an unused reorder
				 * context. */
				idx = bitset_ffs(ts->priv_rvec_free) - 1;
				ts->priv_rvec_free =
					bitset_clr(ts->priv_rvec_free, idx);
				rctx = &ts->rvec[idx];
				rctx_init(rctx, idx, rwin, sn);
				/* Are we in-order or out-of-order? */
				ts->out_of_order = sn != rwin->hc.head;
				ts->rctx = rctx;
			}
			schedq_push(elem->schedq, elem);
		}
		return num;
	}

	/* Ingress queue empty => poll pktio RX queue */
	odp_event_t rx_evts[QUEUE_MULTI_MAX];
	int num_rx = sched_cb_pktin_poll_one(elem->pktio_idx,
			elem->rx_queue,
			rx_evts);
	if (odp_likely(num_rx > 0)) {
		num = num_rx < num_evts ? num_rx : num_evts;
		for (i = 0; i < num; i++) {
			/* Return events directly to caller */
			ev[i] = rx_evts[i];
		}
		if (num_rx > num) {
			/* Events remain, enqueue them */
			odp_buffer_hdr_t *bufs[QUEUE_MULTI_MAX];

			for (i = num; i < num_rx; i++)
				bufs[i] =
					(odp_buffer_hdr_t *)(void *)rx_evts[i];
			i = _odp_queue_enq_sp(elem, &bufs[num], num_rx - num);
			/* Enqueue must succeed as the queue was empty */
			ODP_ASSERT(i == num_rx - num);
		}
		goto events_dequeued;
	}
	/* No packets received, reset state and undo side effects */
	if (is_atomic(elem))
		ts->atomq = NULL;
	else if (is_ordered(elem))
		rwin_unreserve_sc(rwin, sn);

	if (odp_likely(num_rx == 0)) {
		/* RX queue empty, push it to pktin priority schedq */
		sched_queue_t *schedq = ts->src_schedq;
		/* Check if queue came from the designated schedq */
		if (schedq == elem->schedq) {
			/* Yes, add offset to the pktin priority level
			 * in order to get alternate schedq */
			schedq += elem->xoffset;
		}
		/* Else no, queue must have come from alternate schedq */
		schedq_push(schedq, elem);
	} else /* num_rx < 0 => pktio stopped or closed */ {
		/* Remove queue */
		pktio_stop(elem);
		/* Don't push queue to schedq */
	}

	ODP_ASSERT(ts->atomq == NULL);
	ODP_ASSERT(!ts->out_of_order);
	ODP_ASSERT(ts->rctx == NULL);
	return 0;
}

static int _schedule(odp_queue_t *from, odp_event_t ev[], int num_evts)
{
	sched_scalable_thread_state_t *ts;
	sched_elem_t *first;
	sched_elem_t *atomq;
	int num;
	uint32_t i;

	ts = sched_ts;
	atomq = ts->atomq;

	timer_run(1);

	/* Once an atomic queue has been scheduled to a thread, it will stay
	 * on that thread until empty or 'rotated' by WRR
	 */
	if (atomq != NULL && is_pktin(atomq)) {
		/* Atomic pktin queue */
		if (ts->dequeued < atomq->qschst.wrr_budget) {
			ODP_ASSERT(ts->src_schedq != NULL);
			num = poll_pktin(atomq, ev, num_evts);
			if (odp_likely(num != 0)) {
				if (from)
					*from = queue_get_handle(
							(queue_entry_t *)atomq);
				return num;
			}
		} else {
			/* WRR budget exhausted, move queue to end of schedq */
			schedq_push(atomq->schedq, atomq);
		}
		ts->atomq = NULL;
	} else if (atomq != NULL) {
		ODP_ASSERT(ts->ticket != TICKET_INVALID);
#ifdef CONFIG_QSCHST_LOCK
		LOCK(&atomq->qschlock);
#endif
dequeue_atomic:
		ODP_ASSERT(ts->ticket == atomq->qschst.cur_ticket);
		ODP_ASSERT(ts->ticket != atomq->qschst.nxt_ticket);
		/* Atomic queues can be dequeued without lock since this thread
		 * has the only reference to the atomic queue being processed.
		 */
		if (ts->dequeued < atomq->qschst.wrr_budget) {
			num = _odp_queue_deq_sc(atomq, ev, num_evts);
			if (odp_likely(num != 0)) {
#ifdef CONFIG_QSCHST_LOCK
				UNLOCK(&atomq->qschlock);
#endif
				ts->dequeued += num;
				/* Allow this thread to continue to 'own' this
				 * atomic queue until all events have been
				 * processed and the thread re-invokes the
				 * scheduler.
				 */
				if (from)
					*from = queue_get_handle(
							(queue_entry_t *)atomq);
				return num;
			}
		}
		/* Atomic queue was empty or interrupted by WRR, release it. */
		_schedule_release_atomic(ts);
#ifdef CONFIG_QSCHST_LOCK
		UNLOCK(&atomq->qschlock);
#endif
	}

	/* Check for and perform any scheduler group updates. */
	if (odp_unlikely(__atomic_load_n(&ts->sg_sem, __ATOMIC_RELAXED) != 0)) {
		(void)__atomic_load_n(&ts->sg_sem, __ATOMIC_ACQUIRE);
		ts->sg_sem = 0;
		update_sg_membership(ts);
	}

	/* Scan our schedq list from beginning to end */
	for (i = 0, first = NULL; i < ts->num_schedq; i++, first = NULL) {
		sched_queue_t *schedq = ts->schedq_list[i];
		sched_elem_t *elem;
restart_same:
		elem = schedq_peek(schedq);
		if (odp_unlikely(elem == NULL)) {
			/* Schedq empty, look at next one. */
			continue;
		}
		if (is_pktin(elem)) {
			/* Pktio ingress queue */
			if (first == NULL)
				first = elem;
			else if (elem == first) /* Wrapped around */
				continue; /* Go to next schedq */

			if (odp_unlikely(!schedq_cond_pop(schedq, elem)))
				goto restart_same;

			ts->src_schedq = schedq; /* Remember source schedq */
			num = poll_pktin(elem, ev, num_evts);
			if (odp_unlikely(num <= 0))
				goto restart_same;
			if (from)
				*from = queue_get_handle((queue_entry_t *)elem);
			return num;
		} else if (elem->cons_type == ODP_SCHED_SYNC_ATOMIC) {
			/* Dequeue element only if it is still at head
			 * of schedq.
			 */
			if (odp_unlikely(!schedq_cond_pop(schedq, elem))) {
				/* Queue not at head of schedq anymore, some
				 * other thread popped it.
				 */
				goto restart_same;
			}
			ts->atomq = elem;
			atomq = elem;
			ts->dequeued = 0;
#ifdef CONFIG_QSCHST_LOCK
			LOCK(&atomq->qschlock);
			ts->ticket = atomq->qschst.nxt_ticket++;
			ODP_ASSERT(atomq->qschst.cur_ticket == ts->ticket);
#else
			/* Dequeued atomic queue from the schedq, only we
			 * can process it and any qschst updates are our
			 * responsibility.
			 */
			/* The ticket taken below will signal producers */
			ts->ticket = __atomic_fetch_add(
				&atomq->qschst.nxt_ticket, 1, __ATOMIC_RELAXED);
			while (__atomic_load_n(
					&atomq->qschst.cur_ticket,
					__ATOMIC_ACQUIRE) != ts->ticket) {
				/* No need to use WFE, spinning here seems
				 * very infrequent.
				 */
				odp_cpu_pause();
			}
#endif
			goto dequeue_atomic;
		} else if (elem->cons_type == ODP_SCHED_SYNC_PARALLEL) {
#ifdef CONFIG_QSCHST_LOCK
			LOCK(&elem->qschlock);
			num = _odp_queue_deq_sc(elem, ev, num_evts);
			if (odp_likely(num != 0)) {
				sched_update_deq_sc(elem, num, false);
				UNLOCK(&elem->qschlock);
				if (from)
					*from =
					queue_get_handle((queue_entry_t *)elem);
				return num;
			}
			UNLOCK(&elem->qschlock);
#else
			num = _odp_queue_deq_mc(elem, ev, num_evts);
			if (odp_likely(num != 0)) {
				sched_update_deq(elem, num, false);
				if (from)
					*from =
					queue_get_handle((queue_entry_t *)elem);
				return num;
			}
#endif
		} else if (elem->cons_type == ODP_SCHED_SYNC_ORDERED) {
			reorder_window_t *rwin;
			reorder_context_t *rctx;
			uint32_t sn;
			uint32_t idx;

			/* The ordered queue has a reorder window so requires
			 * order restoration. We must use a reorder context to
			 * collect all outgoing events. Ensure there is at least
			 * one available reorder context.
			 */
			if (odp_unlikely(!have_reorder_ctx(ts)))
				continue;

			/* rwin_reserve and odp_queue_deq must be atomic or
			 * there will be a potential race condition.
			 * Allocate a slot in the reorder window.
			 */
			rwin = queue_get_rwin((queue_entry_t *)elem);
			ODP_ASSERT(rwin != NULL);
			if (odp_unlikely(!rwin_reserve(rwin, &sn))) {
				/* Reorder window full */
				/* Look at next schedq, find other queue */
				continue;
			}
			/* Wait for our turn to dequeue */
			if (odp_unlikely(__atomic_load_n(&rwin->turn,
							 __ATOMIC_ACQUIRE)
			    != sn)) {
				sevl();
				while (wfe() &&
				       monitor32(&rwin->turn, __ATOMIC_ACQUIRE)
						!= sn)
					doze();
			}
#ifdef CONFIG_QSCHST_LOCK
			LOCK(&elem->qschlock);
#endif
			num = _odp_queue_deq_sc(elem, ev, num_evts);
			/* Wait for prod_read write in _odp_queue_dequeue_sc()
			 * to complete before we signal the next consumer
			 */
			atomic_store_release(&rwin->turn, sn + 1,
					     /*readonly=*/false);
			/* Find and initialise an unused reorder context. */
			idx = bitset_ffs(ts->priv_rvec_free) - 1;
			ts->priv_rvec_free =
				bitset_clr(ts->priv_rvec_free, idx);
			rctx = &ts->rvec[idx];
			/* Need to initialise reorder context or we can't
			 * release it later.
			 */
			rctx_init(rctx, idx, rwin, sn);

			/* Was dequeue successful? */
			if (odp_likely(num != 0)) {
				/* Perform scheduler related updates */
#ifdef CONFIG_QSCHST_LOCK
				sched_update_deq_sc(elem, num,
						    /*atomic=*/false);
				UNLOCK(&elem->qschlock);
#else
				sched_update_deq(elem, num, /*atomic=*/false);
#endif

				/* Are we in-order or out-of-order? */
				ts->out_of_order = sn != rwin->hc.head;

				ts->rctx = rctx;
				if (from)
					*from = queue_get_handle(
						(queue_entry_t *)elem);
				return num;
			}
#ifdef CONFIG_QSCHST_LOCK
			UNLOCK(&elem->qschlock);
#endif
			/* Since a slot was reserved in the reorder window,
			 * the reorder context needs to be released and
			 * inserted into the reorder window.
			 */
			rctx_release(rctx);
			ODP_ASSERT(ts->rctx == NULL);
		}
		/* Dequeue from parallel/ordered queue failed
		 * Check if we have a queue at the head of the schedq that needs
		 * to be popped
		 */
		if (odp_unlikely(__atomic_load_n(&elem->pop_deficit,
						 __ATOMIC_RELAXED) != 0)) {
#ifdef CONFIG_QSCHST_LOCK
			LOCK(&elem->qschlock);
			sched_update_popd_sc(elem);
			UNLOCK(&elem->qschlock);
#else
			sched_update_popd(elem);
#endif
		}
	}

	return 0;
}

/******************************************************************************/

static void schedule_order_lock(uint32_t lock_index)
{
	struct reorder_context *rctx = sched_ts->rctx;

	if (odp_unlikely(rctx == NULL ||
			 rctx->rwin == NULL ||
			 lock_index >= rctx->rwin->lock_count)) {
		ODP_ERR("Invalid call to odp_schedule_order_lock\n");
		return;
	}
	if (odp_unlikely(__atomic_load_n(&rctx->rwin->olock[lock_index],
					 __ATOMIC_ACQUIRE) != rctx->sn)) {
		sevl();
		while (wfe() &&
		       monitor32(&rctx->rwin->olock[lock_index],
				 __ATOMIC_ACQUIRE) != rctx->sn)
			doze();
	}
}

static void schedule_order_unlock(uint32_t lock_index)
{
	struct reorder_context *rctx;

	rctx = sched_ts->rctx;
	if (odp_unlikely(rctx == NULL ||
			 rctx->rwin == NULL ||
			 lock_index >= rctx->rwin->lock_count ||
			 rctx->rwin->olock[lock_index] != rctx->sn)) {
		ODP_ERR("Invalid call to odp_schedule_order_unlock\n");
		return;
	}
	atomic_store_release(&rctx->rwin->olock[lock_index],
			     rctx->sn + 1,
			     /*readonly=*/false);
	rctx->olock_flags |= 1U << lock_index;
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

static void schedule_release_atomic(void)
{
	sched_scalable_thread_state_t *ts;

	ts = sched_ts;
	if (odp_likely(ts->atomq != NULL)) {
#ifdef CONFIG_QSCHST_LOCK
		sched_elem_t *atomq;

		atomq = ts->atomq;
		LOCK(&atomq->qschlock);
#endif
		_schedule_release_atomic(ts);
#ifdef CONFIG_QSCHST_LOCK
		UNLOCK(&atomq->qschlock);
#endif
	}
}

static void schedule_release_ordered(void)
{
	sched_scalable_thread_state_t *ts;

	ts = sched_ts;
	if (ts->rctx != NULL)
		_schedule_release_ordered(ts);
}

static int schedule_multi(odp_queue_t *from, uint64_t wait, odp_event_t ev[],
			  int num)
{
	sched_scalable_thread_state_t *ts;
	int n;
	odp_time_t start;
	odp_time_t delta;
	odp_time_t deadline;

	ts = sched_ts;
	/* Release any previous reorder context. */
	if (ts->rctx != NULL)
		_schedule_release_ordered(ts);

	if (odp_unlikely(ts->pause)) {
		if (ts->atomq != NULL) {
#ifdef CONFIG_QSCHST_LOCK
			sched_elem_t *atomq;

			atomq = ts->atomq;
			LOCK(&atomq->qschlock);
#endif
			_schedule_release_atomic(ts);
#ifdef CONFIG_QSCHST_LOCK
			UNLOCK(&atomq->qschlock);
#endif
		}
		return 0;
	}

	if (wait == ODP_SCHED_NO_WAIT)
		return _schedule(from, ev, num);

	if (wait == ODP_SCHED_WAIT) {
		for (;;) {
			n = _schedule(from, ev, num);
			if (odp_likely(n  > 0))
				return n;
		}
	}

	start = odp_time_local();

	n = _schedule(from, ev, num);
	if (odp_likely(n > 0))
		return n;

	delta = odp_time_local_from_ns(wait);
	deadline = odp_time_sum(start, delta);

	while (odp_time_cmp(deadline, odp_time_local()) > 0) {
		n = _schedule(from, ev, num);
		if (odp_likely(n > 0))
			return n;
	}

	return 0;
}

static odp_event_t schedule(odp_queue_t *from, uint64_t wait)
{
	odp_event_t ev = ODP_EVENT_INVALID;
	const int num = 1;
	sched_scalable_thread_state_t *ts;
	int n;
	odp_time_t start;
	odp_time_t delta;
	odp_time_t deadline;

	ts = sched_ts;
	/* Release any previous reorder context. */
	if (ts->rctx != NULL)
		_schedule_release_ordered(ts);

	if (odp_unlikely(ts->pause)) {
		if (ts->atomq != NULL) {
#ifdef CONFIG_QSCHST_LOCK
			sched_elem_t *atomq;

			atomq = ts->atomq;
			LOCK(&atomq->qschlock);
#endif
			_schedule_release_atomic(ts);
#ifdef CONFIG_QSCHST_LOCK
			UNLOCK(&atomq->qschlock);
#endif
		}
		return ev;
	}

	if (wait == ODP_SCHED_NO_WAIT) {
		(void)_schedule(from, &ev, num);
		return ev;
	}

	if (wait == ODP_SCHED_WAIT) {
		for (;;) {
			n = _schedule(from, &ev, num);
			if (odp_likely(n > 0))
				return ev;
		}
	}

	start = odp_time_local();

	n = _schedule(from, &ev, num);
	if (odp_likely(n > 0))
		return ev;

	delta = odp_time_local_from_ns(wait);
	deadline = odp_time_sum(start, delta);

	while (odp_time_cmp(deadline, odp_time_local()) > 0) {
		n = _schedule(from, &ev, num);
		if (odp_likely(n > 0))
			return ev;
	}

	return ev;
}

static int schedule_multi_wait(odp_queue_t *from, odp_event_t events[],
			       int max_num)
{
	return schedule_multi(from, ODP_SCHED_WAIT, events, max_num);
}

static int schedule_multi_no_wait(odp_queue_t *from, odp_event_t events[],
				  int max_num)
{
	return schedule_multi(from, ODP_SCHED_NO_WAIT, events, max_num);
}

static void schedule_pause(void)
{
	sched_ts->pause = true;
}

static void schedule_resume(void)
{
	sched_ts->pause = false;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static int schedule_num_prio(void)
{
	return ODP_SCHED_PRIO_NUM - 1; /* Discount the pktin priority level */
}

static int schedule_min_prio(void)
{
	return 0;
}

static int schedule_max_prio(void)
{
	return schedule_num_prio() - 1;
}

static int schedule_default_prio(void)
{
	return schedule_max_prio() / 2;
}

static int schedule_group_update(sched_group_t *sg,
				 uint32_t sgi,
				 const odp_thrmask_t *mask,
				 int join_leave)
{
	int thr;
	uint32_t p;

	/* Internal function, do not validate inputs */

	/* Notify relevant threads about the change */
	thr = odp_thrmask_first(mask);
	while (0 <= thr) {
		/* Add thread to scheduler group's wanted thread mask */
		if (join_leave == SCHED_GROUP_JOIN)
			atom_bitset_set(&sg->thr_wanted, thr, __ATOMIC_RELAXED);
		else
			atom_bitset_clr(&sg->thr_wanted, thr, __ATOMIC_RELAXED);
		for (p = 0; p < ODP_SCHED_PRIO_NUM; p++) {
			if (sg->xcount[p] != 0) {
				sched_scalable_thread_state_t *state;

				state = &global->thread_state[thr];

				/* This priority level has ODP queues
				 * Notify the thread about membership in
				 * this group/priority
				 */
				if (join_leave == SCHED_GROUP_JOIN)
					atom_bitset_set(&state->sg_wanted[p],
							sgi, __ATOMIC_RELEASE);
				else
					atom_bitset_clr(&state->sg_wanted[p],
							sgi, __ATOMIC_RELEASE);
				__atomic_store_n(&state->sg_sem, 1,
						 __ATOMIC_RELEASE);
			}
		}
		thr = odp_thrmask_next(mask, thr);
	}

	return 0;
}

static int _schedule_group_thrmask(sched_group_t *sg, odp_thrmask_t *mask)
{
	bitset_t bs;
	uint32_t bit;

	/* Internal function, do not validate inputs */

	odp_thrmask_zero(mask);
	bs = sg->thr_wanted;
	while (!bitset_is_null(bs)) {
		bit = bitset_ffs(bs) - 1;
		bs = bitset_clr(bs, bit);
		odp_thrmask_set(mask, bit);
	}

	return 0;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *mask)
{
	uint32_t sgi;
	sched_group_mask_t free;
	uint32_t xfactor;
	sched_group_t *sg;
	uint32_t p;
	uint32_t x;
	uint32_t size;

	/* Validate inputs */
	if (mask == NULL)
		ODP_ABORT("mask is NULL\n");

	odp_spinlock_lock(&global->sched_grp_lock);

	/* Allocate a scheduler group */
	free = atom_bitset_load(&global->sg_free, __ATOMIC_RELAXED);
	do {
		/* All sched_groups in use */
		if (bitset_is_null(free))
			goto no_free_sched_group;

		sgi = bitset_ffs(free) - 1;
		/* All sched_groups in use */
		if (sgi >= MAX_SCHED_GROUP)
			goto no_free_sched_group;
	} while (!atom_bitset_cmpxchg(&global->sg_free,
				      &free,
				      bitset_clr(free, sgi),
				      true,
				      __ATOMIC_ACQUIRE,
				      __ATOMIC_ACQUIRE));

	/* Compute xfactor (spread factor) from the number of threads
	 * present in the thread mask. Preferable this would be an
	 * explicit parameter.
	 */
	xfactor = odp_thrmask_count(mask);
	if (xfactor < 1)
		xfactor = CONFIG_DEFAULT_XFACTOR;

	size = sizeof(sched_group_t) +
	       (ODP_SCHED_PRIO_NUM * xfactor - 1) * sizeof(sched_queue_t);
	sg = (sched_group_t *)shm_pool_alloc_align(global->sched_shm_pool,
						   size);
	if (sg == NULL)
		goto shm_pool_alloc_failed;

	strncpy(sg->name, name ? name : "", ODP_SCHED_GROUP_NAME_LEN - 1);
	global->sg_vec[sgi] = sg;
	memset(sg->thr_actual, 0, sizeof(sg->thr_actual));
	sg->thr_wanted = bitset_null();
	sg->xfactor = xfactor;
	for (p = 0; p < ODP_SCHED_PRIO_NUM; p++) {
		sg->xcount[p] = 0;
		for (x = 0; x < xfactor; x++)
			schedq_init(&sg->schedq[p * xfactor + x], p);
	}
	if (odp_thrmask_count(mask) != 0)
		schedule_group_update(sg, sgi, mask, SCHED_GROUP_JOIN);

	odp_spinlock_unlock(&global->sched_grp_lock);

	return (odp_schedule_group_t)(sgi);

shm_pool_alloc_failed:
	/* Free the allocated group index */
	atom_bitset_set(&global->sg_free, sgi, __ATOMIC_RELAXED);

no_free_sched_group:
	odp_spinlock_unlock(&global->sched_grp_lock);

	return ODP_SCHED_GROUP_INVALID;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	uint32_t sgi;
	sched_group_t *sg;
	uint32_t p;
	int ret = 0;

	/* Validate inputs */
	if (group < 0 || group >= (odp_schedule_group_t)MAX_SCHED_GROUP) {
		ret = -1;
		goto invalid_group;
	}

	if (sched_ts &&
	    odp_unlikely(__atomic_load_n(&sched_ts->sg_sem,
					 __ATOMIC_RELAXED) != 0)) {
		(void)__atomic_load_n(&sched_ts->sg_sem,
				      __ATOMIC_ACQUIRE);
		sched_ts->sg_sem = 0;
		update_sg_membership(sched_ts);
	}
	odp_spinlock_lock(&global->sched_grp_lock);

	sgi = (uint32_t)group;
	if (bitset_is_set(global->sg_free, sgi)) {
		ret = -1;
		goto group_not_found;
	}

	sg = global->sg_vec[sgi];
	/* First ensure all threads have processed group_join/group_leave
	 * requests.
	 */
	for (p = 0; p < ODP_SCHED_PRIO_NUM; p++) {
		if (sg->xcount[p] != 0) {
			bitset_t wanted = atom_bitset_load(
				&sg->thr_wanted, __ATOMIC_RELAXED);

			sevl();
			while (wfe() &&
			       !bitset_is_eql(wanted,
					      bitset_monitor(&sg->thr_actual[p],
							     __ATOMIC_RELAXED)))
				doze();
		}
		/* Else ignore because no ODP queues on this prio */
	}

	/* Check if all threads/queues have left the group */
	for (p = 0; p < ODP_SCHED_PRIO_NUM; p++) {
		if (!bitset_is_null(sg->thr_actual[p])) {
			ODP_ERR("Group has threads\n");
			ret = -1;
			goto thrd_q_present_in_group;
		}
		if (p != ODP_SCHED_PRIO_PKTIN && sg->xcount[p] != 0) {
			ODP_ERR("Group has queues\n");
			ret = -1;
			goto thrd_q_present_in_group;
		}
	}

	_odp_ishm_pool_free(global->sched_shm_pool, sg);
	global->sg_vec[sgi] = NULL;
	atom_bitset_set(&global->sg_free, sgi, __ATOMIC_RELEASE);

	odp_spinlock_unlock(&global->sched_grp_lock);

	return ret;

thrd_q_present_in_group:

group_not_found:
	odp_spinlock_unlock(&global->sched_grp_lock);

invalid_group:

	return ret;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	uint32_t sgi;
	odp_schedule_group_t group;

	/* Validate inputs */
	if (name == NULL)
		ODP_ABORT("name or mask is NULL\n");

	group = ODP_SCHED_GROUP_INVALID;

	odp_spinlock_lock(&global->sched_grp_lock);

	/* Scan through the schedule group array */
	for (sgi = 0; sgi < MAX_SCHED_GROUP; sgi++) {
		if ((global->sg_vec[sgi] != NULL) &&
		    (strncmp(name, global->sg_vec[sgi]->name,
			     ODP_SCHED_GROUP_NAME_LEN) == 0)) {
			group = (odp_schedule_group_t)sgi;
			break;
		}
	}

	odp_spinlock_unlock(&global->sched_grp_lock);

	return group;
}

static int schedule_group_join(odp_schedule_group_t group,
			       const odp_thrmask_t *mask)
{
	uint32_t sgi;
	sched_group_t *sg;
	int ret;

	/* Validate inputs */
	if (group < 0 || group >= ((odp_schedule_group_t)MAX_SCHED_GROUP))
		return -1;

	if (mask == NULL)
		ODP_ABORT("name or mask is NULL\n");

	odp_spinlock_lock(&global->sched_grp_lock);

	sgi = (uint32_t)group;
	if (bitset_is_set(global->sg_free, sgi)) {
		odp_spinlock_unlock(&global->sched_grp_lock);
		return -1;
	}

	sg = global->sg_vec[sgi];
	ret = schedule_group_update(sg, sgi, mask, SCHED_GROUP_JOIN);

	odp_spinlock_unlock(&global->sched_grp_lock);

	return ret;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *mask)
{
	uint32_t sgi;
	sched_group_t *sg;
	int ret = 0;

	/* Validate inputs */
	if (group < 0 || group >= (odp_schedule_group_t)MAX_SCHED_GROUP) {
		ret = -1;
		goto invalid_group;
	}

	if (mask == NULL)
		ODP_ABORT("name or mask is NULL\n");

	odp_spinlock_lock(&global->sched_grp_lock);

	sgi = (uint32_t)group;
	if (bitset_is_set(global->sg_free, sgi)) {
		ret = -1;
		goto group_not_found;
	}

	sg = global->sg_vec[sgi];

	ret = schedule_group_update(sg, sgi, mask, SCHED_GROUP_LEAVE);

	odp_spinlock_unlock(&global->sched_grp_lock);

	return ret;

group_not_found:
	odp_spinlock_unlock(&global->sched_grp_lock);

invalid_group:
	return ret;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *mask)
{
	uint32_t sgi;
	sched_group_t *sg;
	int ret = 0;

	/* Validate inputs */
	if (group < 0 || group >= ((odp_schedule_group_t)MAX_SCHED_GROUP)) {
		ret = -1;
		goto invalid_group;
	}

	if (mask == NULL)
		ODP_ABORT("name or mask is NULL\n");

	odp_spinlock_lock(&global->sched_grp_lock);

	sgi = (uint32_t)group;
	if (bitset_is_set(global->sg_free, sgi)) {
		ret = -1;
		goto group_not_found;
	}

	sg = global->sg_vec[sgi];
	ret = _schedule_group_thrmask(sg, mask);

	odp_spinlock_unlock(&global->sched_grp_lock);

	return ret;

group_not_found:
	odp_spinlock_unlock(&global->sched_grp_lock);

invalid_group:
	return ret;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	uint32_t sgi;
	sched_group_t *sg;
	int ret = 0;

	/* Validate inputs */
	if (group < 0 || group >= ((odp_schedule_group_t)MAX_SCHED_GROUP)) {
		ret = -1;
		goto invalid_group;
	}

	if (info == NULL)
		ODP_ABORT("name or mask is NULL\n");

	odp_spinlock_lock(&global->sched_grp_lock);

	sgi = (uint32_t)group;
	if (bitset_is_set(global->sg_free, sgi)) {
		ret = -1;
		goto group_not_found;
	}

	sg = global->sg_vec[sgi];

	ret = _schedule_group_thrmask(sg, &info->thrmask);

	info->name = sg->name;

	odp_spinlock_unlock(&global->sched_grp_lock);

	return ret;

group_not_found:
	odp_spinlock_unlock(&global->sched_grp_lock);

invalid_group:
	return ret;
}

static int schedule_init_global(void)
{
	odp_thrmask_t mask;
	odp_schedule_group_t tmp_all;
	odp_schedule_group_t tmp_wrkr;
	odp_schedule_group_t tmp_ctrl;
	odp_shm_t shm;
	_odp_ishm_pool_t *pool;
	uint32_t bits;
	uint32_t pool_size;
	uint64_t min_alloc;
	uint64_t max_alloc;

	shm = odp_shm_reserve("_odp_sched_scalable",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	memset(global, 0, sizeof(sched_global_t));
	global->shm = shm;

	/* Add storage required for sched groups. Assume worst case
	 * xfactor of MAXTHREADS.
	 */
	pool_size = (sizeof(sched_group_t) +
		     (ODP_SCHED_PRIO_NUM * MAXTHREADS - 1) *
		     sizeof(sched_queue_t)) * MAX_SCHED_GROUP;
	/* Choose min_alloc and max_alloc such that slab allocator
	 * is selected.
	 */
	min_alloc = sizeof(sched_group_t) +
		    (ODP_SCHED_PRIO_NUM * MAXTHREADS - 1) *
		    sizeof(sched_queue_t);
	max_alloc = min_alloc;
	pool = _odp_ishm_pool_create("sched_shm_pool", pool_size,
				     min_alloc, max_alloc,
				     _ODP_ISHM_SINGLE_VA);
	if (pool == NULL) {
		ODP_ERR("Failed to allocate shared memory pool "
			"for sched\n");
		goto failed_sched_shm_pool_create;
	}
	global->sched_shm_pool = pool;

	odp_spinlock_init(&global->sched_grp_lock);

	bits = MAX_SCHED_GROUP;
	if (MAX_SCHED_GROUP == sizeof(global->sg_free) * CHAR_BIT)
		global->sg_free = ~0;
	else
		global->sg_free = (1 << bits) - 1;

	for (uint32_t i = 0; i < MAX_SCHED_GROUP; i++)
		global->sg_vec[i] = NULL;
	for (uint32_t i = 0; i < MAXTHREADS; i++) {
		global->thread_state[i].sg_sem = 0;
		for (uint32_t j = 0; j < ODP_SCHED_PRIO_NUM; j++)
			global->thread_state[i].sg_wanted[j] = bitset_null();
	}

	/* Create sched groups for default GROUP_ALL, GROUP_WORKER and
	 * GROUP_CONTROL groups.
	 */
	odp_thrmask_zero(&mask);
	tmp_all = odp_schedule_group_create("__group_all", &mask);
	if (tmp_all != ODP_SCHED_GROUP_ALL) {
		ODP_ERR("Could not create ODP_SCHED_GROUP_ALL()\n");
		goto failed_create_group_all;
	}

	tmp_wrkr = odp_schedule_group_create("__group_worker", &mask);
	if (tmp_wrkr != ODP_SCHED_GROUP_WORKER) {
		ODP_ERR("Could not create ODP_SCHED_GROUP_WORKER()\n");
		goto failed_create_group_worker;
	}

	tmp_ctrl = odp_schedule_group_create("__group_control", &mask);
	if (tmp_ctrl != ODP_SCHED_GROUP_CONTROL) {
		ODP_ERR("Could not create ODP_SCHED_GROUP_CONTROL()\n");
		goto failed_create_group_control;
	}

	return 0;

failed_create_group_control:
	if (tmp_ctrl != ODP_SCHED_GROUP_INVALID)
		odp_schedule_group_destroy(ODP_SCHED_GROUP_CONTROL);

failed_create_group_worker:
	if (tmp_wrkr != ODP_SCHED_GROUP_INVALID)
		odp_schedule_group_destroy(ODP_SCHED_GROUP_WORKER);

failed_create_group_all:
	if (tmp_all != ODP_SCHED_GROUP_INVALID)
		odp_schedule_group_destroy(ODP_SCHED_GROUP_ALL);

failed_sched_shm_pool_create:

	return -1;
}

static int schedule_term_global(void)
{
	/* Destroy sched groups for default GROUP_ALL, GROUP_WORKER and
	 * GROUP_CONTROL groups.
	 */
	if (odp_schedule_group_destroy(ODP_SCHED_GROUP_ALL) != 0)
		ODP_ERR("Failed to destroy ODP_SCHED_GROUP_ALL\n");
	if (odp_schedule_group_destroy(ODP_SCHED_GROUP_WORKER) != 0)
		ODP_ERR("Failed to destroy ODP_SCHED_GROUP_WORKER\n");
	if (odp_schedule_group_destroy(ODP_SCHED_GROUP_CONTROL) != 0)
		ODP_ERR("Failed to destroy ODP_SCHED_GROUP_CONTROL\n");

	_odp_ishm_pool_destroy(global->sched_shm_pool);

	if (odp_shm_free(global->shm)) {
		ODP_ERR("Shm free failed for scalable scheduler");
		return -1;
	}

	return 0;
}

static int schedule_init_local(void)
{
	int thr_id;
	odp_thread_type_t thr_type;
	odp_thrmask_t mask;

	thr_id = odp_thread_id();
	if (thread_state_init(thr_id))
		goto failed_to_init_ts;

	/* Add this thread to default schedule groups */
	thr_type = odp_thread_type();
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr_id);

	if (odp_schedule_group_join(ODP_SCHED_GROUP_ALL, &mask) != 0) {
		ODP_ERR("Failed to join ODP_SCHED_GROUP_ALL\n");
		goto failed_to_join_grp_all;
	}
	if (thr_type == ODP_THREAD_CONTROL) {
		if (odp_schedule_group_join(ODP_SCHED_GROUP_CONTROL,
					    &mask) != 0) {
			ODP_ERR("Failed to join ODP_SCHED_GROUP_CONTROL\n");
			goto failed_to_join_grp_ctrl;
		}
	} else {
		if (odp_schedule_group_join(ODP_SCHED_GROUP_WORKER,
					    &mask) != 0) {
			ODP_ERR("Failed to join ODP_SCHED_GROUP_WORKER\n");
			goto failed_to_join_grp_wrkr;
		}
	}

	return 0;

failed_to_join_grp_wrkr:

failed_to_join_grp_ctrl:
	odp_schedule_group_leave(ODP_SCHED_GROUP_ALL, &mask);

failed_to_join_grp_all:
failed_to_init_ts:

	return -1;
}

static int schedule_term_local(void)
{
	int thr_id;
	odp_thread_type_t thr_type;
	odp_thrmask_t mask;
	int rc = 0;

	/* Remove this thread from default schedule groups */
	thr_id = odp_thread_id();
	thr_type = odp_thread_type();
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr_id);

	if (odp_schedule_group_leave(ODP_SCHED_GROUP_ALL, &mask) != 0)
		ODP_ERR("Failed to leave ODP_SCHED_GROUP_ALL\n");
	if (thr_type == ODP_THREAD_CONTROL) {
		if (odp_schedule_group_leave(ODP_SCHED_GROUP_CONTROL,
					     &mask) != 0)
			ODP_ERR("Failed to leave ODP_SCHED_GROUP_CONTROL\n");
	} else {
		if (odp_schedule_group_leave(ODP_SCHED_GROUP_WORKER,
					     &mask) != 0)
			ODP_ERR("Failed to leave ODP_SCHED_GROUP_WORKER\n");
	}

	update_sg_membership(sched_ts);

	/* Check if the thread is still part of any groups */
	if (sched_ts->num_schedq != 0) {
		ODP_ERR("Thread %d still part of scheduler group(s)\n",
			sched_ts->tidx);
		rc = -1;
	}

	return rc;
}

static void schedule_config_init(odp_schedule_config_t *config)
{
	config->num_queues = CONFIG_MAX_SCHED_QUEUES;
	config->queue_size = 0; /* FIXME ? */
}

static int schedule_config(const odp_schedule_config_t *config)
{
	(void)config;

	return 0;
}

static int num_grps(void)
{
	return MAX_SCHED_GROUP;
}

/*
 * Stubs for internal scheduler abstraction layer due to absence of NULL
 * checking before calling the function pointer.
 */

static int thr_add(odp_schedule_group_t group, int thr)
{
	/* This function is a schedule_init_local duplicate. */
	(void)group;
	(void)thr;
	return 0;
}

static int thr_rem(odp_schedule_group_t group, int thr)
{
	/* This function is a schedule_term_local duplicate. */
	(void)group;
	(void)thr;
	return 0;
}

static int create_queue(uint32_t queue_index,
			const odp_schedule_param_t *sched_param)
{
	/* Not used in scalable scheduler. */
	(void)queue_index;
	(void)sched_param;
	return 0;
}

static void destroy_queue(uint32_t queue_index)
{
	/* Not used in scalable scheduler. */
	(void)queue_index;
}

static int sched_queue(uint32_t queue_index)
{
	/* Not used in scalable scheduler. */
	(void)queue_index;
	return 0;
}

static int ord_enq_multi(odp_queue_t handle, void *buf_hdr[], int num,
			 int *ret)

{
	queue_entry_t *queue;
	sched_scalable_thread_state_t *ts;
	int actual;

	ts = sched_ts;
	queue = qentry_from_int(handle);
	if (ts && odp_unlikely(ts->out_of_order) &&
	    (queue->s.param.order == ODP_QUEUE_ORDER_KEEP)) {
		actual = rctx_save(queue, (odp_buffer_hdr_t **)buf_hdr, num);
		*ret = actual;
		return 1;
	}
	return 0;
}

static void schedule_prefetch(int num)
{
	(void)num;
}

/* Wait until we are in-order (when processing an ordered queue)
 * Note: this function may be called also when processing other queue types
 */
static void order_lock(void)
{
	sched_scalable_thread_state_t *ts;
	reorder_window_t *rwin;
	uint32_t sn;

	ts = sched_ts;
	if (odp_unlikely(ts->out_of_order)) {
		/* We are processing ordered queue and are currently
		 * out-of-order.
		 * We are in-order when our reorder window slot number (sn)
		 * equals the head of the reorder window.
		 */
		ODP_ASSERT(ts->rctx != NULL);
		rwin = ts->rctx->rwin;
		sn = ts->rctx->sn;
		sevl();
		/* Use acquire ordering to be on the safe side even if
		 * this isn't an acquire/release situation (aka lock).
		 */
		while (wfe() &&
		       monitor32(&rwin->hc.head, __ATOMIC_ACQUIRE) != sn)
			doze();
	}
}

/* This function is unnecessary.
 * The next thread becomes in-order when we release our reorder context
 * (i.e. when odp_schedule() is called again.
 */
static void order_unlock(void)
{
}

static uint32_t schedule_max_ordered_locks(void)
{
	return CONFIG_QUEUE_MAX_ORD_LOCKS;
}

static int schedule_capability(odp_schedule_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_schedule_capability_t));

	capa->max_ordered_locks = schedule_max_ordered_locks();
	capa->max_groups = num_grps();
	capa->max_prios = schedule_num_prio();
	capa->max_queues = CONFIG_MAX_SCHED_QUEUES;
	capa->max_queue_size = 0;

	return 0;
}

const schedule_fn_t schedule_scalable_fn = {
	.pktio_start	= pktio_start,
	.thr_add	= thr_add,
	.thr_rem	= thr_rem,
	.num_grps	= num_grps,
	.create_queue	= create_queue,
	.destroy_queue	= destroy_queue,
	.sched_queue	= sched_queue,
	.ord_enq_multi	= ord_enq_multi,
	.init_global	= schedule_init_global,
	.term_global	= schedule_term_global,
	.init_local	= schedule_init_local,
	.term_local	= schedule_term_local,
	.order_lock	= order_lock,
	.order_unlock	= order_unlock,
	.max_ordered_locks = schedule_max_ordered_locks,
};

const schedule_api_t schedule_scalable_api = {
	.schedule_wait_time		= schedule_wait_time,
	.schedule_capability            = schedule_capability,
	.schedule_config_init		= schedule_config_init,
	.schedule_config		= schedule_config,
	.schedule			= schedule,
	.schedule_multi			= schedule_multi,
	.schedule_multi_wait            = schedule_multi_wait,
	.schedule_multi_no_wait         = schedule_multi_no_wait,
	.schedule_pause			= schedule_pause,
	.schedule_resume		= schedule_resume,
	.schedule_release_atomic	= schedule_release_atomic,
	.schedule_release_ordered	= schedule_release_ordered,
	.schedule_prefetch		= schedule_prefetch,
	.schedule_min_prio		= schedule_min_prio,
	.schedule_max_prio		= schedule_max_prio,
	.schedule_default_prio		= schedule_default_prio,
	.schedule_num_prio		= schedule_num_prio,
	.schedule_group_create		= schedule_group_create,
	.schedule_group_destroy		= schedule_group_destroy,
	.schedule_group_lookup		= schedule_group_lookup,
	.schedule_group_join		= schedule_group_join,
	.schedule_group_leave		= schedule_group_leave,
	.schedule_group_thrmask		= schedule_group_thrmask,
	.schedule_group_info		= schedule_group_info,
	.schedule_order_lock		= schedule_order_lock,
	.schedule_order_unlock		= schedule_order_unlock,
	.schedule_order_unlock_lock	= schedule_order_unlock_lock,
	.schedule_order_lock_start	= schedule_order_lock_start,
	.schedule_order_lock_wait	= schedule_order_lock_wait
};
