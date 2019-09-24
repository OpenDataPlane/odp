/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp/api/shared_memory.h>
#include <odp/api/cpu.h>
#include <odp/api/plat/cpu_inlines.h>
#include <odp_queue_scalable_internal.h>
#include <odp_schedule_if.h>
#include <odp_bitset.h>

#include <string.h>

extern __thread sched_scalable_thread_state_t *sched_ts;

reorder_window_t *rwin_alloc(_odp_ishm_pool_t *pool, unsigned lock_count)
{
	reorder_window_t *rwin;
	uint32_t i;

	rwin = (reorder_window_t *)
	       shm_pool_alloc_align(pool, sizeof(reorder_window_t));
	if (rwin == NULL)
		return NULL;

	rwin->hc.head = 0;
	rwin->hc.chgi = 0;
	rwin->winmask = RWIN_SIZE - 1;
	rwin->tail = 0;
	rwin->turn = 0;
	rwin->lock_count = (uint16_t)lock_count;
	memset(rwin->olock, 0, sizeof(rwin->olock));
	for (i = 0; i < RWIN_SIZE; i++)
		rwin->ring[i] = NULL;

	return rwin;
}

int rwin_free(_odp_ishm_pool_t *pool, reorder_window_t *rwin)
{
	return _odp_ishm_pool_free(pool, rwin);
}

bool rwin_reserve(reorder_window_t *rwin, uint32_t *sn)
{
	uint32_t head;
	uint32_t oldt;
	uint32_t newt;
	uint32_t winmask;

	/* Read head and tail separately */
	oldt = rwin->tail;
	winmask = rwin->winmask;
	do {
		/* Need __atomic_load to avoid compiler reordering */
		head = __atomic_load_n(&rwin->hc.head, __ATOMIC_RELAXED);
		if (odp_unlikely(oldt - head >= winmask))
			return false;

		newt = oldt + 1;
	} while (!__atomic_compare_exchange(&rwin->tail,
					    &oldt,
					    &newt,
					    true,
					    __ATOMIC_RELAXED,
					    __ATOMIC_RELAXED));
	*sn = oldt;

	return true;
}

bool rwin_reserve_sc(reorder_window_t *rwin, uint32_t *sn)
{
	uint32_t head;
	uint32_t oldt;
	uint32_t newt;
	uint32_t winmask;

	/* Read head and tail separately */
	oldt = rwin->tail;
	winmask = rwin->winmask;
	head = rwin->hc.head;
	if (odp_unlikely(oldt - head >= winmask))
		return false;
	newt = oldt + 1;
	rwin->tail = newt;
	*sn = oldt;

	return true;
}

void rwin_unreserve_sc(reorder_window_t *rwin, uint32_t sn)
{
	ODP_ASSERT(rwin->tail == sn + 1);
	rwin->tail = sn;
}

static void rwin_insert(reorder_window_t *rwin,
			reorder_context_t *rctx,
			uint32_t sn,
			void (*callback)(reorder_context_t *))
{
	/* Initialise to silence scan-build */
	hc_t old = {0, 0};
	hc_t new;
	uint32_t winmask;

	__atomic_load(&rwin->hc, &old, __ATOMIC_ACQUIRE);
	winmask = rwin->winmask;
	if (old.head != sn) {
		/* We are out-of-order. Store context in reorder window,
		 * releasing its content.
		 */
		ODP_ASSERT(rwin->ring[sn & winmask] == NULL);
		atomic_store_release(&rwin->ring[sn & winmask],
				     rctx,
				     /*readonly=*/false);
		rctx = NULL;
		do {
			hc_t new;

			new.head = old.head;
			new.chgi = old.chgi + 1; /* Changed value */
			/* Update head & chgi, fail if any has changed */
			if (__atomic_compare_exchange(&rwin->hc,
						      /* Updated on fail */
						      &old,
						      &new,
						      true,
						      /* Rel our ring update */
						      __ATOMIC_RELEASE,
						      __ATOMIC_ACQUIRE))
				/* CAS succeeded => head same (we are not
				 * in-order), chgi updated.
				 */
				return;
			/* CAS failed => head and/or chgi changed.
			 * We might not be out-of-order anymore.
			 */
		} while (old.head != sn);
	}

	/* old.head == sn => we are now in-order! */
	ODP_ASSERT(old.head == sn);
	/* We are in-order so our responsibility to retire contexts */
	new.head = old.head;
	new.chgi = old.chgi + 1;

	/* Retire our in-order context (if we still have it) */
	if (rctx != NULL) {
		callback(rctx);
		new.head++;
	}

	/* Retire in-order contexts in the ring
	 * The first context might actually be ours (if we were originally
	 * out-of-order)
	 */
	do {
		for (;;) {
			rctx = __atomic_load_n(&rwin->ring[new.head & winmask],
					       __ATOMIC_ACQUIRE);
			if (rctx == NULL)
				break;
			/* We are the only thread that are in-order
			 * (until head updated) so don't have to use
			 * atomic load-and-clear (exchange)
			 */
			rwin->ring[new.head & winmask] = NULL;
			callback(rctx);
			new.head++;
		}
	/* Update head&chgi, fail if chgi has changed (head cannot change) */
	} while (!__atomic_compare_exchange(&rwin->hc,
			&old, /* Updated on failure */
			&new,
			false, /* weak */
			__ATOMIC_RELEASE, /* Release our ring updates */
			__ATOMIC_ACQUIRE));
}

void rctx_init(reorder_context_t *rctx, uint16_t idx,
	       reorder_window_t *rwin, uint32_t sn)
{
	/* rctx->rvec_free and rctx->idx already initialised in
	 * thread_state_init function.
	 */
	ODP_ASSERT(rctx->idx == idx);
	rctx->rwin = rwin;
	rctx->sn = sn;
	rctx->olock_flags = 0;
	/* First => no next reorder context */
	rctx->next_idx = idx;
	/* Where to store next event */
	rctx->cur_idx = idx;
	rctx->numevts = 0;
}

static inline void rctx_free(const reorder_context_t *rctx)
{
	const reorder_context_t *const base = &rctx[-(int)rctx->idx];
	const uint32_t first = rctx->idx;
	uint32_t next_idx;

	next_idx = rctx->next_idx;

	ODP_ASSERT(rctx->rwin != NULL);
	/* Set free bit */
	if (rctx->rvec_free == &sched_ts->rvec_free)
		/* Since it is our own reorder context, we can instead
		 * perform a non-atomic and relaxed update on our private
		 * rvec_free.
		 */
		sched_ts->priv_rvec_free =
			bitset_set(sched_ts->priv_rvec_free, rctx->idx);
	else
		atom_bitset_set(rctx->rvec_free, rctx->idx, __ATOMIC_RELEASE);

	/* Can't dereference rctx after the corresponding free bit is set */
	while (next_idx != first) {
		rctx = &base[next_idx];
		next_idx = rctx->next_idx;
		/* Set free bit */
		if (rctx->rvec_free == &sched_ts->rvec_free)
			sched_ts->priv_rvec_free =
				bitset_set(sched_ts->priv_rvec_free, rctx->idx);
		else
			atom_bitset_set(rctx->rvec_free, rctx->idx,
					__ATOMIC_RELEASE);
	}
}

static inline void olock_unlock(const reorder_context_t *rctx,
				reorder_window_t *rwin,
				uint32_t lock_index)
{
	if ((rctx->olock_flags & (1U << lock_index)) == 0) {
		/* Use relaxed ordering, we are not releasing any updates */
		rwin->olock[lock_index] = rctx->sn + 1;
	}
}

static void olock_release(const reorder_context_t *rctx)
{
	reorder_window_t *rwin;
	uint32_t i;

	rwin = rctx->rwin;

	for (i = 0; i < rwin->lock_count; i++)
		olock_unlock(rctx, rwin, i);
}

static void blocking_enqueue(queue_entry_t *q, odp_buffer_hdr_t **evts, int num)
{
	int actual;

	/* Iterate until all events have been successfully enqueued */
	for (;;) {
		/* Attempt to enqueue remaining events */
		actual = q->s.enqueue_multi(qentry_to_int(q), evts, num);
		if (odp_unlikely(actual < 0))
			ODP_ERR("Failed to enqueue deferred events\n");
		/* Update for potential partial success */
		evts += actual;
		num -= actual;
		if (num == 0)
			break;
		/* Back-off to decrease load on the system */
		odp_cpu_pause();
	}
}

static void rctx_retire(reorder_context_t *first)
{
	reorder_context_t *rctx;
	queue_entry_t *q;
	uint32_t i;
	uint32_t j;
	uint32_t num;

	rctx = first;
	do {
		/* Process all events in this reorder context */
		for (i = 0; i < rctx->numevts;) {
			q = rctx->destq[i];
			/* Find index of next different destq */
			j = i + 1;
			while (j < rctx->numevts && rctx->destq[j] == q)
				j++;
			num = j - i;
			/* Blocking enqueue of events to this destq */
			blocking_enqueue(q, &rctx->events[i], num);
			i += num;
		}
		/* Update rctx pointer to point to 'next_idx' element */
		rctx += (int)rctx->next_idx - (int)rctx->idx;
	} while (rctx != first);
	olock_release(first);
	rctx_free(first);
}

void rctx_release(reorder_context_t *rctx)
{
	/* Insert reorder context into reorder window, potentially calling the
	 * rctx_retire function for all pending reorder_contexts.
	 */
	rwin_insert(rctx->rwin, rctx, rctx->sn, rctx_retire);
}

/* Save destination queue and events in the reorder context for deferred
 * enqueue.
 */
int rctx_save(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int i;
	sched_scalable_thread_state_t *ts;
	reorder_context_t *first;
	reorder_context_t *cur;
	bitset_t next_idx;

	ts = sched_ts;
	first = ts->rctx;
	ODP_ASSERT(ts->rctx != NULL);
	cur = &first[(int)first->cur_idx - (int)first->idx];
	for (i = 0; i < num; i++) {
		if (odp_unlikely(cur->numevts == RC_EVT_SIZE)) {
			/* No more space in current reorder context
			 * Try to allocate another.
			 */
			if (odp_unlikely(
				bitset_is_null(ts->priv_rvec_free))) {
				ts->priv_rvec_free =
					atom_bitset_xchg(
						&ts->rvec_free,
						0,
						__ATOMIC_RELAXED);
				if (odp_unlikely(bitset_is_null(
						ts->priv_rvec_free)))
					/* Out of reorder contexts.
					 * Return the number of events
					 * stored so far.
					 */
					return i;
			}
			next_idx = bitset_ffs(ts->priv_rvec_free) - 1;
			ts->priv_rvec_free =
				bitset_clr(ts->priv_rvec_free,
					   next_idx);
			/* Link current to next (for eventual
			 * retiring)
			 */
			cur->next_idx = next_idx;
			/* Link first to next (for next call to
			* queue_enq_multi())
			*/
			first->cur_idx = next_idx;
			/* Update current to next */
			cur = &ts->rvec[next_idx];
			rctx_init(cur, next_idx, NULL, 0);
			/* The last rctx (so far) */
			cur->next_idx = first->idx;
		}
		cur->events[cur->numevts] = buf_hdr[i];
		cur->destq[cur->numevts] = queue;
		cur->numevts++;
	}
	/* All events stored. */
	return num;
}
