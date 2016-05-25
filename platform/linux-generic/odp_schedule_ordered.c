/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet_io_queue.h>
#include <odp_queue_internal.h>
#include <odp_schedule_if.h>
#include <odp_schedule_ordered_internal.h>
#include <odp_traffic_mngr_internal.h>
#include <odp_schedule_internal.h>

#define RESOLVE_ORDER 0
#define NOAPPEND 0
#define APPEND   1

static inline void sched_enq_called(void)
{
	sched_local.enq_called = 1;
}

static inline void get_sched_order(queue_entry_t **origin_qe, uint64_t *order)
{
	if (sched_local.ignore_ordered_context) {
		sched_local.ignore_ordered_context = 0;
		*origin_qe = NULL;
	} else {
		*origin_qe = sched_local.origin_qe;
		*order     = sched_local.order;
	}
}

static inline void sched_order_resolved(odp_buffer_hdr_t *buf_hdr)
{
	if (buf_hdr)
		buf_hdr->origin_qe = NULL;
	sched_local.origin_qe = NULL;
}

static inline void get_qe_locks(queue_entry_t *qe1, queue_entry_t *qe2)
{
	/* Special case: enq to self */
	if (qe1 == qe2) {
		queue_lock(qe1);
		return;
	}

       /* Since any queue can be either a source or target, queues do not have
	* a natural locking hierarchy.  Create one by using the qentry address
	* as the ordering mechanism.
	*/

	if (qe1 < qe2) {
		queue_lock(qe1);
		queue_lock(qe2);
	} else {
		queue_lock(qe2);
		queue_lock(qe1);
	}
}

static inline void free_qe_locks(queue_entry_t *qe1, queue_entry_t *qe2)
{
	queue_unlock(qe1);
	if (qe1 != qe2)
		queue_unlock(qe2);
}

static inline odp_buffer_hdr_t *get_buf_tail(odp_buffer_hdr_t *buf_hdr)
{
	odp_buffer_hdr_t *buf_tail = buf_hdr->link ? buf_hdr->link : buf_hdr;

	buf_hdr->next = buf_hdr->link;
	buf_hdr->link = NULL;

	while (buf_tail->next)
		buf_tail = buf_tail->next;

	return buf_tail;
}

static inline void queue_add_list(queue_entry_t *queue,
				  odp_buffer_hdr_t *buf_head,
				  odp_buffer_hdr_t *buf_tail)
{
	if (queue->s.head)
		queue->s.tail->next = buf_head;
	else
		queue->s.head = buf_head;

	queue->s.tail = buf_tail;
}

static inline void queue_add_chain(queue_entry_t *queue,
				   odp_buffer_hdr_t *buf_hdr)
{
	queue_add_list(queue, buf_hdr, get_buf_tail(buf_hdr));
}

static inline void reorder_enq(queue_entry_t *queue,
			       uint64_t order,
			       queue_entry_t *origin_qe,
			       odp_buffer_hdr_t *buf_hdr,
			       int sustain)
{
	odp_buffer_hdr_t *reorder_buf = origin_qe->s.reorder_head;
	odp_buffer_hdr_t *reorder_prev = NULL;

	while (reorder_buf && order >= reorder_buf->order) {
		reorder_prev = reorder_buf;
		reorder_buf  = reorder_buf->next;
	}

	buf_hdr->next = reorder_buf;

	if (reorder_prev)
		reorder_prev->next = buf_hdr;
	else
		origin_qe->s.reorder_head = buf_hdr;

	if (!reorder_buf)
		origin_qe->s.reorder_tail = buf_hdr;

	buf_hdr->origin_qe     = origin_qe;
	buf_hdr->target_qe     = queue;
	buf_hdr->order         = order;
	buf_hdr->flags.sustain = sustain;
}

static inline void order_release(queue_entry_t *origin_qe, int count)
{
	uint64_t sync;
	uint32_t i;

	origin_qe->s.order_out += count;

	for (i = 0; i < origin_qe->s.param.sched.lock_count; i++) {
		sync = odp_atomic_load_u64(&origin_qe->s.sync_out[i]);
		if (sync < origin_qe->s.order_out)
			odp_atomic_fetch_add_u64(&origin_qe->s.sync_out[i],
						 origin_qe->s.order_out - sync);
	}
}

static inline int reorder_deq(queue_entry_t *queue,
			      queue_entry_t *origin_qe,
			      odp_buffer_hdr_t **reorder_tail_return,
			      odp_buffer_hdr_t **placeholder_buf_return,
			      int *release_count_return,
			      int *placeholder_count_return)
{
	odp_buffer_hdr_t *reorder_buf     = origin_qe->s.reorder_head;
	odp_buffer_hdr_t *reorder_tail    = NULL;
	odp_buffer_hdr_t *placeholder_buf = NULL;
	odp_buffer_hdr_t *next_buf;
	int               deq_count = 0;
	int               release_count = 0;
	int               placeholder_count = 0;

	while (reorder_buf &&
	       reorder_buf->order <= origin_qe->s.order_out +
	       release_count + placeholder_count) {
		/*
		 * Elements on the reorder list fall into one of
		 * three categories:
		 *
		 * 1. Those destined for the same queue.  These
		 *    can be enq'd now if they were waiting to
		 *    be unblocked by this enq.
		 *
		 * 2. Those representing placeholders for events
		 *    whose ordering was released by a prior
		 *    odp_schedule_release_ordered() call.  These
		 *    can now just be freed.
		 *
		 * 3. Those representing events destined for another
		 *    queue. These cannot be consolidated with this
		 *    enq since they have a different target.
		 *
		 * Detecting an element with an order sequence gap, an
		 * element in category 3, or running out of elements
		 * stops the scan.
		 */
		next_buf = reorder_buf->next;

		if (odp_likely(reorder_buf->target_qe == queue)) {
			/* promote any chain */
			odp_buffer_hdr_t *reorder_link =
				reorder_buf->link;

			if (reorder_link) {
				reorder_buf->next = reorder_link;
				reorder_buf->link = NULL;
				while (reorder_link->next)
					reorder_link = reorder_link->next;
				reorder_link->next = next_buf;
				reorder_tail = reorder_link;
			} else {
				reorder_tail = reorder_buf;
			}

			deq_count++;
			if (!reorder_buf->flags.sustain)
				release_count++;
			reorder_buf = next_buf;
		} else if (!reorder_buf->target_qe) {
			if (reorder_tail)
				reorder_tail->next = next_buf;
			else
				origin_qe->s.reorder_head = next_buf;

			reorder_buf->next = placeholder_buf;
			placeholder_buf = reorder_buf;

			reorder_buf = next_buf;
			placeholder_count++;
		} else {
			break;
		}
	}

	*reorder_tail_return = reorder_tail;
	*placeholder_buf_return = placeholder_buf;
	*release_count_return = release_count;
	*placeholder_count_return = placeholder_count;

	return deq_count;
}

static inline void reorder_complete(queue_entry_t *origin_qe,
				    odp_buffer_hdr_t **reorder_buf_return,
				    odp_buffer_hdr_t **placeholder_buf,
				    int placeholder_append)
{
	odp_buffer_hdr_t *reorder_buf = origin_qe->s.reorder_head;
	odp_buffer_hdr_t *next_buf;

	*reorder_buf_return = NULL;
	if (!placeholder_append)
		*placeholder_buf = NULL;

	while (reorder_buf &&
	       reorder_buf->order <= origin_qe->s.order_out) {
		next_buf = reorder_buf->next;

		if (!reorder_buf->target_qe) {
			origin_qe->s.reorder_head = next_buf;
			reorder_buf->next         = *placeholder_buf;
			*placeholder_buf          = reorder_buf;

			reorder_buf = next_buf;
			order_release(origin_qe, 1);
		} else if (reorder_buf->flags.sustain) {
			reorder_buf = next_buf;
		} else {
			*reorder_buf_return = origin_qe->s.reorder_head;
			origin_qe->s.reorder_head =
				origin_qe->s.reorder_head->next;
			break;
		}
	}
}

static inline void get_queue_order(queue_entry_t **origin_qe, uint64_t *order,
				   odp_buffer_hdr_t *buf_hdr)
{
	if (buf_hdr && buf_hdr->origin_qe) {
		*origin_qe = buf_hdr->origin_qe;
		*order     = buf_hdr->order;
	} else {
		get_sched_order(origin_qe, order);
	}
}

int queue_tm_reenq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr,
		   int sustain ODP_UNUSED)
{
	odp_tm_queue_t tm_queue = MAKE_ODP_TM_QUEUE((uint8_t *)queue -
						    offsetof(tm_queue_obj_t,
							     tm_qentry));
	odp_packet_t pkt = (odp_packet_t)buf_hdr->handle.handle;

	return odp_tm_enq(tm_queue, pkt);
}

int queue_tm_reenq_multi(queue_entry_t *queue ODP_UNUSED,
			 odp_buffer_hdr_t *buf[] ODP_UNUSED,
			 int num ODP_UNUSED,
			 int sustain ODP_UNUSED)
{
	ODP_ABORT("Invalid call to queue_tm_reenq_multi()\n");
	return 0;
}

int queue_tm_reorder(queue_entry_t *queue,
		     odp_buffer_hdr_t *buf_hdr)
{
	queue_entry_t *origin_qe;
	uint64_t order;

	get_queue_order(&origin_qe, &order, buf_hdr);

	if (!origin_qe)
		return 0;

	/* Check if we're in order */
	queue_lock(origin_qe);
	if (odp_unlikely(origin_qe->s.status < QUEUE_STATUS_READY)) {
		queue_unlock(origin_qe);
		ODP_ERR("Bad origin queue status\n");
		return 0;
	}

	sched_enq_called();

	/* Wait if it's not our turn */
	if (order > origin_qe->s.order_out) {
		reorder_enq(queue, order, origin_qe, buf_hdr, SUSTAIN_ORDER);
		queue_unlock(origin_qe);
		return 1;
	}

	/* Back to TM to handle enqueue
	 *
	 * Note: Order will be resolved by a subsequent call to
	 * odp_schedule_release_ordered() or odp_schedule() as odp_tm_enq()
	 * calls never resolve order by themselves.
	 */
	queue_unlock(origin_qe);
	return 0;
}

static int queue_enq_internal(odp_buffer_hdr_t *buf_hdr)
{
	return buf_hdr->target_qe->s.enqueue(buf_hdr->target_qe, buf_hdr,
					     buf_hdr->flags.sustain);
}

static int ordered_queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr,
			     int sustain, queue_entry_t *origin_qe,
			     uint64_t order)
{
	odp_buffer_hdr_t *reorder_buf;
	odp_buffer_hdr_t *next_buf;
	odp_buffer_hdr_t *reorder_tail;
	odp_buffer_hdr_t *placeholder_buf = NULL;
	int               release_count, placeholder_count;
	int               sched = 0;

	/* Need two locks for enq operations from ordered queues */
	get_qe_locks(origin_qe, queue);

	if (odp_unlikely(origin_qe->s.status < QUEUE_STATUS_READY ||
			 queue->s.status < QUEUE_STATUS_READY)) {
		free_qe_locks(queue, origin_qe);
		ODP_ERR("Bad queue status\n");
		ODP_ERR("queue = %s, origin q = %s, buf = %p\n",
			queue->s.name, origin_qe->s.name, buf_hdr);
		return -1;
	}

	/* Remember that enq was called for this order */
	sched_enq_called();

	/* We can only complete this enq if we're in order */
	if (order > origin_qe->s.order_out) {
		reorder_enq(queue, order, origin_qe, buf_hdr, sustain);

		/* This enq can't complete until order is restored, so
		 * we're done here.
		 */
		free_qe_locks(queue, origin_qe);
		return 0;
	}

	/* Resolve order if requested */
	if (!sustain) {
		order_release(origin_qe, 1);
		sched_order_resolved(buf_hdr);
	}

	/* Update queue status */
	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1;
	}

	/* We're in order, however the reorder queue may have other buffers
	 * sharing this order on it and this buffer must not be enqueued ahead
	 * of them. If the reorder queue is empty we can short-cut and
	 * simply add to the target queue directly.
	 */

	if (!origin_qe->s.reorder_head) {
		queue_add_chain(queue, buf_hdr);
		free_qe_locks(queue, origin_qe);

		/* Add queue to scheduling */
		if (sched && sched_fn->sched_queue(queue->s.index))
			ODP_ABORT("schedule_queue failed\n");
		return 0;
	}

	/* The reorder_queue is non-empty, so sort this buffer into it.  Note
	 * that we force the sustain bit on here because we'll be removing
	 * this immediately and we already accounted for this order earlier.
	 */
	reorder_enq(queue, order, origin_qe, buf_hdr, 1);

	/* Pick up this element, and all others resolved by this enq,
	 * and add them to the target queue.
	 */
	reorder_deq(queue, origin_qe, &reorder_tail, &placeholder_buf,
		    &release_count, &placeholder_count);

	/* Move the list from the reorder queue to the target queue */
	if (queue->s.head)
		queue->s.tail->next = origin_qe->s.reorder_head;
	else
		queue->s.head       = origin_qe->s.reorder_head;
	queue->s.tail               = reorder_tail;
	origin_qe->s.reorder_head   = reorder_tail->next;
	reorder_tail->next          = NULL;

	/* Reflect resolved orders in the output sequence */
	order_release(origin_qe, release_count + placeholder_count);

	/* Now handle any resolved orders for events destined for other
	 * queues, appending placeholder bufs as needed.
	 */
	if (origin_qe != queue)
		queue_unlock(queue);

	/* Add queue to scheduling */
	if (sched && sched_fn->sched_queue(queue->s.index))
		ODP_ABORT("schedule_queue failed\n");

	reorder_complete(origin_qe, &reorder_buf, &placeholder_buf, APPEND);
	queue_unlock(origin_qe);

	if (reorder_buf)
		queue_enq_internal(reorder_buf);

	/* Free all placeholder bufs that are now released */
	while (placeholder_buf) {
		next_buf = placeholder_buf->next;
		odp_buffer_free(placeholder_buf->handle.handle);
		placeholder_buf = next_buf;
	}

	return 0;
}

int schedule_ordered_queue_enq(queue_entry_t *queue,
			       odp_buffer_hdr_t *buf_hdr,
			       int sustain, int *ret)
{
	queue_entry_t *origin_qe;
	uint64_t order;

	get_queue_order(&origin_qe, &order, buf_hdr);

	/* Handle enqueues from ordered queues separately */
	if (origin_qe) {
		*ret = ordered_queue_enq(queue, buf_hdr, sustain,
					 origin_qe, order);
		return 1;
	}

	return 0;
}

int schedule_ordered_queue_enq_multi(queue_entry_t *queue,
				     odp_buffer_hdr_t *buf_hdr[],
				     int num, int sustain, int *ret)
{
	queue_entry_t *origin_qe;
	uint64_t order;
	int rc;

	/* Handle ordered enqueues commonly via links */
	get_queue_order(&origin_qe, &order, buf_hdr[0]);
	if (origin_qe) {
		buf_hdr[0]->link = buf_hdr[0]->next;
		rc = ordered_queue_enq(queue, buf_hdr[0], sustain,
				       origin_qe, order);
		*ret = rc == 0 ? num : rc;
		return 1;
	}

	return 0;
}

int queue_pktout_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr,
		     int sustain)
{
	queue_entry_t *origin_qe;
	uint64_t order;
	int rc;

	/* Special processing needed only if we came from an ordered queue */
	get_queue_order(&origin_qe, &order, buf_hdr);
	if (!origin_qe)
		return pktout_enqueue(queue, buf_hdr);

	/* Must lock origin_qe for ordered processing */
	queue_lock(origin_qe);
	if (odp_unlikely(origin_qe->s.status < QUEUE_STATUS_READY)) {
		queue_unlock(origin_qe);
		ODP_ERR("Bad origin queue status\n");
		return -1;
	}

	/* We can only complete the enq if we're in order */
	sched_enq_called();
	if (order > origin_qe->s.order_out) {
		reorder_enq(queue, order, origin_qe, buf_hdr, sustain);

		/* This enq can't complete until order is restored, so
		 * we're done here.
		 */
		queue_unlock(origin_qe);
		return 0;
	}

	/* Perform our enq since we're in order.
	 * Note: Don't hold the origin_qe lock across an I/O operation!
	 */
	queue_unlock(origin_qe);

	/* Handle any chained buffers (internal calls) */
	if (buf_hdr->link) {
		odp_buffer_hdr_t *buf_hdrs[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *next_buf;
		int num = 0;

		next_buf = buf_hdr->link;
		buf_hdr->link = NULL;

		while (next_buf) {
			buf_hdrs[num++] = next_buf;
			next_buf = next_buf->next;
		}

		rc = pktout_enq_multi(queue, buf_hdrs, num);
		if (rc < num)
			return -1;
	} else {
		rc = pktout_enqueue(queue, buf_hdr);
		if (rc)
			return rc;
	}

	/* Reacquire the lock following the I/O send. Note that we're still
	 * guaranteed to be in order here since we haven't released
	 * order yet.
	 */
	queue_lock(origin_qe);
	if (odp_unlikely(origin_qe->s.status < QUEUE_STATUS_READY)) {
		queue_unlock(origin_qe);
		ODP_ERR("Bad origin queue status\n");
		return -1;
	}

	/* Account for this ordered enq */
	if (!sustain) {
		order_release(origin_qe, 1);
		sched_order_resolved(NULL);
	}

	/* Now check to see if our successful enq has unblocked other buffers
	 * in the origin's reorder queue.
	 */
	odp_buffer_hdr_t *reorder_buf;
	odp_buffer_hdr_t *next_buf;
	odp_buffer_hdr_t *reorder_tail;
	odp_buffer_hdr_t *xmit_buf;
	odp_buffer_hdr_t *placeholder_buf;
	int               release_count, placeholder_count;

	/* Send released buffers as well */
	if (reorder_deq(queue, origin_qe, &reorder_tail, &placeholder_buf,
			&release_count, &placeholder_count)) {
		xmit_buf = origin_qe->s.reorder_head;
		origin_qe->s.reorder_head = reorder_tail->next;
		reorder_tail->next = NULL;
		queue_unlock(origin_qe);

		do {
			next_buf = xmit_buf->next;
			pktout_enqueue(queue, xmit_buf);
			xmit_buf = next_buf;
		} while (xmit_buf);

		/* Reacquire the origin_qe lock to continue */
		queue_lock(origin_qe);
		if (odp_unlikely(origin_qe->s.status < QUEUE_STATUS_READY)) {
			queue_unlock(origin_qe);
			ODP_ERR("Bad origin queue status\n");
			return -1;
		}
	}

	/* Update the order sequence to reflect the deq'd elements */
	order_release(origin_qe, release_count + placeholder_count);

	/* Now handle sends to other queues that are ready to go */
	reorder_complete(origin_qe, &reorder_buf, &placeholder_buf, APPEND);

	/* We're fully done with the origin_qe at last */
	queue_unlock(origin_qe);

	/* Now send the next buffer to its target queue */
	if (reorder_buf)
		queue_enq_internal(reorder_buf);

	/* Free all placeholder bufs that are now released */
	while (placeholder_buf) {
		next_buf = placeholder_buf->next;
		odp_buffer_free(placeholder_buf->handle.handle);
		placeholder_buf = next_buf;
	}

	return 0;
}

int queue_pktout_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			   int num, int sustain)
{
	int i, rc;
	queue_entry_t *origin_qe;
	uint64_t order;

	/* If we're not ordered, handle directly */
	get_queue_order(&origin_qe, &order, buf_hdr[0]);
	if (!origin_qe)
		return pktout_enq_multi(queue, buf_hdr, num);

	/* Chain input buffers together */
	for (i = 0; i < num - 1; i++)
		buf_hdr[i]->next = buf_hdr[i + 1];

	buf_hdr[num - 1]->next = NULL;

	/* Handle commonly via links */
	buf_hdr[0]->link = buf_hdr[0]->next;
	rc = queue_pktout_enq(queue, buf_hdr[0], sustain);
	return rc == 0 ? num : rc;
}

/* These routines exists here rather than in odp_schedule
 * because they operate on queue interenal structures
 */
int release_order(queue_entry_t *origin_qe, uint64_t order,
		  odp_pool_t pool, int enq_called)
{
	odp_buffer_t placeholder_buf;
	odp_buffer_hdr_t *placeholder_buf_hdr, *reorder_buf, *next_buf;

	/* Must lock the origin queue to process the release */
	queue_lock(origin_qe);

	/* If we are in order we can release immediately since there can be no
	 * confusion about intermediate elements
	 */
	if (order <= origin_qe->s.order_out) {
		reorder_buf = origin_qe->s.reorder_head;

		/* We're in order, however there may be one or more events on
		 * the reorder queue that are part of this order. If that is
		 * the case, remove them and let ordered_queue_enq() handle
		 * them and resolve the order for us.
		 */
		if (reorder_buf && reorder_buf->order == order) {
			odp_buffer_hdr_t *reorder_head = reorder_buf;

			next_buf = reorder_buf->next;

			while (next_buf && next_buf->order == order) {
				reorder_buf = next_buf;
				next_buf    = next_buf->next;
			}

			origin_qe->s.reorder_head = reorder_buf->next;
			reorder_buf->next = NULL;

			queue_unlock(origin_qe);
			reorder_head->link = reorder_buf->next;
			return ordered_queue_enq(reorder_head->target_qe,
						 reorder_head, RESOLVE_ORDER,
						 origin_qe, order);
		}

		/* Reorder queue has no elements for this order, so it's safe
		 * to resolve order here
		 */
		order_release(origin_qe, 1);

		/* Check if this release allows us to unblock waiters.  At the
		 * point of this call, the reorder list may contain zero or
		 * more placeholders that need to be freed, followed by zero
		 * or one complete reorder buffer chain. Note that since we
		 * are releasing order, we know no further enqs for this order
		 * can occur, so ignore the sustain bit to clear out our
		 * element(s) on the reorder queue
		 */
		reorder_complete(origin_qe, &reorder_buf,
				 &placeholder_buf_hdr, NOAPPEND);

		/* Now safe to unlock */
		queue_unlock(origin_qe);

		/* If reorder_buf has a target, do the enq now */
		if (reorder_buf)
			queue_enq_internal(reorder_buf);

		while (placeholder_buf_hdr) {
			odp_buffer_hdr_t *placeholder_next =
				placeholder_buf_hdr->next;

			odp_buffer_free(placeholder_buf_hdr->handle.handle);
			placeholder_buf_hdr = placeholder_next;
		}

		return 0;
	}

	/* If we are not in order we need a placeholder to represent our
	 * "place in line" unless we have issued enqs, in which case we
	 * already have a place in the reorder queue. If we need a
	 * placeholder, use an element from the same pool we were scheduled
	 * with is from, otherwise just ensure that the final element for our
	 * order is not marked sustain.
	 */
	if (enq_called) {
		reorder_buf = NULL;
		next_buf    = origin_qe->s.reorder_head;

		while (next_buf && next_buf->order <= order) {
			reorder_buf = next_buf;
			next_buf = next_buf->next;
		}

		if (reorder_buf && reorder_buf->order == order) {
			reorder_buf->flags.sustain = 0;
			queue_unlock(origin_qe);
			return 0;
		}
	}

	placeholder_buf = odp_buffer_alloc(pool);

	/* Can't release if no placeholder is available */
	if (odp_unlikely(placeholder_buf == ODP_BUFFER_INVALID)) {
		queue_unlock(origin_qe);
		return -1;
	}

	placeholder_buf_hdr = odp_buf_to_hdr(placeholder_buf);

	/* Copy info to placeholder and add it to the reorder queue */
	placeholder_buf_hdr->origin_qe     = origin_qe;
	placeholder_buf_hdr->order         = order;
	placeholder_buf_hdr->flags.sustain = 0;

	reorder_enq(NULL, order, origin_qe, placeholder_buf_hdr, 0);

	queue_unlock(origin_qe);
	return 0;
}

void odp_schedule_order_lock(unsigned lock_index)
{
	queue_entry_t *origin_qe;
	uint64_t sync, sync_out;

	origin_qe = sched_local.origin_qe;
	if (!origin_qe || lock_index >= origin_qe->s.param.sched.lock_count)
		return;

	sync = sched_local.sync[lock_index];
	sync_out = odp_atomic_load_u64(&origin_qe->s.sync_out[lock_index]);
	ODP_ASSERT(sync >= sync_out);

	/* Wait until we are in order. Note that sync_out will be incremented
	 * both by unlocks as well as order resolution, so we're OK if only
	 * some events in the ordered flow need to lock.
	 */
	while (sync != sync_out) {
		odp_cpu_pause();
		sync_out =
			odp_atomic_load_u64(&origin_qe->s.sync_out[lock_index]);
	}
}

void odp_schedule_order_unlock(unsigned lock_index)
{
	queue_entry_t *origin_qe;

	origin_qe = sched_local.origin_qe;
	if (!origin_qe || lock_index >= origin_qe->s.param.sched.lock_count)
		return;
	ODP_ASSERT(sched_local.sync[lock_index] ==
		   odp_atomic_load_u64(&origin_qe->s.sync_out[lock_index]));

	/* Release the ordered lock */
	odp_atomic_fetch_inc_u64(&origin_qe->s.sync_out[lock_index]);
}
