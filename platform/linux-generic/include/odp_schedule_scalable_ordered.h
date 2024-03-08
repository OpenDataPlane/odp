/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_SCHEDULE_SCALABLE_ORDERED_H
#define ODP_SCHEDULE_SCALABLE_ORDERED_H

#include <odp/api/align.h>
#include <odp/api/shared_memory.h>

#include <odp_bitset.h>
#include <odp_event_internal.h>
#include <odp_macros_internal.h>
#include <odp_ishmpool_internal.h>

/* High level functioning of reordering
 * Datastructures -
 * Reorder Window - Every ordered queue is associated with a reorder window.
 *                  Reorder window stores reorder contexts from threads that
 *                  have completed processing out-of-order.
 * Reorder Context - Reorder context consists of events that a thread
 *                   wants to enqueue while processing a batch of events
 *                   from an ordered queue.
 *
 * Algorithm -
 * 1) Thread identifies the ordered queue.
 * 2) It 'reserves a slot in the reorder window and dequeues the
 *    events' atomically. Atomicity is achieved by using a ticket-lock
 *    like design where the reorder window slot is the ticket.
 * 3a) Upon order-release/next schedule call, the thread
 *     checks if it's slot (ticket) equals the head of the reorder window.
 *     If yes, enqueues the events to the destination queue till
 *         i) the reorder window is empty or
 *         ii) there is a gap in the reorder window
 *     If no, the reorder context is stored in the reorder window at
 *     the reserved slot.
 * 3b) Upon the first enqueue, the thread checks if it's slot (ticket)
 *     equals the head of the reorder window.
 *     If yes, enqueues the events immediately to the destination queue
 *     If no, these (and subsequent) events are stored in the reorder context
 *     (in the application given order)
 */

/* Head and change indicator variables are used to synchronise between
 * concurrent insert operations in the reorder window. A thread performing
 * an in-order insertion must be notified about the newly inserted
 * reorder contexts so that it doesn’t halt the retire process too early.
 * A thread performing an out-of-order insertion must correspondingly
 * notify the thread doing in-order insertion of the new waiting reorder
 * context, which may need to be handled by that thread.
 *
 * Also, an out-of-order insertion may become an in-order insertion if the
 * thread doing an in-order insertion completes before this thread completes.
 * We need a point of synchronisation where this knowledge and potential state
 * change can be transferred between threads.
 */
typedef struct ODP_ALIGNED(sizeof(uint64_t)) hc {
	/* First missing context */
	uint32_t head;
	/* Change indicator */
	uint32_t chgi;
} hc_t;

/* Number of reorder contects in the reorder window.
 * Should be at least one per CPU.
 */
#define RWIN_SIZE 32
ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(RWIN_SIZE), "RWIN_SIZE is not a power of 2");

typedef struct reorder_context reorder_context_t;

typedef struct reorder_window {
	/* head and change indicator */
	hc_t hc;
	uint32_t winmask;
	uint32_t tail;
	uint32_t turn;
	uint32_t olock[CONFIG_QUEUE_MAX_ORD_LOCKS];
	uint32_t lock_count;
	/* Reorder contexts in this window */
	reorder_context_t *ring[RWIN_SIZE];
} reorder_window_t;

/* Number of events that can be stored in a reorder context.
 * This size is chosen so that there is no space left unused at the end
 * of the last cache line (for 64b architectures and 64b handles).
 */
#define RC_EVT_SIZE 18

struct ODP_ALIGNED_CACHE reorder_context {
	/* Reorder window to which this context belongs */
	reorder_window_t *rwin;
	/* Pointer to TS->rvec_free */
	bitset_t *rvec_free;
	/* Our slot number in the reorder window */
	uint32_t sn;
	uint8_t olock_flags;
	/* Our index in thread_state rvec array */
	uint8_t idx;
	/* Use to link reorder contexts together */
	uint8_t next_idx;
	/* Current reorder context to save events in */
	uint8_t cur_idx;
	/* Number of events stored in this reorder context */
	uint8_t numevts;
	/* Events stored in this context */
	_odp_event_hdr_t *events[RC_EVT_SIZE];
	queue_entry_t *destq[RC_EVT_SIZE];
};

reorder_window_t *_odp_rwin_alloc(_odp_ishm_pool_t *pool,
				  unsigned int lock_count);
int _odp_rwin_free(_odp_ishm_pool_t *pool, reorder_window_t *rwin);
bool _odp_rwin_reserve(reorder_window_t *rwin, uint32_t *sn);
bool _odp_rwin_reserve_sc(reorder_window_t *rwin, uint32_t *sn);
void _odp_rwin_unreserve_sc(reorder_window_t *rwin, uint32_t sn);
void _odp_rctx_init(reorder_context_t *rctx, uint16_t idx,
		    reorder_window_t *rwin, uint32_t sn);
void _odp_rctx_release(reorder_context_t *rctx);
int _odp_rctx_save(queue_entry_t *queue, _odp_event_hdr_t *event_hdr[], int num);

#endif  /* ODP_SCHEDULE_SCALABLE_ORDERED_H */
