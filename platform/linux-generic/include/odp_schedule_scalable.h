/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_SCHEDULE_SCALABLE_H
#define ODP_SCHEDULE_SCALABLE_H

#include <odp/api/align.h>
#include <odp/api/schedule.h>
#include <odp/api/ticketlock.h>

#include <odp_event_internal.h>
#include <odp_schedule_scalable_config.h>
#include <odp_schedule_scalable_ordered.h>
#include <odp_llqueue.h>

/*
 * Define scalable scheduler internal maximum priority count
 * ODP_SCHED_PRIO_NUM as it is not compile-time constant at API
 * level. The current API for this is odp_schedule_num_prio().
 * The other schedulers also define this internally as NUM_PRIO.
 *
 * One additional priority level for idle pktin queues.
 * This is only for internal use and not visible to the user.
 */
#define ODP_SCHED_PRIO_PKTIN 8
#define ODP_SCHED_PRIO_NUM  9

typedef struct ODP_ALIGNED_CACHE {
	union {
		struct {
			struct llqueue llq;
			uint32_t prio;
		};
		char line[ODP_CACHE_LINE_SIZE];
	};
} sched_queue_t;

#define TICKET_INVALID (uint16_t)(~0U)

typedef struct ODP_ALIGNED(sizeof(uint64_t)) {
	int32_t numevts;
	uint16_t wrr_budget;
	uint8_t cur_ticket;
	uint8_t nxt_ticket;
} qschedstate_t;

typedef uint32_t ringidx_t;

#ifdef CONFIG_SPLIT_PRODCONS
#define SPLIT_PC ODP_ALIGNED_CACHE
#else
#define SPLIT_PC
#endif

#define ODP_NO_SCHED_QUEUE (ODP_SCHED_SYNC_ORDERED + 1)

typedef struct ODP_ALIGNED_CACHE {
	struct llnode node;
	sched_queue_t *schedq;
#ifdef CONFIG_QSCHST_LOCK
	odp_ticketlock_t qschlock;
#endif
	qschedstate_t qschst;
	uint8_t pop_deficit;
	uint8_t qschst_type;
	uint8_t pktio_idx;
	uint8_t rx_queue;
	uint16_t xoffset;
	uint8_t sched_prio;
	ringidx_t prod_read SPLIT_PC;
	ringidx_t prod_write;
	ringidx_t prod_mask;
	_odp_event_hdr_t **prod_ring;
	ringidx_t cons_write SPLIT_PC;
	ringidx_t cons_read;
	reorder_window_t *rwin;
	void *user_ctx;
#ifdef CONFIG_SPLIT_PRODCONS
	_odp_event_hdr_t **cons_ring;
	ringidx_t cons_mask;
	uint16_t cons_type;
#else
#define cons_mask prod_mask
#define cons_ring prod_ring
#define cons_type qschst_type
#endif
	odp_schedule_group_t sched_grp;
	uint32_t loop_check[CONFIG_NUM_CPU_IDS];
} sched_elem_t;

/* Number of scheduling groups */
#define MAX_SCHED_GROUP (sizeof(sched_group_mask_t) * CHAR_BIT)

typedef bitset_t sched_group_mask_t;

typedef struct {
	/* Threads currently associated with the sched group */
	bitset_t thr_actual[ODP_SCHED_PRIO_NUM] ODP_ALIGNED_CACHE;
	bitset_t thr_wanted;
	/* Used to spread queues over schedq's */
	uint32_t xcount[ODP_SCHED_PRIO_NUM];
	/* Number of schedq's per prio */
	uint32_t xfactor;
	char name[ODP_SCHED_GROUP_NAME_LEN];
	/* ODP_SCHED_PRIO_NUM * xfactor. Must be last. */
	sched_queue_t schedq[1] ODP_ALIGNED_CACHE;
} sched_group_t;

/* Number of reorder contexts per thread */
#define TS_RVEC_SIZE 16

typedef struct ODP_ALIGNED_CACHE {
	/* Atomic queue currently being processed or NULL */
	sched_elem_t *atomq;
	/* Schedq the currently processed queue was popped from */
	sched_queue_t *src_schedq;
	/* Current reorder context or NULL */
	reorder_context_t *rctx;
	uint8_t pause;
	uint8_t out_of_order;
	uint8_t tidx;
	uint8_t pad;
	uint32_t dequeued; /* Number of events dequeued from atomic queue */
	uint16_t ticket; /* Ticket for atomic queue or TICKET_INVALID */
	uint16_t num_schedq;
	uint16_t sg_sem; /* Set when sg_wanted is modified by other thread */
#define SCHEDQ_PER_THREAD (MAX_SCHED_GROUP * ODP_SCHED_PRIO_NUM)
	sched_queue_t *schedq_list[SCHEDQ_PER_THREAD];
	/* Current sched_group membership */
	sched_group_mask_t sg_actual[ODP_SCHED_PRIO_NUM];
	/* Future sched_group membership. */
	sched_group_mask_t sg_wanted[ODP_SCHED_PRIO_NUM];
	bitset_t priv_rvec_free;
	/* Bitset of free entries in rvec[] */
	bitset_t rvec_free ODP_ALIGNED_CACHE;
	/* Reordering contexts to allocate from */
	reorder_context_t rvec[TS_RVEC_SIZE] ODP_ALIGNED_CACHE;
	uint32_t loop_cnt; /*Counter to check pktio ingress queue dead loop */
} sched_scalable_thread_state_t;

void _odp_sched_update_enq(sched_elem_t *q, uint32_t actual);
void _odp_sched_update_enq_sp(sched_elem_t *q, uint32_t actual);
sched_queue_t *_odp_sched_queue_add(odp_schedule_group_t grp, uint32_t prio);
void _odp_sched_queue_rem(odp_schedule_group_t grp, uint32_t prio);

#endif  /* ODP_SCHEDULE_SCALABLE_H */
