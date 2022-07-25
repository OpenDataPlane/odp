/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_LLQUEUE_H_
#define ODP_LLQUEUE_H_

#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/spinlock.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_types_internal.h>
#include <odp_cpu.h>

#include <stdint.h>
#include <stdlib.h>

/******************************************************************************
 * Linked list queues
 *****************************************************************************/

struct llqueue;
struct llnode;

static struct llnode *llq_head(struct llqueue *llq);
static void llqueue_init(struct llqueue *llq);
static void llq_enqueue(struct llqueue *llq, struct llnode *node);
static struct llnode *llq_dequeue(struct llqueue *llq);
static odp_bool_t llq_dequeue_cond(struct llqueue *llq, struct llnode *exp);
static odp_bool_t llq_cond_rotate(struct llqueue *llq, struct llnode *node);
static odp_bool_t llq_on_queue(struct llnode *node);

/******************************************************************************
 * The implementation(s)
 *****************************************************************************/

#define SENTINEL ((void *)~(uintptr_t)0)
#define MAX_SPIN_COUNT 1000

#ifdef CONFIG_LLDSCD
/* Implement queue operations using double-word LL/SC */

/* The scalar equivalent of a double pointer */
#if __SIZEOF_PTRDIFF_T__ == 4
typedef uint64_t dintptr_t;
#endif
#if __SIZEOF_PTRDIFF_T__ == 8
typedef _odp_u128_t dintptr_t;
#endif

struct llnode {
	struct llnode *next;
};

union llht {
	struct {
		struct llnode *head, *tail;
	} st;
	dintptr_t ui;
};

struct llqueue {
	union llht u;
};

static inline struct llnode *llq_head(struct llqueue *llq)
{
	return __atomic_load_n(&llq->u.st.head, __ATOMIC_RELAXED);
}

static inline void llqueue_init(struct llqueue *llq)
{
	llq->u.st.head = NULL;
	llq->u.st.tail = NULL;
}

static inline void llq_enqueue(struct llqueue *llq, struct llnode *node)
{
	union llht old, neu;

	ODP_ASSERT(node->next == NULL);
	node->next = SENTINEL;
	do {
		old.ui = lld(&llq->u.ui, __ATOMIC_RELAXED);
		neu.st.head = old.st.head == NULL ? node : old.st.head;
		neu.st.tail = node;
	} while (odp_unlikely(scd(&llq->u.ui, neu.ui, __ATOMIC_RELEASE)));
	if (old.st.tail != NULL) {
		/* List was not empty */
		ODP_ASSERT(old.st.tail->next == SENTINEL);
		old.st.tail->next = node;
	}
}

static inline struct llnode *llq_dequeue(struct llqueue *llq)
{
	struct llnode *head;
	union llht old, neu;

	/* llq_dequeue() may be used in a busy-waiting fashion
	 * Read head using plain load to avoid disturbing remote LL/SC
	 */
	head = __atomic_load_n(&llq->u.st.head, __ATOMIC_ACQUIRE);
	if (head == NULL)
		return NULL;
	/* Read head->next before LL to minimize cache miss latency
	 * in LL/SC below
	 */
	(void)__atomic_load_n(&head->next, __ATOMIC_RELAXED);

	do {
restart_loop:
		old.ui = lld(&llq->u.ui, __ATOMIC_RELAXED);
		if (odp_unlikely(old.st.head == NULL)) {
			/* Empty list */
			return NULL;
		} else if (odp_unlikely(old.st.head == old.st.tail)) {
			/* Single-element in list */
			neu.st.head = NULL;
			neu.st.tail = NULL;
		} else {
			/* Multi-element list, dequeue head */
			struct llnode *next;
			int	spin_count = 0;

			/* Wait until llq_enqueue() has written true next
			 * pointer
			 */
			while ((next = __atomic_load_n(&old.st.head->next,
						       __ATOMIC_RELAXED)) ==
				SENTINEL) {
				odp_cpu_pause();
				if (++spin_count >= MAX_SPIN_COUNT)
					goto restart_loop;
			}
			neu.st.head = next;
			neu.st.tail = old.st.tail;
		}
	} while (odp_unlikely(scd(&llq->u.ui, neu.ui, __ATOMIC_RELAXED)));
	old.st.head->next = NULL;
	return old.st.head;
}

static inline odp_bool_t llq_dequeue_cond(struct llqueue *llq,
					  struct llnode *exp)
{
	union llht old, neu;

	do {
restart_loop:
		old.ui = lld(&llq->u.ui, __ATOMIC_ACQUIRE);
		if (odp_unlikely(old.st.head == NULL || old.st.head != exp)) {
			/* Empty list or wrong head */
			return false;
		} else if (odp_unlikely(old.st.head == old.st.tail)) {
			/* Single-element in list */
			neu.st.head = NULL;
			neu.st.tail = NULL;
		} else {
			/* Multi-element list, dequeue head */
			struct llnode *next;
			int     spin_count = 0;

			/* Wait until llq_enqueue() has written true next
			 * pointer */
			while ((next = __atomic_load_n(&old.st.head->next,
						       __ATOMIC_RELAXED)) ==
				SENTINEL) {
				odp_cpu_pause();
				if (++spin_count >= MAX_SPIN_COUNT)
					goto restart_loop;
			}

			neu.st.head = next;
			neu.st.tail = old.st.tail;
		}
	} while (odp_unlikely(scd(&llq->u.ui, neu.ui, __ATOMIC_RELAXED)));
	old.st.head->next = NULL;
	return true;
}

/* If 'node' is a head of llq then move it to tail */
static inline odp_bool_t llq_cond_rotate(struct llqueue *llq,
					 struct llnode *node)
{
	/* Difficult to make this into a single atomic operation
	 * Instead use existing primitives.
	 */
	if (odp_likely(llq_dequeue_cond(llq, node))) {
		llq_enqueue(llq, node);
		return true;
	}
	return false;
}

static inline odp_bool_t llq_on_queue(struct llnode *node)
{
	return node->next != NULL;
}

#else
/* Implement queue operations protected by a spin lock */

struct llnode {
	struct llnode *next;
};

struct llqueue {
	struct llnode *head, *tail;
	odp_spinlock_t lock;
};

static inline struct llnode *llq_head(struct llqueue *llq)
{
	return __atomic_load_n(&llq->head, __ATOMIC_RELAXED);
}

static inline void llqueue_init(struct llqueue *llq)
{
	llq->head = NULL;
	llq->tail = NULL;
	odp_spinlock_init(&llq->lock);
}

static inline void llq_enqueue(struct llqueue *llq, struct llnode *node)
{
	ODP_ASSERT(node->next == NULL);
	node->next = SENTINEL;

	odp_spinlock_lock(&llq->lock);
	if (llq->head == NULL) {
		llq->head = node;
		llq->tail = node;
	} else {
		llq->tail->next = node;
		llq->tail = node;
	}
	odp_spinlock_unlock(&llq->lock);
}

static inline struct llnode *llq_dequeue(struct llqueue *llq)
{
	struct llnode *head;
	struct llnode *node = NULL;

	head = __atomic_load_n(&llq->head, __ATOMIC_RELAXED);
	if (head == NULL)
		return NULL;

	odp_spinlock_lock(&llq->lock);
	if (llq->head != NULL) {
		node = llq->head;
		if (llq->head == llq->tail) {
			ODP_ASSERT(node->next == SENTINEL);
			llq->head = NULL;
			llq->tail = NULL;
		} else {
			ODP_ASSERT(node->next != SENTINEL);
			llq->head = node->next;
		}
		node->next = NULL;
	}
	odp_spinlock_unlock(&llq->lock);
	return node;
}

static inline odp_bool_t llq_dequeue_cond(struct llqueue *llq,
					  struct llnode *node)
{
	odp_bool_t success = false;

	odp_spinlock_lock(&llq->lock);
	if (odp_likely(llq->head != NULL && llq->head == node)) {
		success = true;
		if (llq->head == llq->tail) {
			ODP_ASSERT(node->next == SENTINEL);
			llq->head = NULL;
			llq->tail = NULL;
		} else {
			ODP_ASSERT(node->next != SENTINEL);
			llq->head = node->next;
		}
		node->next = NULL;
	}
	odp_spinlock_unlock(&llq->lock);
	return success;
}

/* If 'node' is a head of llq then move it to tail */
static inline odp_bool_t llq_cond_rotate(struct llqueue *llq,
					 struct llnode *node)
{
	odp_bool_t success = false;

	odp_spinlock_lock(&llq->lock);
	if (odp_likely(llq->head == node)) {
		success = true;
		if (llq->tail != node) {
			ODP_ASSERT(node->next != SENTINEL);
			llq->head = node->next;
			llq->tail->next = node;
			llq->tail = node;
			node->next = SENTINEL;
		}
		/* Else 'node' is only element on list => nothing to do */
	}
	odp_spinlock_unlock(&llq->lock);
	return success;
}

static inline odp_bool_t llq_on_queue(struct llnode *node)
{
	return node->next != NULL;
}

#endif

#endif
