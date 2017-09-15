/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP list
 * a simple implementation of Doubly linked list
 */

#ifndef ODPH_LIST_INTER_H_
#define ODPH_LIST_INTER_H_

#ifdef __cplusplus
extern "C" {
#endif

/** List object */
typedef struct odph_list_object {
	/** Next element in list */
	struct odph_list_object *next;

	/** Previous element in list */
	struct odph_list_object *prev;
} odph_list_object;

/** Head of list */
typedef odph_list_object odph_list_head;

/**
 * @internal Intiailize list head element
 *
 * @param list List object to be initialized
 */
static inline void ODPH_INIT_LIST_HEAD(odph_list_object *list)
{
	list->next = list;
	list->prev = list;
}

/** @internal Inline function @param new @param prev @param next */
static inline void __odph_list_add(odph_list_object *new,
				   odph_list_object *prev,
				   odph_list_object *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

/** @internal Inline function @param new @param head */
static inline void odph_list_add(odph_list_object *new, odph_list_object *head)
{
	__odph_list_add(new, head, head->next);
}

/** @internal Inline function @param new @param head */
static inline void odph_list_add_tail(struct odph_list_object *new,
				      odph_list_object *head)
{
	__odph_list_add(new, head->prev, head);
}

/** @internal Inline function @param prev @param next */
static inline void __odph_list_del(struct odph_list_object *prev,
				   odph_list_object *next)
{
	next->prev = prev;
	prev->next = next;
}

/** @internal Inline function @param entry */
static inline void odph_list_del(struct odph_list_object *entry)
{
	__odph_list_del(entry->prev, entry->next);
	ODPH_INIT_LIST_HEAD(entry);
}

/** @internal Inline function @param head @return */
static inline int odph_list_empty(const struct odph_list_object *head)
{
	return head->next == head;
}

/** @internal */
#define container_of(ptr, type, list_node) \
		((type *)(void *)((char *)ptr - offsetof(type, list_node)))

/** @internal */
#define ODPH_LIST_FOR_EACH(pos, list_head, type, list_node) \
	for (pos = container_of((list_head)->next, type, list_node); \
		&pos->list_node != (list_head); \
		pos = container_of(pos->list_node.next, type, list_node))

#ifdef __cplusplus
}
#endif

#endif
