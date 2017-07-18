/* Adopted and modified Rusty Russell CCAN Project
 * https://github.com/rustyrussell/ccan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef CCAN_LIST_H
#define CCAN_LIST_H

#include <stddef.h>
#include <stdbool.h>

/* Always assume the availabilities of typeof or __typeof__ */
#if defined(__STDC__)
#define typeof __typeof__
#endif

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the
 * compiler is aware of some particular ordering.  One way to make the
 * compiler aware of ordering is to put the two invocations of READ_ONCE,
 * WRITE_ONCE or ACCESS_ONCE() in different C statements.
 */

#define READ_ONCE(x)						\
({								\
	volatile typeof(x) *__p = &(x);				\
	*__p;							\
})

#define WRITE_ONCE(x, val)					\
({								\
	volatile typeof(x) *__p = &(x);				\
	*__p = (typeof(x)) (val);				\
})

/**
 * struct list_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *	struct child {
 *		const char *name;
 *		// Linked list of all us children.
 *		struct list_node list;
 *	};
 */
struct list_node
{
	struct list_node *next, *prev;
};

/**
 * struct list_head - the head of a doubly-linked list
 * @node: the head node
 *
 * This is used as the head of a linked list.
 * Example:
 *	struct parent {
 *		const char *name;
 *		struct list_head children;
 *		unsigned int num_children;
 *	};
 */
struct list_head
{
	struct list_node node;
};

/**
 * LIST_HEAD_INIT - initializer for an empty list_head
 * @name: the name of the list.
 *
 * Explicit initializer for an empty list.
 *
 * See also:
 *	LIST_HEAD, list_head_init()
 *
 * Example:
 *	static struct list_head my_list = LIST_HEAD_INIT(my_list);
 */
#define LIST_HEAD_INIT(name) { { &(name).node, &(name).node } }

/**
 * LIST_HEAD - define and initialize an empty list_head
 * @name: the name of the list.
 *
 * The LIST_HEAD macro defines a list_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static list_head.
 *
 * See also:
 *	LIST_HEAD_INIT, list_head_init()
 *
 * Example:
 *	static LIST_HEAD(my_global_list);
 */
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

/**
 * list_head_init - initialize a list_head
 * @h: the list_head to set to the empty list
 *
 * Example:
 *	...
 *	struct parent *parent = malloc(sizeof(*parent));
 *
 *	list_head_init(&parent->children);
 *	parent->num_children = 0;
 */
static inline void list_head_init(struct list_head *h)
{
	h->node.next = h->node.prev = &h->node;
}

/**
 * list_node_init - initialize a list_node
 * @n: the list_node to link to itself.
 *
 * You don't need to use this normally!  But it lets you list_del(@n)
 * safely.
 */
static inline void list_node_init(struct list_node *n)
{
	n->next = n->prev = n;
}

/**
 * list_add_after - add an entry after an existing node in a linked list
 * @p: the existing list_node to add the node after
 * @n: the new list_node to add to the list.
 *
 * The existing list_node must already be a member of the list.
 * The new list_node does not need to be initialized; it will be overwritten.
 *
 * Example:
 *	struct child c1, c2, c3;
 *	LIST_HEAD(h);
 *
 *	list_add_tail(&h, &c1.list);
 *	list_add_tail(&h, &c3.list);
 *	list_add_after(&c1.list, &c2.list);
 */
static inline void list_add_after(struct list_node *p,
				  struct list_node *n)
{
	n->next = p->next;
	n->prev = p;
	p->next->prev = n;
	WRITE_ONCE(p->next, n);
}

/**
 * list_add - add an entry at the start of a linked list.
 * @h: the list_head to add the node to
 * @n: the list_node to add to the list.
 *
 * The list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	struct child *child = malloc(sizeof(*child));
 *
 *	child->name = "marvin";
 *	list_add(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void list_add(struct list_head *h,
			    struct list_node *n)
{
	list_add_after(&h->node, n);
}

/**
 * list_add_before - add an entry before an existing node in a linked list
 * @p: the existing list_node to add the node before
 * @n: the new list_node to add to the list.
 *
 * The existing list_node must already be a member of the list.
 * The new list_node does not need to be initialized; it will be overwritten.
 *
 * Example:
 *	list_head_init(&h);
 *	list_add_tail(&h, &c1.list);
 *	list_add_tail(&h, &c3.list);
 *	list_add_before(&c3.list, &c2.list);
 */
static inline void list_add_before(struct list_node *p,
				   struct list_node *n)
{
	n->next = p;
	n->prev = p->prev;
	p->prev->next = n;
	WRITE_ONCE(p->prev, n);
}

/**
 * list_add_tail - add an entry at the end of a linked list.
 * @h: the list_head to add the node to
 * @n: the list_node to add to the list.
 *
 * The list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	list_add_tail(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void list_add_tail(struct list_head *h,
				 struct list_node *n)
{
	list_add_before(&h->node, n);
}

/**
 * list_empty - is a list empty?
 * @h: the list_head
 *
 * If the list is empty, returns true.
 *
 * Example:
 *	assert(list_empty(&parent->children) == (parent->num_children == 0));
 */
static inline bool list_empty(const struct list_head *h)
{
	return READ_ONCE(h->node.next) == &h->node;
}

/**
 * list_node_detached - is a node detached from any lists?
 * @n: the list_node
 *
 * If the list node is initialized and detached, return true.
 * Always use list_node_init() and list_del_init() on list nodes.
 */
static inline bool list_node_detached(const struct list_node *n)
{
	return READ_ONCE(n->next) == n;
}

/**
 * list_del - delete an entry from an (unknown) linked list.
 * @n: the list_node to delete from the list.
 *
 * Note that this leaves @n in an undefined state; it can be added to
 * another list, but not deleted again.
 *
 * See also:
 *	list_del_from(), list_del_init()
 *
 * Example:
 *	list_del(&child->list);
 *	parent->num_children--;
 */
static inline void list_del(struct list_node *n)
{
	n->next->prev = n->prev;
	n->prev->next = n->next;

	/* Catch use-after-del. */
	WRITE_ONCE(n->next, NULL);
	WRITE_ONCE(n->prev, NULL);
}

/**
 * list_del_init - delete a node, and reset it so it can be deleted again.
 * @n: the list_node to be deleted.
 *
 * list_del(@n) or list_del_init() again after this will be safe,
 * which can be useful in some cases.
 *
 * See also:
 *	list_del_from(), list_del()
 *
 * Example:
 *	list_del_init(&child->list);
 *	parent->num_children--;
 */
static inline void list_del_init(struct list_node *n)
{
	list_del(n);
	list_node_init(n);
}

#endif /* CCAN_LIST_H */
