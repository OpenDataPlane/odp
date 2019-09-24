/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include <odp/helper/odph_iplookuptable.h>
#include <odp/helper/odph_debug.h>
#include "odph_list_internal.h"
#include <odp_api.h>

/** @magic word, write to the first byte of the memory block
 *   to indicate this block is used by a ip lookup table
 */
#define ODPH_IP_LOOKUP_TABLE_MAGIC_WORD 0xCFCFFCFC

/* The length(bit) of the IPv4 address */
#define IP_LENGTH 32

/* The number of L1 entries */
#define ENTRY_NUM_L1		(1 << 16)
/* The size of one L2\L3 subtree */
#define ENTRY_NUM_SUBTREE	(1 << 8)

#define WHICH_CHILD(ip, cidr) ((ip >> (IP_LENGTH - cidr)) & 0x00000001)

/** @internal entry struct
 *   Structure store an entry of the ip prefix table.
 *   Because of the leaf pushing, each entry of the table must have
 *   either a child entry, or a nexthop info.
 *   If child == 0 and index != ODP_BUFFER_INVALID, this entry has
 *		a nexthop info, index indicates the buffer that stores the
 *		nexthop value, and ptr points to the address of the buffer.
 *   If child == 1, this entry has a subtree, index indicates
 *		the buffer that stores the subtree, and ptr points to the
 *		address of the buffer.
 */
typedef struct {
	union {
		odp_buffer_t nexthop;
		void *ptr;
	};
	union {
		uint8_t u8;
		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint8_t child : 1;
			uint8_t cidr  : 7;
#else
			uint8_t cidr  : 7;
			uint8_t child : 1;
#endif
		};
	};
} prefix_entry_t;

#define ENTRY_SIZE (sizeof(prefix_entry_t) + sizeof(odp_buffer_t))
#define ENTRY_BUFF_ARR(x) ((odp_buffer_t *)(void *)((char *)x \
			+ sizeof(prefix_entry_t) * ENTRY_NUM_SUBTREE))

/** @internal trie node struct
 *  In this IP lookup algorithm, we use a
 *  binary tire to detect the overlap prefix.
 */
typedef struct trie_node {
	/* tree structure */
	struct trie_node *parent;
	struct trie_node *left;
	struct trie_node *right;
	/* IP prefix length */
	uint8_t cidr;
	/* Nexthop buffer index */
	odp_buffer_t nexthop;
	/* Buffer that stores this node */
	odp_buffer_t buffer;
} trie_node_t;

/** Number of L2\L3 entries(subtrees) per cache cube. */
#define CACHE_NUM_SUBTREE	(4 * 1024)
/** Number of trie nodes per cache cube. */
#define CACHE_NUM_TRIE		(4 * 1024)

/** @typedef cache_type_t
 *	Cache node type
 */
typedef enum {
	CACHE_TYPE_SUBTREE = 0,
	CACHE_TYPE_TRIE
} cache_type_t;

/** A IP lookup table structure. */
typedef struct ODP_ALIGNED_CACHE {
	/**< for check */
	uint32_t magicword;
	/** Name of the hash. */
	char name[ODPH_TABLE_NAME_LEN];
	/** Total L1 entries. */
	prefix_entry_t *l1e;
	/** Root node of the binary trie */
	trie_node_t *trie;
	/** Length of value. */
	uint32_t nexthop_len;
	/** Queues of free slots (caches)
	 *  There are two queues:
	 *  - free_slots[CACHE_TYPE_SUBTREE] is used for L2 and
	 *    L3 entries (subtrees). Each entry stores an 8-bit
	 *    subtree.
	 *  - free_slots[CACHE_TYPE_TRIE] is used for the binary
	 *    trie. Each entry contains a trie node.
	 */
	odp_queue_t free_slots[2];
	/** The number of pool used by each queue. */
	uint32_t cache_count[2];
} odph_iplookup_table_impl;

/***********************************************************
 *****************   Cache management   ********************
 ***********************************************************/

/** Destroy all caches */
static void
cache_destroy(odph_iplookup_table_impl *impl)
{
	odp_queue_t queue;
	odp_event_t ev;
	uint32_t i = 0, count = 0;
	char pool_name[ODPH_TABLE_NAME_LEN + 8];

	/* free all buffers in the queue */
	for (; i < 2; i++) {
		queue = impl->free_slots[i];
		if (queue == ODP_QUEUE_INVALID)
			continue;

		while ((ev = odp_queue_deq(queue))
				!= ODP_EVENT_INVALID) {
			odp_buffer_free(odp_buffer_from_event(ev));
		}
		odp_queue_destroy(queue);
	}

	/* destroy all cache pools */
	for (i = 0; i < 2; i++) {
		for (count = 0; count < impl->cache_count[i]; count++) {
			sprintf(
					pool_name, "%s_%d_%d",
					impl->name, i, count);
			odp_pool_destroy(odp_pool_lookup(pool_name));
		}
	}
}

/** According to the type of cahce, set the value of
 *  a buffer to the initial value.
 */
static void
cache_init_buffer(odp_buffer_t buffer, cache_type_t type, uint32_t size)
{
	int i = 0;
	void *addr = odp_buffer_addr(buffer);

	memset(addr, 0, size);
	if (type == CACHE_TYPE_SUBTREE) {
		prefix_entry_t *entry = (prefix_entry_t *)addr;

		for (i = 0; i < ENTRY_NUM_SUBTREE; i++, entry++)
			entry->nexthop = ODP_BUFFER_INVALID;
	} else if (type == CACHE_TYPE_TRIE) {
		trie_node_t *node = (trie_node_t *)addr;

		node->buffer = buffer;
		node->nexthop = ODP_BUFFER_INVALID;
	}
}

/** Create a new buffer pool, and insert its buffer into the queue. */
static int
cache_alloc_new_pool(
		odph_iplookup_table_impl *tbl, cache_type_t type)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_pool_capability_t pool_capa;
	odp_queue_t queue = tbl->free_slots[type];

	odp_buffer_t buffer;
	char pool_name[ODPH_TABLE_NAME_LEN + 8];
	uint32_t size = 0, num = 0;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("pool capa failed\n");
		return -1;
	}

	if (pool_capa.buf.max_num) {
		if (pool_capa.buf.max_num < CACHE_NUM_TRIE ||
		    pool_capa.buf.max_num < CACHE_NUM_SUBTREE) {
			ODPH_ERR("pool size too small\n");
			return -1;
		}
	}

	if (pool_capa.buf.max_size) {
		if (pool_capa.buf.max_size < ENTRY_SIZE * ENTRY_NUM_SUBTREE ||
		    pool_capa.buf.max_size < sizeof(trie_node_t)) {
			ODPH_ERR("buffer size too small\n");
			return -1;
		}
	}

	/* Create new pool (new free buffers). */
	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.buf.align = ODP_CACHE_LINE_SIZE;
	if (type == CACHE_TYPE_SUBTREE) {
		num = CACHE_NUM_SUBTREE;
		size = ENTRY_SIZE * ENTRY_NUM_SUBTREE;
	} else if (type == CACHE_TYPE_TRIE) {
		num = CACHE_NUM_TRIE;
		size = sizeof(trie_node_t);
	} else {
		ODPH_DBG("wrong cache_type_t.\n");
		return -1;
	}
	param.buf.size = size;
	param.buf.num = num;

	sprintf(
			pool_name, "%s_%d_%d",
			tbl->name, type, tbl->cache_count[type]);
	pool = odp_pool_create(pool_name, &param);
	if (pool == ODP_POOL_INVALID) {
		ODPH_DBG("failed to create a new pool.\n");
		return -1;
	}

	/* insert new free buffers into queue */
	while ((buffer = odp_buffer_alloc(pool))
			!= ODP_BUFFER_INVALID) {
		cache_init_buffer(buffer, type, size);
		if (odp_queue_enq(queue, odp_buffer_to_event(buffer))) {
			ODPH_DBG("queue enqueue failed\n");
			odp_buffer_free(buffer);
			break;
		}
	}

	tbl->cache_count[type]++;
	return 0;
}

/** Get a new buffer from a cache list. If there is no
 *  available buffer, allocate a new pool.
 */
static odp_buffer_t
cache_get_buffer(odph_iplookup_table_impl *tbl, cache_type_t type)
{
	odp_buffer_t buffer = ODP_BUFFER_INVALID;
	odp_queue_t queue = tbl->free_slots[type];

	/* get free buffer from queue */
	buffer = odp_buffer_from_event(
				odp_queue_deq(queue));

	/* If there is no free buffer available, allocate new pool */
	if (buffer == ODP_BUFFER_INVALID) {
		cache_alloc_new_pool(tbl, type);
		buffer = odp_buffer_from_event(odp_queue_deq(queue));
	}

	return buffer;
}

/***********************************************************
 ******************     Binary trie     ********************
 ***********************************************************/

/* Initialize the root node of the trie */
static int
trie_init(odph_iplookup_table_impl *tbl)
{
	trie_node_t *root = NULL;
	odp_buffer_t buffer = cache_get_buffer(tbl, CACHE_TYPE_TRIE);

	if (buffer != ODP_BUFFER_INVALID) {
		root = (trie_node_t *)odp_buffer_addr(buffer);
		root->cidr = 0;
		tbl->trie = root;
		return 0;
	}

	return -1;
}

/* Destroy the whole trie (recursively) */
static void
trie_destroy(odph_iplookup_table_impl *tbl, trie_node_t *trie)
{
	if (trie->left != NULL)
		trie_destroy(tbl, trie->left);
	if (trie->right != NULL)
		trie_destroy(tbl, trie->right);

	/* destroy this node */
	odp_queue_enq(
			tbl->free_slots[CACHE_TYPE_TRIE],
			odp_buffer_to_event(trie->buffer));
}

/* Insert a new prefix node into the trie
 * If the node is already existed, update its nexthop info,
 *   Return 0 and set nexthop pointer to INVALID.
 * If the node is not exitsed, create this target node and
 *   all nodes along the path from root to the target node.
 *   Then return 0 and set nexthop pointer points to the
 *   new buffer.
 * Return -1 for error.
 */
static int
trie_insert_node(
		odph_iplookup_table_impl *tbl, trie_node_t *root,
		uint32_t ip, uint8_t cidr, odp_buffer_t nexthop)
{
	uint8_t level = 0, child;
	odp_buffer_t buf;
	trie_node_t *node = root, *prev = root;

	/* create/update all nodes along the path
	 * from root to the new node. */
	for (level = 1; level <= cidr; level++) {
		child = WHICH_CHILD(ip, level);

		node = child == 0 ? prev->left : prev->right;
		/* If the child node doesn't exit, create it. */
		if (node == NULL) {
			buf = cache_get_buffer(tbl, CACHE_TYPE_TRIE);
			if (buf == ODP_BUFFER_INVALID)
				return -1;

			node = (trie_node_t *)odp_buffer_addr(buf);
			node->cidr = level;
			node->parent = prev;

			if (child == 0)
				prev->left = node;
			else
				prev->right = node;
		}
		prev = node;
	}

	/* The final one is the target. */
	node->nexthop = nexthop;
	return 0;
}

/* Delete a node */
static int
trie_delete_node(
		odph_iplookup_table_impl *tbl,
		trie_node_t *root, uint32_t ip, uint8_t cidr)
{
	if (root == NULL)
		return -1;

	/* The default prefix (root node) cannot be deleted. */
	if (cidr == 0)
		return -1;

	trie_node_t *node = root, *prev = NULL;
	uint8_t level = 1, child = 0;
	odp_buffer_t tmp;

	/* Find the target node. */
	for (level = 1; level <= cidr; level++) {
		child = WHICH_CHILD(ip, level);
		node = (child == 0) ? node->left : node->right;
		if (node == NULL) {
			ODPH_DBG("Trie node is not existed\n");
			return -1;
		}
	}

	node->nexthop = ODP_BUFFER_INVALID;

	/* Delete all redundant nodes along the path. */
	for (level = cidr; level > 0; level--) {
		if (
			node->left != NULL || node->right != NULL ||
			node->nexthop != ODP_BUFFER_INVALID)
			break;

		child = WHICH_CHILD(ip, level);
		prev = node->parent;

		/* free trie node */
		tmp = node->buffer;
		cache_init_buffer(
				tmp, CACHE_TYPE_TRIE, sizeof(trie_node_t));
		odp_queue_enq(
				tbl->free_slots[CACHE_TYPE_TRIE],
				odp_buffer_to_event(tmp));

		if (child == 0)
			prev->left = NULL;
		else
			prev->right = NULL;
		node = prev;
	}
	return 0;
}

/* Detect the longest overlapping prefix. */
static int
trie_detect_overlap(
		trie_node_t *trie, uint32_t ip, uint8_t cidr,
		uint8_t leaf_push, uint8_t *over_cidr,
		odp_buffer_t *over_nexthop)
{
	uint8_t child = 0;
	uint32_t level, limit = cidr > leaf_push ? leaf_push + 1 : cidr;
	trie_node_t *node = trie, *longest = trie;

	for (level = 1; level < limit; level++) {
		child = WHICH_CHILD(ip, level);
		node = (child == 0) ? node->left : node->right;
		if (node->nexthop != ODP_BUFFER_INVALID)
			longest = node;
	}

	*over_cidr = longest->cidr;
	*over_nexthop = longest->nexthop;
	return 0;
}

/***********************************************************
 ***************   IP prefix lookup table   ****************
 ***********************************************************/

odph_table_t
odph_iplookup_table_lookup(const char *name)
{
	odph_iplookup_table_impl *tbl = NULL;
	odp_shm_t shm;

	if (name == NULL || strlen(name) >= ODPH_TABLE_NAME_LEN)
		return NULL;

	shm = odp_shm_lookup(name);
	if (shm != ODP_SHM_INVALID)
		tbl = (odph_iplookup_table_impl *)odp_shm_addr(shm);

	if (
		tbl != NULL &&
		tbl->magicword == ODPH_IP_LOOKUP_TABLE_MAGIC_WORD &&
		strcmp(tbl->name, name) == 0)
		return (odph_table_t)tbl;

	return NULL;
}

odph_table_t odph_iplookup_table_create(const char *name,
					uint32_t p1 ODP_UNUSED,
					uint32_t p2 ODP_UNUSED,
					uint32_t value_size)
{
	odph_iplookup_table_impl *tbl;
	odp_shm_t shm_tbl;
	odp_queue_t queue;
	odp_queue_param_t qparam;
	odp_queue_capability_t queue_capa;
	unsigned i;
	uint32_t impl_size, l1_size, queue_size;
	char queue_name[ODPH_TABLE_NAME_LEN + 2];

	if (odp_queue_capability(&queue_capa)) {
		ODPH_ERR("queue capa failed\n");
		return NULL;
	}

	if (queue_capa.plain.max_size) {
		if (queue_capa.plain.max_size < CACHE_NUM_TRIE ||
		    queue_capa.plain.max_size < CACHE_NUM_SUBTREE) {
			ODPH_ERR("queue size too small\n");
			return NULL;
		}
	}

	queue_size = CACHE_NUM_TRIE;
	if (CACHE_NUM_SUBTREE > CACHE_NUM_TRIE)
		queue_size = CACHE_NUM_SUBTREE;

	/* Check for valid parameters */
	if (strlen(name) == 0) {
		ODPH_DBG("invalid parameters\n");
		return NULL;
	}

	/* Guarantee there's no existing */
	tbl = (void *)odph_iplookup_table_lookup(name);
	if (tbl != NULL) {
		ODPH_DBG("IP prefix table %s already exists\n", name);
		return NULL;
	}

	/* Calculate the sizes of different parts of IP prefix table */
	impl_size = sizeof(odph_iplookup_table_impl);
	l1_size = ENTRY_SIZE * ENTRY_NUM_L1;

	shm_tbl = odp_shm_reserve(
				name, impl_size + l1_size,
				ODP_CACHE_LINE_SIZE, ODP_SHM_SW_ONLY);

	if (shm_tbl == ODP_SHM_INVALID) {
		ODPH_DBG(
			"shm allocation failed for odph_iplookup_table_impl %s\n",
			name);
		return NULL;
	}

	tbl = (odph_iplookup_table_impl *)odp_shm_addr(shm_tbl);
	memset(tbl, 0, impl_size + l1_size);

	/* header of this mem block is the table impl struct,
	 * then the l1 entries array.
	 */
	tbl->l1e = (prefix_entry_t *)(void *)((char *)tbl + impl_size);
	for (i = 0; i < ENTRY_NUM_L1; i++)
		tbl->l1e[i].nexthop = ODP_BUFFER_INVALID;

	/* Setup table context. */
	snprintf(tbl->name, sizeof(tbl->name), "%s", name);
	tbl->magicword = ODPH_IP_LOOKUP_TABLE_MAGIC_WORD;
	tbl->nexthop_len = value_size;

	/* Initialize cache */
	for (i = 0; i < 2; i++) {
		tbl->cache_count[i] = 0;

		odp_queue_param_init(&qparam);
		qparam.type = ODP_QUEUE_TYPE_PLAIN;
		qparam.size = queue_size;
		sprintf(queue_name, "%s_%d", name, i);
		queue = odp_queue_create(queue_name, &qparam);
		if (queue == ODP_QUEUE_INVALID) {
			ODPH_DBG("failed to create queue");
			cache_destroy(tbl);
			return NULL;
		}
		tbl->free_slots[i] = queue;
		cache_alloc_new_pool(tbl, i);
	}

	/* Initialize tire */
	if (trie_init(tbl) < 0) {
		odp_shm_free(shm_tbl);
		return NULL;
	}

	return (odph_table_t)tbl;
}

int
odph_iplookup_table_destroy(odph_table_t tbl)
{
	int i, j;
	odph_iplookup_table_impl *impl = NULL;
	prefix_entry_t *subtree = NULL;
	odp_buffer_t *buff1 = NULL, *buff2 = NULL;

	if (tbl == NULL)
		return -1;

	impl = (odph_iplookup_table_impl *)(void *)tbl;

	/* check magic word */
	if (impl->magicword != ODPH_IP_LOOKUP_TABLE_MAGIC_WORD) {
		ODPH_DBG("wrong magicword for IP prefix table\n");
		return -1;
	}

	/* destroy trie */
	trie_destroy(impl, impl->trie);

	/* free all L2 and L3 entries */
	buff1 = ENTRY_BUFF_ARR(impl->l1e);
	for (i = 0; i < ENTRY_NUM_L1; i++) {
		if ((impl->l1e[i]).child == 0)
			continue;

		subtree = (prefix_entry_t *)impl->l1e[i].ptr;
		buff2 = ENTRY_BUFF_ARR(subtree);
		/* destroy all l3 subtrees of this l2 subtree */
		for (j = 0; j < ENTRY_NUM_SUBTREE; j++) {
			if (subtree[j].child == 0)
				continue;
			odp_queue_enq(
					impl->free_slots[CACHE_TYPE_TRIE],
					odp_buffer_to_event(buff2[j]));
		}
		/* destroy this l2 subtree */
		odp_queue_enq(
				impl->free_slots[CACHE_TYPE_TRIE],
				odp_buffer_to_event(buff1[i]));
	}

	/* destroy all cache */
	cache_destroy(impl);

	/* free impl */
	odp_shm_free(odp_shm_lookup(impl->name));
	return 0;
}

/* Insert the prefix into level x
 * Return:
 *   -1	error
 *   0	the table is unmodified
 *   1	the table is modified
 */
static int
prefix_insert_into_lx(
		odph_iplookup_table_impl *tbl, prefix_entry_t *entry,
		uint8_t cidr, odp_buffer_t nexthop, uint8_t level)
{
	int ret = 0;
	uint32_t i = 0, limit = (1 << (level - cidr));
	prefix_entry_t *e = entry, *ne = NULL;

	for (i = 0; i < limit; i++, e++) {
		if (e->cidr > cidr)
			continue;

		if (e->child == 1) {
			e->cidr = cidr;
			/* push to next level */
			ne = (prefix_entry_t *)e->ptr;
			ret = prefix_insert_into_lx(
					tbl, ne, cidr, nexthop, cidr + 8);
			if (ret == -1)
				return -1;
			if (ret == 0)
				return ret;
		} else {
			e->child = 0;
			e->cidr = cidr;
			e->nexthop = nexthop;
			ret = 1;
		}
	}
	return ret;
}

static int
prefix_insert_iter(
		odph_iplookup_table_impl *tbl, prefix_entry_t *entry,
		odp_buffer_t *buff, uint32_t ip, uint8_t cidr,
		odp_buffer_t nexthop, uint8_t level, uint8_t depth)
{
	uint8_t state = 0;
	prefix_entry_t *ne = NULL;
	odp_buffer_t *nbuff = NULL;

	/* If child subtree is existed, get it. */
	if (entry->child) {
		ne = (prefix_entry_t *)entry->ptr;
		nbuff = ENTRY_BUFF_ARR(ne);
	} else {
		/* If the child is not existed, create a new subtree. */
		odp_buffer_t buf, push = entry->nexthop;

		buf = cache_get_buffer(tbl, CACHE_TYPE_SUBTREE);
		if (buf == ODP_BUFFER_INVALID) {
			ODPH_DBG("failed to get subtree buffer from cache.\n");
			return -1;
		}
		ne = (prefix_entry_t *)odp_buffer_addr(buf);
		nbuff = ENTRY_BUFF_ARR(ne);

		entry->child = 1;
		entry->ptr = ne;
		*buff = buf;

		/* If this entry contains a nexthop and a small cidr,
		 * push it to the next level.
		 */
		if (entry->cidr > 0)
			(void)prefix_insert_into_lx(tbl, ne, entry->cidr,
						    push, entry->cidr + 8);
	}

	ne += (ip >> 24);
	nbuff += (ip >> 24);
	if (cidr <= 8) {
		state = prefix_insert_into_lx(
				tbl, ne, cidr + depth * 8, nexthop, level);
	} else {
		state = prefix_insert_iter(
				tbl, ne, nbuff, ip << 8, cidr - 8,
				nexthop, level + 8, depth + 1);
	}

	return state;
}

int
odph_iplookup_table_put_value(odph_table_t tbl, void *key, void *value)
{
	odph_iplookup_table_impl *impl = (void *)tbl;
	odph_iplookup_prefix_t *prefix = (odph_iplookup_prefix_t *)key;
	prefix_entry_t *l1e = NULL;
	odp_buffer_t nexthop;
	int ret = 0;

	if ((tbl == NULL) || (key == NULL) || (value == NULL))
		return -1;

	nexthop = *((odp_buffer_t *)value);

	if (prefix->cidr == 0 || prefix->cidr > 32)
		return -1;

	prefix->ip = prefix->ip & (0xffffffff << (IP_LENGTH - prefix->cidr));

	/* insert into trie */
	ret = trie_insert_node(
				impl, impl->trie,
				prefix->ip, prefix->cidr, nexthop);

	if (ret < 0) {
		ODPH_DBG("failed to insert into trie\n");
		return -1;
	}

	/* get L1 entry */
	l1e = &impl->l1e[prefix->ip >> 16];
	odp_buffer_t *buff = ENTRY_BUFF_ARR(impl->l1e) + (prefix->ip >> 16);

	if (prefix->cidr <= 16) {
		ret = prefix_insert_into_lx(
				impl, l1e, prefix->cidr, nexthop, 16);
	} else {
		ret = prefix_insert_iter(
				impl, l1e, buff,
				((prefix->ip) << 16), prefix->cidr - 16,
				nexthop, 24, 2);
	}

	return ret;
}

int odph_iplookup_table_get_value(odph_table_t tbl, void *key,
				  void *buffer ODP_UNUSED,
				  uint32_t buffer_size ODP_UNUSED)
{
	odph_iplookup_table_impl *impl = (void *)tbl;
	uint32_t ip;
	prefix_entry_t *entry;
	odp_buffer_t *buff = (odp_buffer_t *)buffer;

	if ((tbl == NULL) || (key == NULL) || (buffer == NULL))
		return -EINVAL;

	ip = *((uint32_t *)key);
	entry = &impl->l1e[ip >> 16];

	if (entry == NULL) {
		ODPH_DBG("failed to get L1 entry.\n");
		return -1;
	}

	ip <<= 16;
	while (entry->child) {
		entry = (prefix_entry_t *)entry->ptr;
		entry += ip >> 24;
		ip <<= 8;
	}

	/* copy data */
	if (entry->nexthop == ODP_BUFFER_INVALID) {
		/* ONLY match the default prefix */
		printf("only match the default prefix\n");
		*buff = ODP_BUFFER_INVALID;
	} else {
		*buff = entry->nexthop;
	}

	return 0;
}

static int
prefix_delete_lx(
		odph_iplookup_table_impl *tbl, prefix_entry_t *l1e,
		odp_buffer_t *buff, uint8_t cidr, uint8_t over_cidr,
		odp_buffer_t over_nexthop, uint8_t level)
{
	uint8_t ret, flag = 1;
	prefix_entry_t *e = l1e;
	odp_buffer_t *b = buff;
	uint32_t i = 0, limit = 1 << (level - cidr);

	for (i = 0; i < limit; i++, e++, b++) {
		if (e->child == 1) {
			if (e->cidr > cidr) {
				flag = 0;
				continue;
			}

			prefix_entry_t *ne = (prefix_entry_t *)e->ptr;
			odp_buffer_t *nbuff = ENTRY_BUFF_ARR(ne);

			e->cidr = over_cidr;
			ret = prefix_delete_lx(
					tbl, ne, nbuff, cidr, over_cidr,
					over_nexthop, cidr + 8);

			/* If ret == 1, the next 2^8 entries equal to
			 * (over_cidr, over_nexthop). In this case, we
			 * should not push the (over_cidr, over_nexthop)
			 * to the next level. In fact, we should recycle
			 * the next 2^8 entries.
			 */
			if (ret) {
				/* destroy subtree */
				cache_init_buffer(
					*b, CACHE_TYPE_SUBTREE,
					ENTRY_SIZE * ENTRY_NUM_SUBTREE);
				odp_queue_enq(
					tbl->free_slots[CACHE_TYPE_SUBTREE],
					odp_buffer_to_event(*b));
				e->child = 0;
				e->nexthop = over_nexthop;
			} else {
				flag = 0;
			}
		} else {
			if (e->cidr > cidr) {
				flag = 0;
				continue;
			} else {
				e->cidr = over_cidr;
				e->nexthop = over_nexthop;
			}
		}
	}
	return flag;
}

/* Check if the entry can be recycled.
 * An entry can be recycled duo to two reasons:
 * - all children of the entry are the same,
 * - all children of the entry have a cidr smaller than the level
 *   bottom bound.
 */
static uint8_t
can_recycle(prefix_entry_t *e, uint32_t level)
{
	uint8_t recycle = 1;
	int i = 1;
	prefix_entry_t *ne = (prefix_entry_t *)e->ptr;

	if (ne->child)
		return 0;

	uint8_t cidr = ne->cidr;
	odp_buffer_t index = ne->nexthop;

	if (cidr > level)
		return 0;

	ne++;
	for (; i < 256; i++, ne++) {
		if (
				ne->child != 0 || ne->cidr != cidr ||
				ne->nexthop != index) {
			recycle = 0;
			break;
		}
	}
	return recycle;
}

static uint8_t
prefix_delete_iter(
		odph_iplookup_table_impl *tbl, prefix_entry_t *e,
		odp_buffer_t *buff, uint32_t ip, uint8_t cidr,
		uint8_t level, uint8_t depth)
{
	uint8_t ret = 0, over_cidr;
	odp_buffer_t over_nexthop;

	trie_detect_overlap(
			tbl->trie, ip, cidr + 8 * depth, level,
			&over_cidr, &over_nexthop);
	if (cidr > 8) {
		prefix_entry_t *ne =
			(prefix_entry_t *)e->ptr;
		odp_buffer_t *nbuff = ENTRY_BUFF_ARR(ne);

		ne += ((uint32_t)(ip << level) >> 24);
		nbuff += ((uint32_t)(ip << level) >> 24);
		ret = prefix_delete_iter(
				tbl, ne, nbuff, ip, cidr - 8,
				level + 8, depth + 1);

		if (ret && can_recycle(e, level)) {
			/* destroy subtree */
			cache_init_buffer(
				*buff, CACHE_TYPE_SUBTREE,
				ENTRY_SIZE * ENTRY_NUM_SUBTREE);
			odp_queue_enq(
				tbl->free_slots[CACHE_TYPE_SUBTREE],
				odp_buffer_to_event(*buff));
			e->child = 0;
			e->nexthop = over_nexthop;
			e->cidr = over_cidr;
			return 1;
		}
		return 0;
	}

	ret = prefix_delete_lx(
			tbl, e, buff, cidr + 8 * depth,
			over_cidr, over_nexthop, level);
	return ret;
}

int
odph_iplookup_table_remove_value(odph_table_t tbl, void *key)
{
	odph_iplookup_table_impl *impl = (void *)tbl;
	odph_iplookup_prefix_t *prefix = (odph_iplookup_prefix_t *)key;
	uint32_t ip;
	uint8_t cidr;

	if ((tbl == NULL) || (key == NULL))
		return -EINVAL;

	ip   = prefix->ip;
	cidr = prefix->cidr;

	if (cidr == 0 || cidr > 32)
		return -EINVAL;

	prefix_entry_t *entry = &impl->l1e[ip >> 16];
	odp_buffer_t *buff = ENTRY_BUFF_ARR(impl->l1e) + (ip >> 16);
	uint8_t over_cidr, ret;
	odp_buffer_t over_nexthop;

	trie_detect_overlap(
			impl->trie, ip, cidr, 16, &over_cidr, &over_nexthop);

	if (cidr <= 16) {
		prefix_delete_lx(
			impl, entry, buff, cidr, over_cidr, over_nexthop, 16);
	} else {
		prefix_entry_t *ne = (prefix_entry_t *)entry->ptr;
		odp_buffer_t *nbuff = ENTRY_BUFF_ARR(ne);

		ne += ((uint32_t)(ip << 16) >> 24);
		nbuff += ((uint32_t)(ip << 16) >> 24);
		ret = prefix_delete_iter(impl, ne, nbuff, ip, cidr - 16, 24, 2);

		if (ret && can_recycle(entry, 16)) {
			/* destroy subtree */
			cache_init_buffer(
				*buff, CACHE_TYPE_SUBTREE,
				sizeof(prefix_entry_t) * ENTRY_NUM_SUBTREE);
			odp_queue_enq(
				impl->free_slots[CACHE_TYPE_SUBTREE],
				odp_buffer_to_event(*buff));
			entry->child = 0;
			entry->cidr = over_cidr;
			entry->nexthop = over_nexthop;
		}
	}

	return trie_delete_node(impl, impl->trie, ip, cidr);
}

odph_table_ops_t odph_iplookup_table_ops = {
	odph_iplookup_table_create,
	odph_iplookup_table_lookup,
	odph_iplookup_table_destroy,
	odph_iplookup_table_put_value,
	odph_iplookup_table_get_value,
	odph_iplookup_table_remove_value
};
