/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <odp_l3fwd_lpm.h>

/**
 * This is a simple implementation of lpm based on patricia tree.
 *
 * Tradeoff exists between memory consumption and lookup time.
 * Currently it prefers 5 levels: {16, 4, 4, 4, 4}, could be 3
 * levels: {16, 8, 8} by defining FIB_NEXT_STRIDE as 8. Other
 * levels are also possible.
 *
 * the ip here is host endian, when doing init or lookup, the
 * caller should do endianness conversion if needed.
 */

#define FIB_IP_WIDTH 32
#define FIB_FIRST_STRIDE 16
#define FIB_NEXT_STRIDE 4
#define FIB_NEXT_SIZE (1 << FIB_NEXT_STRIDE)
#define FIB_SUB_COUNT 16384
#define DEPTH_TO_MASK(depth) ((1 << (depth)) - 1)

typedef struct fib_node_s {
	union {
		uint32_t next_hop;
		struct fib_node_s *next; /* next level table */
	};
	uint8_t valid	:1; /* 1, this node has a valid next hop */
	uint8_t end	:1; /* 0, next points to the extended table */
	uint8_t depth	:6; /* bit length of subnet mask */
} fib_node_t;

typedef struct fib_sub_tbl_s {
	fib_node_t *fib_nodes;
	uint32_t fib_count;
	uint32_t fib_idx;
} fib_sub_tbl_t;

static fib_node_t fib_rt_tbl[1 << FIB_FIRST_STRIDE];
static fib_sub_tbl_t fib_lpm_cache;

static inline fib_node_t *fib_alloc_sub(void)
{
	fib_node_t *sub_tbl = NULL;
	uint32_t i, nb_entry;

	/* extend to next level */
	if (fib_lpm_cache.fib_idx < fib_lpm_cache.fib_count) {
		nb_entry = (fib_lpm_cache.fib_idx + 1) * FIB_NEXT_SIZE;
		sub_tbl = &fib_lpm_cache.fib_nodes[nb_entry];
		fib_lpm_cache.fib_idx++;
		for (i = 0; i < nb_entry; i++) {
			sub_tbl[i].valid = 0;
			sub_tbl[i].end = 1;
		}
	}

	return sub_tbl;
}

static void fib_update_node(fib_node_t *fe, int port, int depth)
{
	fib_node_t *p;
	int i;

	if (fe->end) {
		if (!fe->valid) {
			fe->depth = depth;
			fe->next_hop = port;
			fe->valid = 1;
		} else if (fe->depth <= depth) {
			fe->next_hop = port;
			fe->depth = depth;
		}

		return;
	}

	for (i = 0; i < FIB_NEXT_SIZE; i++) {
		p = &fe->next[i];
		if (p->end)
			fib_update_node(p, port, depth);
	}
}

static void fib_insert_node(fib_node_t *fe, uint32_t ip, uint32_t next_hop,
			    int ip_width, int eat_bits, int depth)
{
	int i;
	uint32_t idx, port;
	fib_node_t *p;

	if (fe->end) {
		port = fe->next_hop;
		p = fib_alloc_sub();
		if (!p)
			return;

		fe->next = p;
		fe->end = 0;
		if (fe->valid) {
			for (i = 0; i < FIB_NEXT_SIZE; i++) {
				p = &fe->next[i];
				p->next_hop = port;
				p->depth = fe->depth;
			}
		}
	}
	if (depth - eat_bits <= FIB_NEXT_STRIDE) {
		ip_width -= depth - eat_bits;
		idx = ip >> ip_width;
		ip &= DEPTH_TO_MASK(ip_width);
		p = &fe->next[idx];
		fib_update_node(p, next_hop, depth);
	} else {
		ip_width -= FIB_NEXT_STRIDE;
		idx = ip >> ip_width;
		p = &fe->next[idx];
		ip &= DEPTH_TO_MASK(ip_width);
		eat_bits += FIB_NEXT_STRIDE;
		fib_insert_node(p, ip, next_hop, ip_width, eat_bits, depth);
	}
}

void fib_tbl_init(void)
{
	int i;
	fib_node_t *fe;
	uint32_t size;
	odp_shm_t lpm_shm;

	for (i = 0; i < (1 << FIB_FIRST_STRIDE); i++) {
		fe = &fib_rt_tbl[i];
		fe->valid = 0;
		fe->end = 1;
		fe->depth = 0;
		fe->next_hop = 0;
	}

	size = FIB_NEXT_SIZE * FIB_SUB_COUNT;
	/*Reserve memory for Routing hash table*/
	lpm_shm = odp_shm_reserve("fib_lpm_sub", size, ODP_CACHE_LINE_SIZE, 0);
	if (lpm_shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	fe = odp_shm_addr(lpm_shm);
	if (!fe) {
		ODPH_ERR("Error: shared mem alloc failed for lpm cache.\n");
		exit(-1);
	}

	fib_lpm_cache.fib_nodes = fe;
	fib_lpm_cache.fib_count = FIB_SUB_COUNT;
	fib_lpm_cache.fib_idx = 0;
}

void fib_tbl_insert(uint32_t ip, int port, int depth)
{
	fib_node_t *fe, *p;
	uint32_t idx;
	int i, j;
	int nb_bits;

	nb_bits = FIB_FIRST_STRIDE;
	idx = ip >> (FIB_IP_WIDTH - nb_bits);
	fe = &fib_rt_tbl[idx];
	if (depth <= nb_bits) {
		if (fe->end) {
			fe->next_hop = port;
			fe->depth = depth;
			fe->valid = 1;
			return;
		}

		for (i = 0; i < FIB_NEXT_SIZE; i++) {
			p = &fe->next[i];
			if (p->end)
				fib_update_node(p, port, depth);
			else
				for (j = 0; j < FIB_NEXT_SIZE; j++)
					fib_update_node(&p->next[j], port,
							depth);
		}

		return;
	}

	/* need to check sub table */
	ip &= DEPTH_TO_MASK(FIB_IP_WIDTH - nb_bits);
	fib_insert_node(fe, ip, port, FIB_IP_WIDTH - nb_bits, nb_bits, depth);
}

int fib_tbl_lookup(uint32_t ip, int *port)
{
	fib_node_t *fe;
	uint32_t idx;
	int nb_bits;

	nb_bits = FIB_IP_WIDTH - FIB_FIRST_STRIDE;
	idx = ip >> nb_bits;
	fe = &fib_rt_tbl[idx];

	ip &= DEPTH_TO_MASK(nb_bits);
	while (!fe->end) {
		nb_bits -= FIB_NEXT_STRIDE;
		idx = ip >> nb_bits;
		fe = &fe->next[idx];
		ip &= DEPTH_TO_MASK(nb_bits);
	}
	*port = fe->next_hop;

	return fe->valid ? 0 : -1;
}
