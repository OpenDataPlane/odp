/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef PHYSMEM_BLOCK_H
#define PHYSMEM_BLOCK_H

#include <sys/queue.h>
#include <stdint.h>

typedef enum {
	BLOCK_EMPTY = 0,
	BLOCK_AVAIL,
	BLOCK_USED
} physmem_block_type_t;

/* a block is a chunk of physically contiguous memory that can be
 * made of one or more huge pages
 */
struct physmem_block {
	LIST_ENTRY(physmem_block) next;
	void *va; /* virtual address where the block is mapped */
	uint64_t pa; /* physical address where it starts */
	uint64_t size; /* the size of this memory block */
	uint32_t first; /* index of first hugepage belonging to this block
			 * in pages[] */
	uint32_t count; /* number of hugepages in this block */
	uint32_t hp_size; /* the size of the hugepages */
	uint32_t id; /* internal ID of this block, debug purposes */
	physmem_block_type_t type;
};

int physmem_block_init_global(void);
int physmem_block_term_global(void);

struct physmem_block *physmem_block_alloc(uint64_t);
void physmem_block_free(struct physmem_block *);
int physmem_block_map(struct physmem_block *block, void *addr);
int physmem_block_unmap(struct physmem_block *block);

/* if pages is not 0, it will print the pages associated to each block */
void physmem_block_dump(physmem_block_type_t, int pages);
int physmem_block_check(const struct physmem_block *);

#endif
