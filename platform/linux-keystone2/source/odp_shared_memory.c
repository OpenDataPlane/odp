/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_shared_memory.h>
#include <odp_shared_memory_internal.h>
#include <odp_internal.h>
#include <odp_spinlock.h>
#include <odp_align.h>
#include <odp_system_info.h>
#include <odp_debug.h>

#include <sys/mman.h>
#ifdef __powerpc__
#include <asm/mman.h>
#endif
#include <fcntl.h>

#include <stdio.h>
#include <string.h>

#include <ti_em_rh.h>

#define ODP_SHM_NUM_BLOCKS 32


typedef struct {
	char name[ODP_SHM_NAME_LEN];
	uint64_t size;
	uint64_t align;
	void *addr;
	int huge;
	ti_em_rh_mem_config_t mem_config;
} odp_shm_block_t;


typedef struct {
	odp_shm_block_t block[ODP_SHM_NUM_BLOCKS];
	odp_spinlock_t  lock;

} odp_shm_table_t;


#define SHM_FLAGS (MAP_SHARED | MAP_ANONYMOUS)


/* Global shared memory table */
static odp_shm_table_t *odp_shm_tbl;


int odp_shm_init_global(void)
{
	void *addr;

#ifndef MAP_HUGETLB
	ODP_DBG("NOTE: mmap does not support huge pages\n");
#endif

	addr = mmap(NULL, sizeof(odp_shm_table_t),
		    PROT_READ | PROT_WRITE, SHM_FLAGS, -1, 0);

	if (addr == MAP_FAILED)
		return -1;

	odp_shm_tbl = addr;

	memset(odp_shm_tbl, 0, sizeof(odp_shm_table_t));
	odp_spinlock_init(&odp_shm_tbl->lock);

	return 0;
}


int odp_shm_init_local(void)
{
	return 0;
}


static int find_block(const char *name)
{
	int i;

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		if (strcmp(name, odp_shm_tbl->block[i].name) == 0) {
			/* found it */
			return i;
		}
	}

	return -1;
}

enum {
	ODP_SHM_MMAP,
	ODP_SHM_CMA
};

void *_odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
		       int type)
{
	int i;
	odp_shm_block_t *block;
#ifdef MAP_HUGETLB
	uint64_t huge_sz, page_sz;
	ti_em_rh_mem_config_t mem_config = {0};

	huge_sz = odp_sys_huge_page_size();
	page_sz = odp_sys_page_size();
#endif

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (find_block(name) >= 0) {
		/* Found a block with the same name */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return NULL;
	}

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		if (odp_shm_tbl->block[i].addr == NULL) {
			/* Found free block */
			break;
		}
	}

	if (i > ODP_SHM_NUM_BLOCKS - 1) {
		/* Table full */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return NULL;
	}

	block = &odp_shm_tbl->block[i];

	/* Allocate memory */
	mem_config.size = size + align;
	mem_config.flags = TI_EM_OSAL_MEM_CACHED;
	/*
	 * alloc free mapping id.
	 * FIXME: mapping_id is uint32_t.
	 */
	mem_config.mapping_id = -1;

	if (type == ODP_SHM_CMA) {
		ti_em_rh_alloc_map_cma(&mem_config);

		if (!mem_config.vaddr) {
			/* Alloc failed */
			odp_spinlock_unlock(&odp_shm_tbl->lock);
			ODP_ERR("%s: failed to allocate block: %-24s %4"PRIu64"  %4"PRIu64"\n",
				__func__,
				name,
				size,
				align);
			return NULL;
		}

	} else if (type == ODP_SHM_MMAP) {
		void *addr = MAP_FAILED;
		block->huge = 0;

#ifdef MAP_HUGETLB
		/* Try first huge pages */
		if (huge_sz && (size + align) > page_sz) {
			addr = mmap(NULL, size + align, PROT_READ | PROT_WRITE,
				    SHM_FLAGS | MAP_HUGETLB, -1, 0);
		}
#endif

		/* Use normal pages for small or failed huge page allocations */
		if (addr == MAP_FAILED) {
			addr = mmap(NULL, size + align, PROT_READ | PROT_WRITE,
				    SHM_FLAGS, -1, 0);
		} else {
			block->huge = 1;
		}

		if (addr == MAP_FAILED) {
			/* Alloc failed */
			odp_spinlock_unlock(&odp_shm_tbl->lock);
			return NULL;
		}
		mem_config.vaddr = (uintptr_t)addr;
	} else {
		ODP_ERR("Unknown shared memory type: %d\n", type);
	}

	block->mem_config = mem_config;

	/* move to correct alignment */
	block->addr = ODP_ALIGN_ROUNDUP_PTR(mem_config.vaddr, align);

	strncpy(block->name, name, ODP_SHM_NAME_LEN - 1);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;
	block->size   = size;
	block->align  = align;

	odp_spinlock_unlock(&odp_shm_tbl->lock);
	ODP_DBG("%s: reserved block: %-24s %4"PRIu64"  %4"PRIu64" %p\n",
		__func__,
		block->name,
		block->size,
		block->align,
		block->addr);

	return block->addr;
}

void *odp_shm_reserve(const char *name, uint64_t size, uint64_t align)
{
	return _odp_shm_reserve(name, size, align, ODP_SHM_CMA);
}

uintptr_t _odp_shm_get_paddr(void *vaddr)
{
	int i;
	uintptr_t addr = (uintptr_t)vaddr;
	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		ti_em_rh_mem_config_t *mem = &odp_shm_tbl->block[i].mem_config;
		if (mem->vaddr == 0)
			continue;
		if ((mem->vaddr <= addr) && (addr < mem->vaddr + mem->size)) {
			addr = (uintptr_t)odp_shm_tbl->block[i].addr;
			return (addr - mem->vaddr) + mem->paddr;
		}
	}
	return 0;
}

void *odp_shm_lookup(const char *name)
{
	int i;
	void *addr;

	odp_spinlock_lock(&odp_shm_tbl->lock);

	i = find_block(name);

	if (i < 0) {
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return NULL;
	}

	addr = odp_shm_tbl->block[i].addr;
	odp_spinlock_unlock(&odp_shm_tbl->lock);

	return addr;
}


void odp_shm_print_all(void)
{
	int i;

	printf("\nShared memory\n");
	printf("--------------\n");
	printf("  page size:      %"PRIu64" kB\n", odp_sys_page_size() / 1024);
	printf("  huge page size: %"PRIu64" kB\n",
	       odp_sys_huge_page_size() / 1024);
	printf("\n");

	printf("  id name                       kB align huge addr        paddr\n");

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		odp_shm_block_t *block;

		block = &odp_shm_tbl->block[i];

		if (block->addr) {
			printf("  %2i %-24s %4"PRIu64"  %4"PRIu64" %2c   %p  0x%08x\n",
			       i,
			       block->name,
			       block->size/1024,
			       block->align,
			       (block->huge ? '*' : ' '),
			       block->addr,
			       block->mem_config.paddr);
		}
	}

	printf("\n");
}
