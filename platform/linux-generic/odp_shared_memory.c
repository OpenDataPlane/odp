/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_shared_memory.h>
#include <odp_internal.h>
#include <odp_spinlock.h>
#include <odp_align.h>
#include <odp_system_info.h>
#include <odp_debug.h>
#include <odp_debug_internal.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <asm/mman.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>


#define ODP_SHM_NUM_BLOCKS 32


typedef struct {
	char      name[ODP_SHM_NAME_LEN];
	uint64_t  size;
	uint64_t  align;
	void      *addr_orig;
	void      *addr;
	int       huge;
	odp_shm_t hdl;
	uint32_t  flags;
	uint64_t  page_sz;
	int       fd;

} odp_shm_block_t;


typedef struct {
	odp_shm_block_t block[ODP_SHM_NUM_BLOCKS];
	odp_spinlock_t  lock;

} odp_shm_table_t;


#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif


/* Global shared memory table */
static odp_shm_table_t *odp_shm_tbl;


static inline uint32_t from_handle(odp_shm_t shm)
{
	return shm - 1;
}


static inline odp_shm_t to_handle(uint32_t index)
{
	return index + 1;
}


int odp_shm_init_global(void)
{
	void *addr;

#ifndef MAP_HUGETLB
	ODP_DBG("NOTE: mmap does not support huge pages\n");
#endif

	addr = mmap(NULL, sizeof(odp_shm_table_t),
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

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


static int find_block(const char *name, uint32_t *index)
{
	uint32_t i;

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		if (strcmp(name, odp_shm_tbl->block[i].name) == 0) {
			/* found it */
			if (index != NULL)
				*index = i;

			return 1;
		}
	}

	return 0;
}

int odp_shm_free(odp_shm_t shm)
{
	uint32_t i;
	int ret;
	odp_shm_block_t *shm_block;
	uint64_t alloc_size;

	i = from_handle(shm);
	if (NULL == odp_shm_tbl->block[i].addr) {
		ODP_DBG("odp_shm_free: Free block\n");
		return 0;
	}

	odp_spinlock_lock(&odp_shm_tbl->lock);
	shm_block = &odp_shm_tbl->block[i];

	alloc_size = shm_block->size + shm_block->align;
	ret = munmap(shm_block->addr, alloc_size);
	if (0 != ret) {
		ODP_DBG("odp_shm_free: munmap failed\n");
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return -1;
	}

	if (shm_block->flags & ODP_SHM_PROC) {
		ret = shm_unlink(shm_block->name);
		if (0 != ret) {
			ODP_DBG("odp_shm_free: shm_unlink failed\n");
			odp_spinlock_unlock(&odp_shm_tbl->lock);
			return -1;
		}
	}
	memset(&odp_shm_tbl->block[i], 0, sizeof(odp_shm_block_t));
	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return 0;
}

odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags)
{
	uint32_t i;
	odp_shm_block_t *block;
	void *addr;
	int fd = -1;
	int map_flag = MAP_SHARED;
	/* If already exists: O_EXCL: error, O_TRUNC: truncate to zero */
	int oflag = O_RDWR | O_CREAT | O_TRUNC;
	uint64_t alloc_size = size + align;
	uint64_t page_sz, huge_sz;

	huge_sz = odp_sys_huge_page_size();
	page_sz = odp_sys_page_size();

	if (flags & ODP_SHM_PROC) {
		/* Creates a file to /dev/shm */
		fd = shm_open(name, oflag,
			      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

		if (fd == -1) {
			ODP_DBG("odp_shm_reserve: shm_open failed\n");
			return ODP_SHM_INVALID;
		}

		if (ftruncate(fd, alloc_size) == -1) {
			ODP_DBG("odp_shm_reserve: ftruncate failed\n");
			return ODP_SHM_INVALID;
		}

	} else {
		map_flag |= MAP_ANONYMOUS;
	}

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (find_block(name, NULL)) {
		/* Found a block with the same name */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		ODP_DBG("odp_shm_reserve: name already used\n");
		return ODP_SHM_INVALID;
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
		ODP_DBG("odp_shm_reserve: no more blocks\n");
		return ODP_SHM_INVALID;
	}

	block = &odp_shm_tbl->block[i];

	block->hdl  = to_handle(i);
	block->huge = 0;
	addr        = MAP_FAILED;

#ifdef MAP_HUGETLB
	/* Try first huge pages */
	if (huge_sz && alloc_size > page_sz) {
		addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
			    map_flag | MAP_HUGETLB, fd, 0);
	}
#endif

	/* Use normal pages for small or failed huge page allocations */
	if (addr == MAP_FAILED) {
		addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
			    map_flag, fd, 0);
		block->page_sz = page_sz;
	} else {
		block->huge    = 1;
		block->page_sz = huge_sz;
	}

	if (addr == MAP_FAILED) {
		/* Alloc failed */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		ODP_DBG("odp_shm_reserve: mmap failed\n");
		return ODP_SHM_INVALID;
	}

	block->addr_orig = addr;

	/* move to correct alignment */
	addr = ODP_ALIGN_ROUNDUP_PTR(addr, align);

	strncpy(block->name, name, ODP_SHM_NAME_LEN - 1);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;
	block->size   = size;
	block->align  = align;
	block->flags  = flags;
	block->fd     = fd;
	block->addr   = addr;

	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return block->hdl;
}

odp_shm_t odp_shm_lookup(const char *name)
{
	uint32_t i;
	odp_shm_t hdl;

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (find_block(name, &i) == 0) {
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return ODP_SHM_INVALID;
	}

	hdl = odp_shm_tbl->block[i].hdl;
	odp_spinlock_unlock(&odp_shm_tbl->lock);

	return hdl;
}


void *odp_shm_addr(odp_shm_t shm)
{
	uint32_t i;

	i = from_handle(shm);

	if (i > (ODP_SHM_NUM_BLOCKS - 1))
		return NULL;

	return odp_shm_tbl->block[i].addr;
}


int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	odp_shm_block_t *block;
	uint32_t i;

	i = from_handle(shm);

	if (i > (ODP_SHM_NUM_BLOCKS - 1))
		return -1;

	block = &odp_shm_tbl->block[i];

	info->name      = block->name;
	info->addr      = block->addr;
	info->size      = block->size;
	info->page_size = block->page_sz;
	info->flags     = block->flags;

	return 0;
}


void odp_shm_print_all(void)
{
	int i;

	ODP_PRINT("\nShared memory\n");
	ODP_PRINT("--------------\n");
	ODP_PRINT("  page size:      %"PRIu64" kB\n",
		  odp_sys_page_size() / 1024);
	ODP_PRINT("  huge page size: %"PRIu64" kB\n",
		  odp_sys_huge_page_size() / 1024);
	ODP_PRINT("\n");

	ODP_PRINT("  id name                       kB align huge addr\n");

	for (i = 0; i < ODP_SHM_NUM_BLOCKS; i++) {
		odp_shm_block_t *block;

		block = &odp_shm_tbl->block[i];

		if (block->addr) {
			ODP_PRINT("  %2i %-24s %4"PRIu64"  %4"PRIu64
				  " %2c   %p\n",
				  i,
				  block->name,
				  block->size/1024,
				  block->align,
				  (block->huge ? '*' : ' '),
				  block->addr);
		}
	}

	ODP_PRINT("\n");
}
