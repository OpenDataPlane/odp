/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/plat/strong_types.h>
#include <odp_shm_internal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_lcore.h>
#include <rte_memzone.h>

#define SHM_MAX_ALIGN (0x80000000)
#define SHM_BLOCK_NAME "%" PRIu64 "-%d-%s"

ODP_STATIC_ASSERT(ODP_CONFIG_SHM_BLOCKS >= ODP_CONFIG_POOLS,
		  "ODP_CONFIG_SHM_BLOCKS < ODP_CONFIG_POOLS");

ODP_STATIC_ASSERT(ODP_SHM_NAME_LEN >= RTE_MEMZONE_NAMESIZE,
		  "ODP_SHM_NAME_LEN < RTE_MEMZONE_NAMESIZE");

typedef enum {
	SHM_TYPE_LOCAL = 0,
	SHM_TYPE_REMOTE
} shm_type_t;

/**
 * Memory zone descriptor
 *
 * This struct is stored inside DPDK memzone to make it available for
 * odp_shm_import().
 */
typedef struct {
	/* Shared memory flags */
	uint32_t flags;
} shm_zone_t;

/**
 * Memory block descriptor
 */
typedef struct {
	/* Memory block type */
	shm_type_t type;
	/* Memory block name */
	char name[ODP_SHM_NAME_LEN];
	/* DPDK memzone. If this pointer != NULL, the shm block is interpreted
	 * as reserved. */
	const struct rte_memzone *mz;
} shm_block_t;

/**
 * Table of blocks describing allocated shared memory. This table is visible to
 * every ODP thread (linux process or pthreads). It is allocated shared at odp
 * init time and is therefore inherited by all.
 */
typedef struct {
	odp_spinlock_t  lock;
	shm_block_t block[ODP_CONFIG_SHM_BLOCKS];
} shm_table_t;

static shm_table_t *shm_tbl;

/**
 * Check if DPDK memzone name has been used already
 */
static odp_bool_t mz_name_used(const char *name)
{
	int idx;

	for (idx = 0; idx < ODP_CONFIG_SHM_BLOCKS; idx++) {
		if (shm_tbl->block[idx].mz &&
		    strncmp(name, shm_tbl->block[idx].mz->name,
			    RTE_MEMZONE_NAMESIZE) == 0)
			return 1;
	}
	return 0;
}

/**
 * Convert ODP shm name into unique DPDK memzone name
 */
static void name_to_mz_name(const char *name, char *mz_name)
{
	int i = 0;

	/* Use pid and counter to make name unique */
	do {
		snprintf(mz_name, RTE_MEMZONE_NAMESIZE, SHM_BLOCK_NAME,
			 (odp_instance_t)odp_global_data.main_pid, i++, name);
		mz_name[RTE_MEMZONE_NAMESIZE - 1] = 0;
	} while (mz_name_used(mz_name));
}

/**
 * Convert DPDK memzone length into ODP shm block size
 */
static uint64_t shm_size(const struct rte_memzone *mz)
{
	return mz->len - sizeof(shm_zone_t);
}

/**
 * Return a pointer to shm zone descriptor stored at the end of DPDK memzone
 */
static shm_zone_t *shm_zone(const struct rte_memzone *mz)
{
	return (shm_zone_t *)(uintptr_t)((uint8_t *)mz->addr + shm_size(mz));
}

static int find_free_block(void)
{
	int idx;

	for (idx = 0; idx < ODP_CONFIG_SHM_BLOCKS; idx++) {
		if (shm_tbl->block[idx].mz == NULL)
			return idx;
	}
	return -1;
}

static inline uint32_t handle_to_idx(odp_shm_t shm)
{
	return _odp_typeval(shm) - 1;
}

static inline odp_shm_t idx_to_handle(uint32_t idx)
{
	return _odp_cast_scalar(odp_shm_t, idx + 1);
}

static inline odp_bool_t handle_is_valid(odp_shm_t shm)
{
	int idx = handle_to_idx(shm);

	if (idx < 0 || idx >= ODP_CONFIG_SHM_BLOCKS ||
	    shm_tbl->block[idx].mz == NULL) {
		ODP_ERR("Invalid odp_shm_t handle: %" PRIu64 "\n",
			odp_shm_to_u64(shm));
		return 0;
	}
	return 1;
}

int _odp_shm_init_global(void)
{
	void *addr;

	if ((getpid() != odp_global_data.main_pid) ||
	    (syscall(SYS_gettid) != getpid())) {
		ODP_ERR("shm_init_global() must be performed by the main "
			"ODP process!\n.");
		return -1;
	}

	/* Allocate space for the internal shared mem block table */
	addr = mmap(NULL, sizeof(shm_table_t), PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ODP_ERR("Unable to mmap the shm block table\n");
		return -1;
	}

	shm_tbl = addr;
	memset(shm_tbl, 0, sizeof(shm_table_t));

	odp_spinlock_init(&shm_tbl->lock);

	return 0;
}

int _odp_shm_init_local(void)
{
	return 0;
}

int _odp_shm_term_global(void)
{
	shm_block_t *block;
	int idx;

	if ((getpid() != odp_global_data.main_pid) ||
	    (syscall(SYS_gettid) != getpid())) {
		ODP_ERR("shm_term_global() must be performed by the main "
			"ODP process!\n.");
		return -1;
	}

	/* Cleanup possibly non freed memory (and complain a bit) */
	for (idx = 0; idx < ODP_CONFIG_SHM_BLOCKS; idx++) {
		block = &shm_tbl->block[idx];
		if (block->mz) {
			ODP_ERR("block '%s' was never freed (cleaning up...)\n",
				block->name);
			rte_memzone_free(block->mz);
		}
	}
	/* Free the shared memory block table */
	if (munmap(shm_tbl, sizeof(shm_table_t)) < 0) {
		ODP_ERR("Unable to munmap the shm block table\n");
		return -1;
	}
	return 0;
}

int _odp_shm_term_local(void)
{
	return 0;
}

int odp_shm_capability(odp_shm_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_shm_capability_t));

	capa->max_blocks = ODP_CONFIG_SHM_BLOCKS;
	capa->max_size = 0;
	capa->max_align = SHM_MAX_ALIGN;

	return 0;
}

odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags)
{
	shm_block_t *block;
	const struct rte_memzone *mz;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	uint32_t mz_flags = RTE_MEMZONE_1GB | RTE_MEMZONE_SIZE_HINT_ONLY;
	int idx;

	if (align > SHM_MAX_ALIGN) {
		ODP_ERR("Align too large: %" PRIu64 "\n", align);
		return ODP_SHM_INVALID;
	}

	/* DPDK requires alignment to be power of two */
	if (!rte_is_power_of_2(align))
		align = ROUNDUP_POWER2_U32(align);

	odp_spinlock_lock(&shm_tbl->lock);

	idx = find_free_block();
	if (idx < 0) {
		odp_spinlock_unlock(&shm_tbl->lock);
		ODP_ERR("No free SHM blocks left\n");
		return ODP_SHM_INVALID;
	}
	block = &shm_tbl->block[idx];

	/* DPDK requires unique memzone names */
	name_to_mz_name(name, mz_name);
	/* Reserve extra space for storing shm zone descriptor */
	mz = rte_memzone_reserve_aligned(mz_name, size + sizeof(shm_zone_t),
					 rte_socket_id(), mz_flags, align);
	if (mz == NULL) {
		odp_spinlock_unlock(&shm_tbl->lock);
		ODP_ERR("Reserving DPDK memzone failed\n");
		return ODP_SHM_INVALID;
	}

	block->mz = mz;
	snprintf(block->name, ODP_SHM_NAME_LEN, "%s", name);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;
	block->type = SHM_TYPE_LOCAL;
	/* Note: ODP_SHM_SW_ONLY/ODP_SHM_PROC/ODP_SHM_SINGLE_VA flags are
	 * currently ignored. */
	shm_zone(mz)->flags = flags;

	odp_spinlock_unlock(&shm_tbl->lock);

	return idx_to_handle(idx);
}

odp_shm_t odp_shm_import(const char *remote_name, odp_instance_t odp_inst,
			 const char *local_name)
{
	shm_block_t *block;
	const struct rte_memzone *mz;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	int idx;

	snprintf(mz_name, RTE_MEMZONE_NAMESIZE, SHM_BLOCK_NAME, odp_inst, 0,
		 remote_name);
	mz_name[RTE_MEMZONE_NAMESIZE - 1] = 0;

	mz = rte_memzone_lookup(mz_name);
	if (mz == NULL) {
		ODP_ERR("Unable to find remote SHM block: %s\n", remote_name);
		return ODP_SHM_INVALID;
	}

	if (!(shm_zone(mz)->flags & ODP_SHM_EXPORT)) {
		ODP_ERR("Not exported SHM block!\n");
		return ODP_SHM_INVALID;
	}

	odp_spinlock_lock(&shm_tbl->lock);

	idx = find_free_block();
	if (idx < 0) {
		odp_spinlock_unlock(&shm_tbl->lock);
		ODP_ERR("No free SHM blocks left\n");
		return ODP_SHM_INVALID;
	}
	block = &shm_tbl->block[idx];

	block->mz = mz;
	snprintf(block->name, ODP_SHM_NAME_LEN, "%s", local_name);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;
	block->type = SHM_TYPE_REMOTE;

	odp_spinlock_unlock(&shm_tbl->lock);

	return idx_to_handle(idx);
}

int odp_shm_free(odp_shm_t shm)
{
	shm_block_t *block;
	int ret = 0;

	odp_spinlock_lock(&shm_tbl->lock);

	if (!handle_is_valid(shm)) {
		odp_spinlock_unlock(&shm_tbl->lock);
		return -1;
	}

	block = &shm_tbl->block[handle_to_idx(shm)];

	/* Only the creator of memzone can free it */
	if (block->type == SHM_TYPE_LOCAL)
		ret = rte_memzone_free(block->mz);

	block->mz = NULL;

	odp_spinlock_unlock(&shm_tbl->lock);

	return ret;
}

odp_shm_t odp_shm_lookup(const char *name)
{
	int idx;

	odp_spinlock_lock(&shm_tbl->lock);

	for (idx = 0; idx < ODP_CONFIG_SHM_BLOCKS; idx++) {
		if (shm_tbl->block[idx].mz &&
		    strncmp(name, shm_tbl->block[idx].name,
			    ODP_SHM_NAME_LEN) == 0) {
			odp_spinlock_unlock(&shm_tbl->lock);
			return idx_to_handle(idx);
		}
	}

	odp_spinlock_unlock(&shm_tbl->lock);

	return ODP_SHM_INVALID;
}

void *odp_shm_addr(odp_shm_t shm)
{
	void *addr;

	odp_spinlock_lock(&shm_tbl->lock);

	if (!handle_is_valid(shm)) {
		odp_spinlock_unlock(&shm_tbl->lock);
		return NULL;
	}

	addr = shm_tbl->block[handle_to_idx(shm)].mz->addr;

	odp_spinlock_unlock(&shm_tbl->lock);

	return addr;
}

int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	shm_block_t *block;
	int idx = handle_to_idx(shm);

	odp_spinlock_lock(&shm_tbl->lock);

	if (!handle_is_valid(shm)) {
		odp_spinlock_unlock(&shm_tbl->lock);
		return -1;
	}

	block = &shm_tbl->block[idx];

	memset(info, 0, sizeof(odp_shm_info_t));

	info->name = block->name;
	info->addr = block->mz->addr;
	info->size = shm_size(block->mz);
	info->page_size = block->mz->hugepage_sz;
	info->flags = shm_zone(block->mz)->flags;

	odp_spinlock_unlock(&shm_tbl->lock);

	return 0;
}

void odp_shm_print_all(void)
{
	shm_block_t *block;
	int idx;

	odp_spinlock_lock(&shm_tbl->lock);

	printf("\nShared memory blocks\n--------------------\n");

	for (idx = 0; idx < ODP_CONFIG_SHM_BLOCKS; idx++) {
		block = &shm_tbl->block[idx];
		if (block->mz == NULL)
			continue;
		printf("  %s: addr: %p, len: %" PRIu64 " page size: "
		       "%" PRIu64 "\n", block->name, block->mz->addr,
		       shm_size(block->mz), block->mz->hugepage_sz);
	}

	odp_spinlock_unlock(&shm_tbl->lock);
}

void odp_shm_print(odp_shm_t shm)
{
	shm_block_t *block;
	int idx = handle_to_idx(shm);

	odp_spinlock_lock(&shm_tbl->lock);

	if (!handle_is_valid(shm)) {
		odp_spinlock_unlock(&shm_tbl->lock);
		return;
	}

	block = &shm_tbl->block[idx];

	ODP_PRINT("\nSHM block info\n--------------\n");
	ODP_PRINT(" name:       %s\n",   block->name);
	ODP_PRINT(" type:       %s\n",   block->type == SHM_TYPE_LOCAL ? "local"
			: "remote");
	ODP_PRINT(" flags:      0x%x\n", shm_zone(block->mz)->flags);
	ODP_PRINT(" start:      %p\n",   block->mz->addr);
	ODP_PRINT(" len:        %" PRIu64 "\n",  shm_size(block->mz));
	ODP_PRINT(" page size:  %" PRIu64 "\n", block->mz->hugepage_sz);
	ODP_PRINT(" NUMA ID:    %" PRIi32 "\n",  block->mz->socket_id);
	ODP_PRINT("\n");

	odp_spinlock_unlock(&shm_tbl->lock);
}

uint64_t odp_shm_to_u64(odp_shm_t hdl)
{
	return _odp_pri(hdl);
}
