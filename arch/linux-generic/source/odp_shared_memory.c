/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <odp_shared_memory.h>
#include <odp_internal.h>
#include <odp_spinlock.h>
#include <odp_align.h>

#include <sys/mman.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>


#define ODP_SHM_NUM_BLOCKS 32


typedef struct {
	char name[ODP_SHM_NAME_LEN];
	uint64_t size;
	uintptr_t align;
	void *addr_orig;
	void *addr;

} odp_shm_block_t;


typedef struct {
	odp_shm_block_t block[ODP_SHM_NUM_BLOCKS];
	odp_spinlock_t  lock;

} odp_shm_table_t;


/* Global shared memory table */
static odp_shm_table_t *odp_shm_tbl;



int odp_shm_init_global(void)
{
	void *addr;

	addr = mmap(NULL, sizeof(odp_shm_table_t),
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
		    -1, 0);

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


void *odp_shm_reserve(const char *name, uint64_t size, uintptr_t align)
{
	int i;
	odp_shm_block_t *block;
	void *addr;

	(void) size; (void)align;

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

	addr = mmap(NULL, size + align,
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
		    -1, 0);

	if (addr == MAP_FAILED) {
		/* Alloc failed */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return NULL;
	}

	block->addr_orig = addr;

	/* move to correct alignment */
	addr = (void *)ODP_ALIGN_ROUNDUP_POWER_2((uintptr_t)addr, align);

	strncpy(block->name, name, ODP_SHM_NAME_LEN - 1);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;
	block->size   = size;
	block->align  = align;
	block->addr   = addr;

	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return addr;
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



