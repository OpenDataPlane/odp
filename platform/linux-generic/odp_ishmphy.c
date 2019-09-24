/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * This file handles the lower end of the ishm memory allocator:
 * It performs the physical mappings.
 */
#include <odp_posix_extensions.h>
#include <odp_config_internal.h>
#include <odp/api/align.h>
#include <odp/api/system_info.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <odp_shm_internal.h>
#include <odp_ishmphy_internal.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <odp_ishmphy_internal.h>

static void *common_va_address;
static uint64_t common_va_len;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Reserve single VA memory
 * This function is called at odp_init_global() time to pre-reserve some memory
 * which is inherited by all odpthreads (i.e. descendant processes and threads).
 * This memory block is later used when memory is reserved with
 * _ODP_ISHM_SINGLE_VA flag.
 * returns the address of the mapping or NULL on error.
 */
void *_odp_ishmphy_reserve_single_va(uint64_t len, int fd)
{
	void *addr;

	addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, 0);
	if (addr == MAP_FAILED) {
		ODP_ERR("mmap failed: %s\n", strerror(errno));
		return NULL;
	}

	if (mprotect(addr, len, PROT_READ | PROT_WRITE))
		ODP_ERR("mprotect failed: %s\n", strerror(errno));

	ODP_DBG("VA Reserved: %p, len=%" PRIu64 "\n", addr, len);

	common_va_address = addr;
	common_va_len	  = len;

	return addr;
}

/* Free single VA memory
 * This function is called at odp_term_global() time to free the memory reserved
 * by _odp_ishmphy_reserve_single_va()
 */
int _odp_ishmphy_free_single_va(void)
{
	int ret;

	if (!common_va_address)
		return 0;

	ret = munmap(common_va_address, common_va_len);
	if (ret)
		ODP_ERR("munmap failed: %s\n", strerror(errno));
	return ret;
}

/*
 * do a mapping:
 * Performs a mapping of the provided file descriptor to the process VA
 * space. Not to be used with _ODP_ISHM_SINGLE_VA blocks.
 * returns the address of the mapping or NULL on error.
 */
void *_odp_ishmphy_map(int fd, uint64_t size, uint64_t offset, int flags)
{
	void *mapped_addr;
	int mmap_flags = MAP_POPULATE;

	ODP_ASSERT(!(flags & _ODP_ISHM_SINGLE_VA));

	/* do a new mapping in the VA space: */
	mapped_addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_SHARED | mmap_flags, fd, offset);
	if ((mapped_addr >= common_va_address) &&
	    ((char *)mapped_addr <
		(char *)common_va_address + common_va_len)) {
		ODP_ERR("VA SPACE OVERLAP!\n");
	}

	if (mapped_addr == MAP_FAILED)
		return NULL;

	/* if locking is requested, lock it...*/
	if (flags & _ODP_ISHM_LOCK) {
		if (mlock(mapped_addr, size)) {
			ODP_ERR("mlock failed: %s\n", strerror(errno));
			if (munmap(mapped_addr, size))
				ODP_ERR("munmap failed: %s\n", strerror(errno));
			return NULL;
		}
	}
	return mapped_addr;
}

/* free a mapping:
 * _ODP_ISHM_SINGLE_VA memory is not returned back to linux until global
 * terminate. If the _ODP_ISHM_SINGLE_VA flag was not given, both physical
 * memory and virtual address space are released by calling the normal munmap.
 * return 0 on success or -1 on error.
 */
int _odp_ishmphy_unmap(void *start, uint64_t len, int flags)
{
	int ret;

	/* if locking was requested, unlock...*/
	if (flags & _ODP_ISHM_LOCK)
		munlock(start, len);

	if (flags & _ODP_ISHM_SINGLE_VA)
		return 0;

	/* just release the mapping */
	ret = munmap(start, len);
	if (ret)
		ODP_ERR("munmap failed: %s\n", strerror(errno));
	return ret;
}
