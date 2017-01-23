/* Copyright (c) 2016, Linaro Limited
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
#include <odp_internal.h>
#include <odp/api/align.h>
#include <odp/api/system_info.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <_ishm_internal.h>
#include <_ishmphy_internal.h>

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
#include <_ishmphy_internal.h>

static void *common_va_address;
static uint64_t common_va_len;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Book some virtual address space
 * This function is called at odp_init_global() time to pre-book some
 * virtual address space inherited by all odpthreads (i.e. descendant
 * processes and threads) and later used to guarantee the unicity the
 * the mapping VA address when memory is reserver with the _ODP_ISHM_SINGLE_VA
 * flag.
 * returns the address of the mapping or NULL on error.
 */
void *_odp_ishmphy_book_va(uintptr_t len, intptr_t align)
{
	void *addr;

	addr = mmap(NULL, len + align, PROT_NONE,
		    MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (addr == MAP_FAILED) {
		ODP_ERR("_ishmphy_book_va failure\n");
		return NULL;
	}

	if (mprotect(addr, len, PROT_NONE))
			ODP_ERR("failure for protect\n");

	ODP_DBG("VA Reserved: %p, len=%p\n", addr, len + align);

	common_va_address = addr;
	common_va_len	  = len;

	/* return the nearest aligned address: */
	return (void *)(((uintptr_t)addr + align - 1) & (-align));
}

/* Un-book some virtual address space
 * This function is called at odp_term_global() time to unbook
 * the virtual address space booked by _ishmphy_book_va()
 */
int _odp_ishmphy_unbook_va(void)
{
	int ret;

	ret = munmap(common_va_address, common_va_len);
	if (ret)
		ODP_ERR("_unishmphy_book_va failure\n");
	return ret;
}

/*
 * do a mapping:
 * Performs a mapping of the provided file descriptor to the process VA
 * space. If the _ODP_ISHM_SINGLE_VA flag is set, 'start' is assumed to be
 * the VA address where the mapping is to be done.
 * If the flag is not set, a new VA address is taken.
 * returns the address of the mapping or NULL on error.
 */
void *_odp_ishmphy_map(int fd, void *start, uint64_t size,
		       int flags)
{
	void *mapped_addr_tmp, *mapped_addr;
	int mmap_flags = 0;

	if (flags & _ODP_ISHM_SINGLE_VA) {
		if (!start) {
			ODP_ERR("failure: missing address\n");
			return NULL;
		}
		/* maps over fragment of reserved VA: */
		/* first, try a normal map. If that works, remap it where it
		 * should (on the prereverved space), and remove the initial
		 * normal mapping:
		 * This is because it turned out that if a mapping fails
		 * on a the prereserved virtual address space, then
		 * the prereserved address space which was tried to be mapped
		 * on becomes available to the kernel again! This was not
		 * according to expectations: the assumption was that if a
		 * mapping fails, the system should remain unchanged, but this
		 * is obvioulsy not true (at least for huge pages when
		 * exhausted).
		 * So the strategy is to first map at a non reserved place
		 * (which can then be freed and returned to the kernel on
		 * failure) and peform a new map to the prereserved space on
		 * success (which is then guaranteed to work).
		 * The initial free maping can then be removed.
		 */
		mapped_addr = MAP_FAILED;
		mapped_addr_tmp = mmap(NULL, size, PROT_READ | PROT_WRITE,
				       MAP_SHARED | mmap_flags, fd, 0);
		if (mapped_addr_tmp != MAP_FAILED) {
			/* If OK, do new map at right fixed location... */
			mapped_addr = mmap(start,
					   size, PROT_READ | PROT_WRITE,
					   MAP_SHARED | MAP_FIXED | mmap_flags,
					   fd, 0);
			if (mapped_addr != start)
				ODP_ERR("new map failed:%s\n", strerror(errno));
			/* ... and remove initial mapping: */
			if (munmap(mapped_addr_tmp, size))
				ODP_ERR("munmap failed:%s\n", strerror(errno));
		}
	} else {
		/* just do a new mapping in the VA space: */
		mapped_addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
				   MAP_SHARED | mmap_flags, fd, 0);
		if ((mapped_addr >= common_va_address) &&
		    ((char *)mapped_addr <
			(char *)common_va_address + common_va_len)) {
			ODP_ERR("VA SPACE OVERLAP!\n");
		}
	}

	if (mapped_addr == MAP_FAILED) {
		ODP_ERR("mmap failed:%s\n", strerror(errno));
		return NULL;
	}

	/* if locking is requested, lock it...*/
	if (flags & _ODP_ISHM_LOCK) {
		if (mlock(mapped_addr, size)) {
			if (munmap(mapped_addr, size))
				ODP_ERR("munmap failed:%s\n", strerror(errno));
			ODP_ERR("mlock failed:%s\n", strerror(errno));
			return NULL;
		}
	}
	return mapped_addr;
}

/* free a mapping:
 * If the _ODP_ISHM_SINGLE_VA flag was given at creation time the virtual
 * address range must be returned to the preoallocated "pool". this is
 * done by mapping non accessibly memory there (hence blocking the VA but
 * releasing the physical memory).
 * If the _ODP_ISHM_SINGLE_VA flag was not given, both physical memory and
 * virtual address space are realeased by calling the normal munmap.
 * return 0 on success or -1 on error.
 */
int _odp_ishmphy_unmap(void *start, uint64_t len, int flags)
{
	void *addr;
	int ret;
	int mmap_flgs;

	mmap_flgs = MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE;

	/* if locking was requested, unlock...*/
	if (flags & _ODP_ISHM_LOCK)
		munlock(start, len);

	if (flags & _ODP_ISHM_SINGLE_VA) {
		/* map unnaccessible memory overwrites previous mapping
		 * and free the physical memory, but guarantees to block
		 * the VA range from other mappings
		 */
		addr = mmap(start, len, PROT_NONE, mmap_flgs, -1, 0);
		if (addr == MAP_FAILED) {
			ODP_ERR("_ishmphy_free failure for ISHM_SINGLE_VA\n");
			return -1;
		}
		if (mprotect(start, len, PROT_NONE))
			ODP_ERR("_ishmphy_free failure for protect\n");
		return 0;
	}

	/* just release the mapping */
	ret = munmap(start, len);
	if (ret)
		ODP_ERR("_ishmphy_free failure: %s\n", strerror(errno));
	return ret;
}
