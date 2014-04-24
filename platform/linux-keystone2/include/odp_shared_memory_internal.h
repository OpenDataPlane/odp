/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP shared memory internal
 */

#ifndef ODP_SHARED_MEMORY_INTERNAL_H_
#define ODP_SHARED_MEMORY_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

void *_odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
		       int type);
uintptr_t _odp_shm_get_paddr(void *vaddr);

#ifdef __cplusplus
}
#endif

#endif
