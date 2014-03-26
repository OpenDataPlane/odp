/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODP_SHARED_MEMORY_H_
#define ODP_SHARED_MEMORY_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>

/** Maximum shared memory block name lenght in chars */
#define ODP_SHM_NAME_LEN 32


/**
 * Reserve a block of shared memory
 *
 * @param name   Name of the block (maximum ODP_SHM_NAME_LEN - 1 chars)
 * @param size   Block size in bytes
 * @param align  Block alignment in bytes
 *
 * @return Pointer to the reserved block, or NULL
 */
void *odp_shm_reserve(const char *name, uint64_t size, uint64_t align);

/**
 * Lookup for a block of shared memory
 *
 * @param name   Name of the block
 *
 * @return Pointer to the block, or NULL
 */
void *odp_shm_lookup(const char *name);


/**
 * Print all shared memory blocks
 */
void odp_shm_print_all(void);


#ifdef __cplusplus
}
#endif

#endif


