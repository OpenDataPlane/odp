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

/** Maximum shared memory block name length in chars */
#define ODP_SHM_NAME_LEN 32

/*
 * Shared memory flags
 */

/* Share level */
#define ODP_SHM_SW_ONLY 0x1 /**< Application SW only, no HW access */
#define ODP_SHM_PROC    0x2 /**< Share with external processes */



/**
 * Reserve a block of shared memory
 *
 * @param name   Name of the block (maximum ODP_SHM_NAME_LEN - 1 chars)
 * @param size   Block size in bytes
 * @param align  Block alignment in bytes
 * @param flags  Shared mem parameter flags (ODP_SHM_*). Default value is 0.
 *
 * @return Pointer to the reserved block, or NULL
 */
void *odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
		      uint32_t flags);

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
