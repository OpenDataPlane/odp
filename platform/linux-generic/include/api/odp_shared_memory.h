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
 * ODP shared memory block
 */
typedef uint32_t odp_shm_t;

/** Invalid shared memory block */
#define ODP_SHM_INVALID 0


/**
 * Shared memory block info
 */
typedef struct odp_shm_info_t {
	const char *name;      /**< Block name */
	void       *addr;      /**< Block address */
	uint64_t    size;      /**< Block size in bytes */
	uint64_t    page_size; /**< Memory page size */
	uint32_t    flags;     /**< ODP_SHM_* flags */
} odp_shm_info_t;


/**
 * Reserve a contiguous block of shared memory
 *
 * @param name   Name of the block (maximum ODP_SHM_NAME_LEN - 1 chars)
 * @param size   Block size in bytes
 * @param align  Block alignment in bytes
 * @param flags  Shared mem parameter flags (ODP_SHM_*). Default value is 0.
 *
 * @return Pointer to the reserved block, or NULL
 */
odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags);

/**
 * Lookup for a block of shared memory
 *
 * @param name   Name of the block
 *
 * @return Pointer to the block, or NULL
 */
odp_shm_t odp_shm_lookup(const char *name);


/**
 * Shared memory block address
 *
 * @param shm   Block handle
 *
 * @return Memory block address, or NULL on error
 */
void *odp_shm_addr(odp_shm_t shm);


/**
 * Shared memory block info
 *
 * @param shm   Block handle
 * @param info  Block info pointer for output
 *
 * @return 0 on success, otherwise non-zero
 */
int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info);


/**
 * Print all shared memory blocks
 */
void odp_shm_print_all(void);


#ifdef __cplusplus
}
#endif

#endif
