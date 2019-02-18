/* Copyright (c) 2019, Nokia
 * Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODP_API_SPEC_SHARED_MEMORY_H_
#define ODP_API_SPEC_SHARED_MEMORY_H_
#include <odp/visibility_begin.h>
#include <odp/api/init.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_shared_memory ODP SHARED MEMORY
 *  Operations on shared memory.
 *  @{
 */

/**
 * @typedef odp_shm_t
 * ODP shared memory block
 */

/**
 * @def ODP_SHM_INVALID
 * Invalid shared memory block
 */

/**
 * @def ODP_SHM_NAME_LEN
 * Maximum shared memory block name length in chars including null char
 */

 /* Shared memory flags */

/**
 * Application SW only, no HW access
 */
#define ODP_SHM_SW_ONLY		0x1

/**
 * Share with external processes
 */
#define ODP_SHM_PROC		0x2

/**
 * Single virtual address
 *
 * When set, this flag guarantees that all ODP threads sharing this
 * memory block will see the block at the same address - regardless
 * of ODP thread type (e.g. pthread vs. process (or fork process time)).
 */
#define ODP_SHM_SINGLE_VA	0x4

/**
 * Export memory
 *
 * When set, the memory block becomes visible to other ODP instances
 * through odp_shm_import().
 */
#define ODP_SHM_EXPORT		0x08

/**
 * Use huge pages
 *
 * When set, this flag guarantees that the memory reserved by odp_shm_reserve()
 * is allocated from huge pages. The reserve call will return failure if enough
 * huge page memory is not available.
 */
#define ODP_SHM_HP		0x10

/**
 * Shared memory block info
 */
typedef struct odp_shm_info_t {
	/** Block name */
	const char *name;

	/** Block address */
	void       *addr;

	/** Block size in bytes */
	uint64_t    size;

	/** Memory page size */
	uint64_t    page_size;

	/** ODP_SHM_* flags */
	uint32_t    flags;
} odp_shm_info_t;

/**
 * Shared memory capabilities
 */
typedef struct odp_shm_capability_t {
	/** Maximum number of shared memory blocks
	 *
	 * This number of separate shared memory blocks can be
	 * reserved concurrently. */
	unsigned max_blocks;

	/** Maximum memory block size in bytes
	 *
	 * The value of zero means that size is limited only by the available
	 * memory size. */
	uint64_t max_size;

	/** Maximum memory block alignment in bytes
	 *
	 * The value of zero means that alignment is limited only by the
	 * available memory size. */
	uint64_t max_align;

} odp_shm_capability_t;

/**
 * Query shared memory capabilities
 *
 * Outputs shared memory capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_shm_capability(odp_shm_capability_t *capa);

/**
 * Reserve a contiguous block of shared memory
 *
 * Reserve a contiguous block of shared memory that fulfills size, alignment
 * and shareability (ODP_SHM_* flags) requirements. In general, a name is
 * optional and does not need to be unique. However, if the block will be
 * searched with odp_shm_lookup() or odp_shm_import(), a unique name is needed
 * for correct match.
 *
 * @param name   Name of the block or NULL. Maximum string length is
 *               ODP_SHM_NAME_LEN.
 * @param size   Block size in bytes
 * @param align  Block alignment in bytes
 * @param flags  Shared memory parameter flags (ODP_SHM_*). Default value is 0.
 *
 * @return Handle of the reserved block
 * @retval ODP_SHM_INVALID on failure
 */
odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags);

/**
 * Free a contiguous block of shared memory
 *
 * Frees a previously reserved block of shared memory. Freeing memory that is
 * in use will result in UNDEFINED behavior
 *
 * @param shm    Block handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_shm_free(odp_shm_t shm);

/**
 * Lookup for a block of shared memory
 *
 * @param name   Name of the block
 *
 * @return A handle to the block if it is found by name
 * @retval ODP_SHM_INVALID on failure
 */
odp_shm_t odp_shm_lookup(const char *name);

/**
 * Import a block of shared memory, exported by another ODP instance
 *
 * This call creates a new handle for accessing a shared memory block created
 * (with ODP_SHM_EXPORT flag) by another ODP instance. An instance may have
 * only a single handle to the same block. Application must not access the
 * block after freeing the handle. When an imported handle is freed, only
 * the calling instance is affected. The exported block may be freed only
 * after all other instances have stopped accessing the block.
 *
 * @param remote_name  Name of the block, in the remote ODP instance
 * @param odp_inst     Remote ODP instance, as returned by odp_init_global()
 * @param local_name   Name given to the block, in the local ODP instance
 *		       May be NULL, if the application doesn't need a name
 *		       (for a lookup).
 *
 * @return A handle to access a block exported by another ODP instance.
 * @retval ODP_SHM_INVALID on failure
 */
odp_shm_t odp_shm_import(const char *remote_name,
			 odp_instance_t odp_inst,
			 const char *local_name);

/**
 * Shared memory block address
 *
 * @param shm    Block handle
 *
 * @return Memory block address
 * @retval NULL on failure
 */
void *odp_shm_addr(odp_shm_t shm);

/**
 * Shared memory block info
 *
 * Get information about the specified shared memory block. This is the only
 * shared memory API function which accepts invalid shm handles (any bit value)
 * without causing undefined behavior.
 *
 * @param      shm   Block handle
 * @param[out] info  Block info pointer for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info);

/**
 * Print all shared memory blocks
 */
void odp_shm_print_all(void);

/**
 * Print shared memory block info
 *
 * Print implementation defined information about the specified shared memory
 * block to the ODP log. The information is intended to be used for debugging.
 *
 * @param shm        Block handle
 */
void odp_shm_print(odp_shm_t shm);

/**
 * Get printable value for an odp_shm_t
 *
 * This routine is intended to be used for diagnostic purposes to enable
 * applications to generate a printable value that represents an odp_shm_t
 * handle.
 *
 * @param shm    Block handle
 *
 * @return uint64_t value that can be used to print this handle
 */
uint64_t odp_shm_to_u64(odp_shm_t shm);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
