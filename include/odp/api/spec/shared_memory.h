/* Copyright (c) 2013-2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODP_API_SHARED_MEMORY_H_
#define ODP_API_SHARED_MEMORY_H_
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
 * @def ODP_SHM_NULL
 * Synonym for buffer pool use
 */

/**
 * @def ODP_SHM_NAME_LEN
 * Maximum shared memory block name length in chars including null char
 */

/*
 * Shared memory flags:
 */
#define ODP_SHM_SW_ONLY		0x1 /**< Application SW only, no HW access   */
#define ODP_SHM_PROC		0x2 /**< Share with external processes       */
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
 * @param[in] name   Name of the block (maximum ODP_SHM_NAME_LEN - 1 chars)
 * @param[in] size   Block size in bytes
 * @param[in] align  Block alignment in bytes
 * @param[in] flags  Shared memory parameter flags (ODP_SHM_*).
 *                   Default value is 0.
 *
 * @return Handle of the reserved block
 * @retval ODP_SHM_INVALID on failure
 */
odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags);

/**
 * Free a contiguous block of shared memory
 *
 * Frees a previously reserved block of shared memory.
 * @note Freeing memory that is in use will result in UNDEFINED behavior
 *
 * @param[in] shm Block handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_shm_free(odp_shm_t shm);

/**
 * Lookup for a block of shared memory
 *
 * @param[in] name   Name of the block
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
 * @param[in] shm   Block handle
 *
 * @return Memory block address
 * @retval NULL on failure
 */
void *odp_shm_addr(odp_shm_t shm);


/**
 * Shared memory block info
 * @note This is the only shared memory API function which accepts invalid
 * shm handles (any bit value) without causing undefined behavior.
 *
 * @param[in]  shm   Block handle
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
 * Get printable value for an odp_shm_t
 *
 * @param hdl  odp_shm_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_shm_t handle.
 */
uint64_t odp_shm_to_u64(odp_shm_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
