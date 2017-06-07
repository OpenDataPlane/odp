/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPRDV shared memory (shm)
 */

#ifndef ODPDRV_SHM_H_
#define ODPDRV_SHM_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_shm ODPDRV SHARED MEMORY
 *  Operations on driver shared memory.
 *  @{
 */

/**
 * @typedef odpdrv_shm_t
 * odpdrv shared memory block
 */

/**
 * @def ODPDRV_SHM_INVALID
 * Invalid odpdrv shared memory block
 */

/** Maximum shared memory block name length in chars */
#define ODPDRV_SHM_NAME_LEN 32

/*
 * Shared memory flags
 */
#define ODPDRV_SHM_SINGLE_VA	0x01 /**< Memory shall be mapped at same VA */
#define ODPDRV_SHM_LOCK		0x02 /**< Memory shall be locked (no swap) */

/**
 * Shared memory block info
 */
typedef struct odpdrv_shm_info_t {
	const char *name;      /**< Block name */
	void       *addr;      /**< Block address */
	uint64_t    size;      /**< Block size in bytes */
	uint64_t    page_size; /**< Memory page size */
	uint32_t    flags;     /**< ODPDRV_SHM_* flags */
} odpdrv_shm_info_t;

/**
 * Shared memory capabilities
 */
typedef struct odpdrv_shm_capability_t {
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

} odpdrv_shm_capability_t;

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
int odpdrv_shm_capability(odpdrv_shm_capability_t *capa);

/**
 * Reserve a contiguous block of shared memory
 *
 * @param[in] name   Name of the block (maximum ODPDRV_SHM_NAME_LEN - 1 chars)
 * @param[in] size   Block size in bytes
 * @param[in] align  Block alignment in bytes
 * @param[in] flags  Shared memory parameter flags (ODPDRV_SHM_*).
 *                   Default value is 0.
 *
 * @return Handle of the reserved block
 * @retval ODPDRV_SHM_INVALID on failure
 */
odpdrv_shm_t odpdrv_shm_reserve(const char *name, uint64_t size, uint64_t align,
				uint32_t flags);

/**
 * Free a contiguous block of shared memory
 *
 * Frees a previously reserved block of shared memory (found by its handle).
 * @note Freeing memory that is in use will result in UNDEFINED behavior
 *
 * @param[in] shm	odpdrv_shm Block handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odpdrv_shm_free_by_handle(odpdrv_shm_t shm);

/**
 * Free a contiguous block of shared memory (found from its name)
 *
 * Frees a previously reserved block of shared memory.
 * @note Freeing memory that is in use will result in UNDEFINED behavior
 *
 * @param[in] name	odpdrv_shm Block name
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odpdrv_shm_free_by_name(const char *name);

/**
 * Free a contiguous block of shared memory (found from its address)
 *
 * Frees a previously reserved block of shared memory.
 * @note Freeing memory that is in use will result in UNDEFINED behavior
 *
 * @param[in] address	odpdrv_shm Block address
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odpdrv_shm_free_by_address(void *address);

/**
 * Lookup and map a block of shared memory (identified by its handle)
 *
 * @param[in] shm	odpdrv_shm Block handle
 *
 * @return The address of the newly mapped block.
 * @retval NULL on failure
 */
void *odpdrv_shm_lookup_by_handle(odpdrv_shm_t shm);

/**
 * Lookup and map a block of shared memory (identified by its name)
 *
 * @param[in] name	odpdrv_shm Block name
 *
 * @return The handle of the newly mapped block.
 * @retval ODPDRV_SHM_INVALID on failure
 */
odpdrv_shm_t odpdrv_shm_lookup_by_name(const char *name);

/**
 * Lookup and map a block of shared memory (identified by its address)
 *
 * @note This only works when the flag ODPDRV_SHM_SINGLE_VA was set,
 * as otherwise addresses are odp-thread local and hence meaningless to
 * identify the block between odp-threads.
 *
 * @param[in] address	odpdrv_shm Block address
 *
 * @return The handle of the newly mapped block.
 * @retval ODPDRV_SHM_INVALID on failure
 */
odpdrv_shm_t odpdrv_shm_lookup_by_address(void *address);

/**
 * Get a Shared memory block address
 *
 * @param[in] shm	odpdrv_shm Block handle
 *
 * @return Memory block address
 * @retval NULL on failure
 */
void *odpdrv_shm_addr(odpdrv_shm_t shm);

/**
 * Shared memory block info
 *
 * @param[in]  shm	Odpdrv_shm block handle
 * @param[out] info	Block info pointer for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odpdrv_shm_info(odpdrv_shm_t shm, odpdrv_shm_info_t *info);

/**
 * Print all shared memory blocks and returns the number of allocated blocks.
 * This function is meant for debug.
 * @param title  A string to be printed before the shared memory status
 * @return       The total number of allocated blocks
 */
int odpdrv_shm_print_all(const char *title);

/**
 * Get printable value for an odpdrv_shm_t
 *
 * @param hdl  odpdrv_shm_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odpdrv_shm_t handle.
 */
uint64_t odpdrv_shm_to_u64(odpdrv_shm_t hdl);

/**
 * drv shm pool parameters
 * Used to communicate pool creation options.
 */
typedef struct {
	/** Sum of all (simultaneous) allocs (bytes)*/
	uint64_t pool_size;

	/** Minimum alloc size user will request from pool (bytes)*/
	uint64_t min_alloc;

	/** Maximum alloc size user will request from pool (bytes)*/
	uint64_t max_alloc;
} odpdrv_shm_pool_param_t;

/**
 * @typedef odpdrv_shm_pool_t
 * odpdrv shared memory pool
 */

/**
 * @def ODPDRV_SHM_POOL_INVALID
 * Invalid odpdrv shared memory pool
 */

/**
 * Create a memory pool
 *
 * This routine is used to create a memory pool. The use of pool name is
 * optional.
 * Unique names are not required. However, odpdrv_shm_pool_lookup()
 * returns only a single matching pool.
 *
 * @param pool_name Name of the pool or NULL.
 * @param param     Pool parameters.
 *
 * @return Handle of the created drv shm memory pool
 * @retval ODPDRV_SHM_POOL_INVALID  Pool could not be created
 */
odpdrv_shm_pool_t odpdrv_shm_pool_create(const char *pool_name,
					 odpdrv_shm_pool_param_t *param);

/**
 * Destroy a pool previously created by odpdrv_shm_pool_create()
 *
 * @param pool    Handle of the pool to be destroyed
 *
 * @retval 0 Success
 * @retval <0 Failure
 *
 * @note This routine destroys a previously created pool, and will destroy any
 * internal shared memory objects associated with the pool. Results are
 * undefined if an attempt is made to destroy a pool that contains allocated
 * or otherwise active allocations.
 */
int odpdrv_shm_pool_destroy(odpdrv_shm_pool_t pool);

/**
 * Find a memory pool by name
 *
 * @param name      Name of the pool
 *
 * @return Handle of the first matching pool
 * @retval ODPDRV_SHM_POOL_INVALID Pool could not be found
 */
odpdrv_shm_pool_t odpdrv_shm_pool_lookup(const char *name);

/**
 * Allocate memory from a memory pool
 *
 * @param pool      Memory pool handle
 * @param size      Number of bytes to allocate (bytes)
 *
 * @return A pointer to the allocated memory
 * @retval NULL on error.
 */
void *odpdrv_shm_pool_alloc(odpdrv_shm_pool_t pool, uint64_t size);

/**
 * Free memory  back to a memory pool
 *
 * @param pool      Memory pool handle
 * @param addr      pointer to a previously allocated memory
 *		    (as returned by a previous call to odpdrv_shm_pool_alloc)
 */
void odpdrv_shm_pool_free(odpdrv_shm_pool_t pool, void *addr);

/**
 * Print memory pool info
 *
 * @param title     A string to be printed as a title (e.g. location)
 * @param pool      Memory pool handle
 *
 * @return 0 on success, negative value if pool inconsistency is detected.
 *
 * @note This routine writes implementation-defined information about the
 * specified pool to the ODP log. The intended use is for debugging.
 */
int  odpdrv_shm_pool_print(const char *title, odpdrv_shm_pool_t pool);
/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
