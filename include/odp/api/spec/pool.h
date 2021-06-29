/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2020-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP pool
 */

#ifndef ODP_API_SPEC_POOL_H_
#define ODP_API_SPEC_POOL_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/spec/pool_types.h>

/** @defgroup odp_pool ODP POOL
 *  Packet and buffer (event) pools.
 *  @{
 */

/**
 * Query pool capabilities
 *
 * Outputs pool capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pool_capability(odp_pool_capability_t *capa);

/**
 * Create a pool
 *
 * This routine is used to create a pool. The use of pool name is optional.
 * Unique names are not required. However, odp_pool_lookup() returns only a
 * single matching pool. Use odp_pool_param_init() to initialize parameters
 * into their default values.
 *
 * @param name     Name of the pool or NULL. Maximum string length is
 *                 ODP_POOL_NAME_LEN.
 * @param param    Pool parameters.
 *
 * @return Handle of the created pool
 * @retval ODP_POOL_INVALID  Pool could not be created
 */
odp_pool_t odp_pool_create(const char *name, const odp_pool_param_t *param);

/**
 * Destroy a pool previously created by odp_pool_create()
 *
 * @param pool    Handle of the pool to be destroyed
 *
 * @retval 0 Success
 * @retval -1 Failure
 *
 * @note This routine destroys a previously created pool, and will destroy any
 * internal shared memory objects associated with the pool. Results are
 * undefined if an attempt is made to destroy a pool that contains allocated
 * or otherwise active buffers.
 */
int odp_pool_destroy(odp_pool_t pool);

/**
 * Find a pool by name
 *
 * @param name      Name of the pool
 *
 * @return Handle of the first matching pool
 * @retval ODP_POOL_INVALID  Pool could not be found
 */
odp_pool_t odp_pool_lookup(const char *name);

/**
 * Retrieve information about a pool
 *
 * @param pool         Pool handle
 *
 * @param[out] info    Receives an odp_pool_info_t object
 *                     that describes the pool.
 *
 * @retval 0 Success
 * @retval -1 Failure.  Info could not be retrieved.
 */
int odp_pool_info(odp_pool_t pool, odp_pool_info_t *info);

/**
 * Print pool info
 *
 * @param pool      Pool handle
 *
 * @note This routine writes implementation-defined information about the
 * specified pool to the ODP log. The intended use is for debugging.
 */
void odp_pool_print(odp_pool_t pool);

/**
 * Get printable value for an odp_pool_t
 *
 * @param hdl  odp_pool_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_pool_t handle.
 */
uint64_t odp_pool_to_u64(odp_pool_t hdl);

/**
 * Initialize pool params
 *
 * Initialize an odp_pool_param_t to its default values for all fields
 *
 * @param param   Address of the odp_pool_param_t to be initialized
 */
void odp_pool_param_init(odp_pool_param_t *param);

/**
 * Maximum pool index
 *
 * Return the maximum pool index. Pool indexes (e.g. returned by odp_pool_index())
 * range from zero to this maximum value.
 *
 * @return Maximum pool index
 */
unsigned int odp_pool_max_index(void);

/**
 * Get pool index
 *
 * @param pool    Pool handle
 *
 * @return Pool index (0..odp_pool_max_index())
 * @retval <0 on failure
 */
int odp_pool_index(odp_pool_t pool);

/**
 * Get statistics for pool handle
 *
 * Read the statistics counters enabled using odp_pool_stats_opt_t during pool
 * creation. The inactive counters are set to zero by the implementation.
 *
 * @param      pool   Pool handle
 * @param[out] stats  Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats(odp_pool_t pool, odp_pool_stats_t *stats);

/**
 * Reset statistics for pool handle
 *
 * Reset all statistics counters to zero except: odp_pool_stats_t::available,
 * odp_pool_stats_t::cache_available
 *
 * @param pool    Pool handle
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats_reset(odp_pool_t pool);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
