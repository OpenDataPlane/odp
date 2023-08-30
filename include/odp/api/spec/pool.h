/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
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
#include <odp/api/pool_types.h>

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
 * This routine destroys a previously created pool, and will destroy any
 * internal shared memory objects associated with the pool. The pool must not
 * be in use (in pktio, classifier, timer, etc.) when calling this function.
 * Results are undefined if an attempt is made to destroy a pool that contains
 * allocated or otherwise active buffers.
 *
 * @param pool    Handle of the pool to be destroyed
 *
 * @retval 0 Success
 * @retval -1 Failure
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
 * Print debug info about all pools
 *
 * Print implementation defined information about all created pools to the ODP
 * log. The information is intended to be used for debugging.
 */
void odp_pool_print_all(void);

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
 * Get statistics for pool
 *
 * Read the statistics counters enabled using odp_pool_stats_opt_t during pool creation. The
 * inactive counters are set to zero by the implementation. Depending on the implementation, there
 * may be some delay until performed pool operations are visible in the statistics.
 *
 * A single call may read statistics from one to ODP_POOL_MAX_THREAD_STATS
 * threads. Set 'stats.thread.first' and 'stats.thread.last' to select the
 * threads ('first' <= 'last'). Valid values range from 0 to odp_thread_count_max() - 1.
 * A successful call fills the output array starting always from the first element
 * 'stats.thread.cache_available[0]' (='stats.thread.first').
 *
 * @param         pool   Pool handle
 * @param[in,out] stats  Output buffer for counters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats(odp_pool_t pool, odp_pool_stats_t *stats);

/**
 * Get selected pool statistics
 *
 * Read the selected counters given in odp_pool_stats_opt_t bit field structure. Only counters
 * included in odp_pool_stats_selected_t can be read and the selected counters must have been
 * enabled during pool creation. Values of the unselected counters are undefined. Depending on the
 * implementation, there may be some delay until performed pool operations are visible in the
 * statistics.
 *
 * Depending on the implementation, this function may have higher performance compared to
 * odp_pool_stats(), as only the selected set of counters is read.
 *
 * @param         pool   Pool handle
 * @param[out]    stats  Output buffer for counters
 * @param         opt    Bit field for selecting the counters to be read
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats_selected(odp_pool_t pool, odp_pool_stats_selected_t *stats,
			    const odp_pool_stats_opt_t *opt);

/**
 * Reset statistics for pool
 *
 * Reset all statistics counters to zero except: odp_pool_stats_t::available,
 * odp_pool_stats_t::cache_available, odp_pool_stats_t::thread::cache_available
 *
 * @param pool    Pool handle
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pool_stats_reset(odp_pool_t pool);

/**
 * Query capabilities of an external memory pool type
 *
 * Outputs pool capabilities on success. Returns failure if a bad pool type is used. When
 * the requested pool type is valid but not supported, sets the value of 'max_pools' to zero.
 *
 * @param      type    Pool type
 * @param[out] capa    Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pool_ext_capability(odp_pool_type_t type, odp_pool_ext_capability_t *capa);

/**
 * Initialize pool params
 *
 * Initialize an odp_pool_ext_param_t to its default values for all fields
 * based on the selected pool type.
 *
 * @param type     Pool type
 * @param param    odp_pool_ext_param_t to be initialized
 */
void odp_pool_ext_param_init(odp_pool_type_t type, odp_pool_ext_param_t *param);

/**
 * Create an external memory pool
 *
 * This routine is used to create a pool. The use of pool name is optional.
 * Unique names are not required. However, odp_pool_lookup() returns only a
 * single matching pool. Use odp_pool_ext_param_init() to initialize parameters
 * into their default values.
 *
 * @param name     Name of the pool or NULL. Maximum string length is ODP_POOL_NAME_LEN.
 * @param param    Pool parameters
 *
 * @return Pool handle on success
 * @retval ODP_POOL_INVALID on failure
 */
odp_pool_t odp_pool_ext_create(const char *name, const odp_pool_ext_param_t *param);

/**
 * Populate external memory pool with buffer memory
 *
 * Populate can be called multiple times to add memory buffers into the pool. Application must
 * populate the pool with the exact number of buffers specified in pool parameters. The pool is
 * ready to be used for allocations only after all populate calls have returned successfully.
 * Application marks the last populate call with ODP_POOL_POPULATE_DONE flag.
 *
 * Depending on pool usage (and ODP implementation), the memory may need to be accessible by
 * HW accelerators. Application may use e.g. odp_shm_reserve() with ODP_SHM_HW_ACCESS flag to
 * ensure HW access. The memory area used for one pool, starting from (or before) the lowest
 * addressed buffer and extending to the end (or after) of the highest addressed buffer, must not
 * overlap with the memory area used for any other pool. Pool capabilities
 * (odp_pool_ext_capability_t) specify the minimum alignment of the memory area.
 *
 * Pool type defines memory buffer layout and where the buffer pointer (buf[N]) points
 * in the layout. Pool capabilities specify requirements for buffer size, layout and
 * pointer alignment.
 *
 * For packet pools, packet buffer layout is shown below. The packet headroom (odp_packet_head())
 * starts immediately after the application header. For a segmented packet, each segment has this
 * same layout. Buffer size includes all headers, headroom, data, tailroom and trailer.
 *
 * @code{.unparsed}
 *
 *                      +-------------------------------+    --                     --
 *          buf[N] ---> |                               |     |                      |
 *                      | ODP header (optional)         |      > odp_header_size     |
 *                      |                               |     |                      |
 *                      +-------------------------------+    --                      |
 *                      |                               |     |                      |
 *                      | Application header (optional) |      > app_header_size     |
 *                      |                               |     |                       > buf_size
 *                      +-------------------------------+    --                      |
 * odp_packet_head()--> |                               |                            |
 *                      | Packet data                   |                            |
 *                      |  (headroom, data, tailroom)   |                            |
 *                      |                               |                            |
 *                      |                               |                            |
 *                      +-------------------------------+    --                      |
 *                      |                               |     |                      |
 *                      | ODP trailer (optional)        |      > odp_trailer_size    |
 *                      |                               |     |                      |
 *                      +-------------------------------+    --                     --
 *
 * @endcode
 *
 * @param pool      External memory pool
 * @param buf       Buffer pointers to be populated into the pool
 * @param buf_size  Buffer size
 * @param num       Number of buffer pointers
 * @param flags     0:                      No flags
 *                  ODP_POOL_POPULATE_DONE: Marks the last populate call and completes the pool
 *                                          population phase
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pool_ext_populate(odp_pool_t pool, void *buf[], uint32_t buf_size, uint32_t num,
			  uint32_t flags);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
