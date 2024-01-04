/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Nokia
 */

/**
 * @file
 *
 * ODP stash
 */

#ifndef ODP_API_SPEC_STASH_H_
#define ODP_API_SPEC_STASH_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/stash_types.h>

/** @addtogroup odp_stash
 *  Stash for storing object handles
 *  @{
 */

/**
 * Query stash capabilities
 *
 * Outputs capabilities of the given stash type on success. The stash type
 * is not supported if 'max_stashes' capability is zero. The default stash
 * type (ODP_STASH_TYPE_DEFAULT) is always supported. The function returns
 * failure if the given stash type is unknown to the implementation.
 *
 * @param[out] capa   Pointer to capability structure for output
 * @param      type   Stash type
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_stash_capability(odp_stash_capability_t *capa, odp_stash_type_t type);

/**
 * Initialize stash params
 *
 * Initialize an odp_stash_param_t to its default values for all fields.
 *
 * @param param   Parameter structure to be initialized
 */
void odp_stash_param_init(odp_stash_param_t *param);

/**
 * Create a stash
 *
 * This routine is used to create a stash for object handles. Object handle
 * values are opaque data to ODP implementation. Application may use a stash
 * to store e.g. pointers, offsets or indexes to arbitrary objects which are
 * allocated and freed frequently (e.g. per packet) during application
 * processing. Object handle size is specified in stash parameters.
 *
 * It is optional to give a name. Names do not have to be unique. However,
 * odp_stash_lookup() returns only a single matching stash.
 *
 * @param name     Name of the stash or NULL. Maximum string length is
 *                 ODP_STASH_NAME_LEN.
 * @param param    Stash creation parameters
 *
 * @return Handle of the created stash
 * @retval ODP_STASH_INVALID  Stash could not be created
 */
odp_stash_t odp_stash_create(const char *name, const odp_stash_param_t *param);

/**
 * Destroy a stash
 *
 * Destroy a previously created stash. Stash must be empty before it is
 * destroyed. Results are undefined if an attempt is made to destroy a stash
 * that contains object handles.
 *
 * @param stash    The stash to be destroyed
 *
 * @retval  0 Success
 * @retval <0 Failure
 */
int odp_stash_destroy(odp_stash_t stash);

/**
 * Find a stash by name
 *
 * @param name      Name of the stash
 *
 * @return Handle of the first matching stash
 * @retval ODP_STASH_INVALID  Stash could not be found
 */
odp_stash_t odp_stash_lookup(const char *name);

/**
 * Get printable value for a stash handle
 *
 * @param stash  Handle to be converted for debugging
 * @return uint64_t value that can be used for debugging (e.g. printed)
 */
uint64_t odp_stash_to_u64(odp_stash_t stash);

/**
 * Put object handles into a stash
 *
 * Store object handles into the stash. Handle values are opaque data to
 * ODP implementation and may be e.g. pointers or indexes to arbitrary objects.
 * Application specifies object handle size and maximum number of handles to be
 * stored in stash creation parameters.
 *
 * A successful operation returns the actual number of object handles stored.
 * If the return value is less than 'num', the remaining handles at the end of
 * 'obj' array are not stored.
 *
 * In case of ODP_STASH_TYPE_FIFO, object handles are stored into the stash in
 * the order they are in the array.
 *
 * @param stash  Stash handle
 * @param obj    Points to an array of object handles to be stored.
 *               Object handle size is specified by 'obj_size' in stash
 *               creation parameters. The array must be 'obj_size' aligned
 *               in memory.
 * @param num    Number of object handles to store
 *
 * @return Number of object handles actually stored (0 ... num)
 * @retval <0 on failure
 */
int32_t odp_stash_put(odp_stash_t stash, const void *obj, int32_t num);

/**
 * Put batch of object handles into a stash
 *
 * Otherwise like odp_stash_put(), except that this function stores either all
 * 'num' object handles or none. odp_stash_capability_t.max_put_batch defines
 * the maximum supported batch size.
 *
 * @param stash  Stash handle
 * @param obj    Points to an array of object handles to be stored.
 *               Object handle size is specified by 'obj_size' in stash
 *               creation parameters. The array must be 'obj_size' aligned
 *               in memory.
 * @param num    Number of object handles to store
 *
 * @return Number of object handles actually stored (0 or num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_batch(odp_stash_t stash, const void *obj, int32_t num);

/**
 * Put 32-bit integers into a stash
 *
 * Otherwise like odp_stash_put(), except that this function operates on 32-bit
 * integers. The stash must have been created with 'obj_size' of 4.
 *
 * @param stash  Stash handle
 * @param val    Points to an array of 32-bit integers to be stored. The array
 *               must be 32-bit aligned in memory.
 * @param num    Number of integers to store
 *
 * @return Number of integers actually stored (0 ... num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_u32(odp_stash_t stash, const uint32_t val[], int32_t num);

/**
 * Put batch of 32-bit integers into a stash
 *
 * Otherwise like odp_stash_put_u32(), except that this function stores either
 * all 'num' object handles or none. odp_stash_capability_t.max_put_batch
 * defines the maximum supported batch size.
 *
 * @param stash  Stash handle
 * @param val    Points to an array of 32-bit integers to be stored. The array
 *               must be 32-bit aligned in memory.
 * @param num    Number of integers to store
 *
 * @return Number of integers actually stored (0 or num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_u32_batch(odp_stash_t stash, const uint32_t val[], int32_t num);

/**
 * Put 64-bit integers into a stash
 *
 * Otherwise like odp_stash_put(), except that this function operates on 64-bit
 * integers. The stash must have been created with 'obj_size' of 8.
 *
 * @param stash  Stash handle
 * @param val    Points to an array of 64-bit integers to be stored. The array
 *               must be 64-bit aligned in memory.
 * @param num    Number of integers to store
 *
 * @return Number of integers actually stored (0 ... num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_u64(odp_stash_t stash, const uint64_t val[], int32_t num);

/**
 * Put batch of 64-bit integers into a stash
 *
 * Otherwise like odp_stash_put_u64(), except that this function stores either
 * all 'num' object handles or none. odp_stash_capability_t.max_put_batch
 * defines the maximum supported batch size.
 *
 * @param stash  Stash handle
 * @param val    Points to an array of 64-bit integers to be stored. The array
 *               must be 64-bit aligned in memory.
 * @param num    Number of integers to store
 *
 * @return Number of integers actually stored (0 or num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_u64_batch(odp_stash_t stash, const uint64_t val[], int32_t num);

/**
 * Put pointers into a stash
 *
 * Otherwise like odp_stash_put(), except that this function operates on
 * pointers. The stash must have been created with 'obj_size' matching to the
 * size of uintptr_t.
 *
 * @param stash  Stash handle
 * @param ptr    Points to an array of pointers to be stored. The array must be
 *               pointer size aligned in memory.
 * @param num    Number of pointers to store
 *
 * @return Number of pointers actually stored (0 ... num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_ptr(odp_stash_t stash, const uintptr_t ptr[], int32_t num);

/**
 * Put batch of pointers into a stash
 *
 * Otherwise like odp_stash_put_ptr(), except that this function stores either
 * all 'num' object handles or none. odp_stash_capability_t.max_put_batch
 * defines the maximum supported batch size.
 *
 * @param stash  Stash handle
 * @param ptr    Points to an array of pointers to be stored. The array must be
 *               pointer size aligned in memory.
 * @param num    Number of pointers to store
 *
 * @return Number of pointers actually stored (0 or num)
 * @retval <0 on failure
 */
int32_t odp_stash_put_ptr_batch(odp_stash_t stash, const uintptr_t ptr[], int32_t num);

/**
 * Get object handles from a stash
 *
 * Get previously stored object handles from the stash. Application specifies
 * object handle size in stash creation parameters.
 *
 * @param      stash  Stash handle
 * @param[out] obj    Points to an array of object handles for output.
 *                    Object handle size is specified by 'obj_size' in stash
 *                    creation parameters. The array must be 'obj_size' aligned
 *                    in memory.
 * @param      num    Maximum number of object handles to get from the stash
 *
 * @return Number of object handles actually output (0 ... num) to 'obj' array
 * @retval <0 on failure
 */
int32_t odp_stash_get(odp_stash_t stash, void *obj, int32_t num);

/**
 * Get batch of object handles from a stash
 *
 * Otherwise like odp_stash_get(), except that this function outputs either
 * all 'num' object handles or none. odp_stash_capability_t.max_get_batch
 * defines the maximum supported batch size.
 *
 * @param      stash  Stash handle
 * @param[out] obj    Points to an array of object handles for output.
 *                    Object handle size is specified by 'obj_size' in stash
 *                    creation parameters. The array must be 'obj_size' aligned
 *                    in memory.
 * @param      num    Number of object handles to get from the stash
 *
 * @return Number of object handles actually output (0 or num) to 'obj' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_batch(odp_stash_t stash, void *obj, int32_t num);

/**
 * Get 32-bit integers from a stash
 *
 * Otherwise like odp_stash_get(), except that this function operates on 32-bit
 * integers. The stash must have been created with 'obj_size' of 4.
 *
 * @param      stash  Stash handle
 * @param[out] val    Points to an array of 32-bit integers for output. The
 *                    array must be 32-bit aligned in memory.
 * @param      num    Maximum number of integers to get from the stash
 *
 * @return Number of integers actually output (0 ... num) to 'val' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_u32(odp_stash_t stash, uint32_t val[], int32_t num);

/**
 * Get batch of 32-bit integers from a stash
 *
 * Otherwise like odp_stash_get_u32(), except that this function outputs either
 * all 'num' object handles or none. odp_stash_capability_t.max_get_batch
 * defines the maximum supported batch size.
 *
 * @param      stash  Stash handle
 * @param[out] val    Points to an array of 32-bit integers for output. The
 *                    array must be 32-bit aligned in memory.
 * @param      num    Number of integers to get from the stash
 *
 * @return Number of integers actually output (0 or num) to 'val' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_u32_batch(odp_stash_t stash, uint32_t val[], int32_t num);

/**
 * Get 64-bit integers from a stash
 *
 * Otherwise like odp_stash_get(), except that this function operates on 64-bit
 * integers. The stash must have been created with 'obj_size' of 8.
 *
 * @param      stash  Stash handle
 * @param[out] val    Points to an array of 64-bit integers for output. The
 *                    array must be 64-bit aligned in memory.
 * @param      num    Maximum number of integers to get from the stash
 *
 * @return Number of integers actually output (0 ... num) to 'val' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_u64(odp_stash_t stash, uint64_t val[], int32_t num);

/**
 * Get batch of 64-bit integers from a stash
 *
 * Otherwise like odp_stash_get_u64(), except that this function outputs either
 * all 'num' object handles or none. odp_stash_capability_t.max_get_batch
 * defines the maximum supported batch size.
 *
 * @param      stash  Stash handle
 * @param[out] val    Points to an array of 64-bit integers for output. The
 *                    array must be 64-bit aligned in memory.
 * @param      num    Number of integers to get from the stash
 *
 * @return Number of integers actually output (0 or num) to 'val' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_u64_batch(odp_stash_t stash, uint64_t val[], int32_t num);

/**
 * Get pointers from a stash
 *
 * Otherwise like odp_stash_get(), except that this function operates on
 * pointers. The stash must have been created with 'obj_size' matching to the
 * size of uintptr_t.
 *
 * @param      stash  Stash handle
 * @param[out] ptr    Points to an array of pointers for output. The array must
 *                    be pointer size aligned in memory.
 * @param      num    Maximum number of pointers to get from the stash
 *
 * @return Number of pointers actually output (0 ... num) to 'ptr' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_ptr(odp_stash_t stash, uintptr_t ptr[], int32_t num);

/**
 * Get batch of pointers from a stash
 *
 * Otherwise like odp_stash_get_ptr(), except that this function outputs either
 * all 'num' object handles or none. odp_stash_capability_t.max_get_batch
 * defines the maximum supported batch size.
 *
 * @param      stash  Stash handle
 * @param[out] ptr    Points to an array of pointers for output. The array must
 *                    be pointer size aligned in memory.
 * @param      num    Number of pointers to get from the stash
 *
 * @return Number of pointers actually output (0 or num) to 'ptr' array
 * @retval <0 on failure
 */
int32_t odp_stash_get_ptr_batch(odp_stash_t stash, uintptr_t ptr[], int32_t num);

/**
 * Flush object handles from the thread local cache
 *
 * Flushes all object handles from the thread local cache into the stash, so
 * that those are available to odp_stash_get() calls from other threads. This
 * call may be used to ensure that thread local cache is empty e.g. before
 * the calling thread stops using the stash.
 *
 * Flush and put operations share 'put_mode' setting in stash creation
 * parameters. So, application must ensure that flush and put operations are not
 * used concurrently, when ODP_STASH_OP_ST is selected.
 *
 * @param stash  Stash handle
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_stash_flush_cache(odp_stash_t stash);

/**
 * Print debug information about the stash
 *
 * Print implementation defined information about the stash to the ODP log. The information
 * is intended to be used for debugging.
 *
 * @param stash  Stash handle
 */
void odp_stash_print(odp_stash_t stash);

/**
 * Read statistics counters of a stash
 *
 * Read the statistics counters enabled using odp_stash_stats_opt_t during stash creation.
 * Inactive counters are set to zero by the implementation.
 *
 * @param      stash  Stash handle
 * @param[out] stats  Points to statistics counters structure for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_stash_stats(odp_stash_t stash, odp_stash_stats_t *stats);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
