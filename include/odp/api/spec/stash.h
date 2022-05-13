/* Copyright (c) 2020-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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

#include <odp/api/std_types.h>

/** @defgroup odp_stash ODP STASH
 *  Stash for storing object handles
 *  @{
 */

/**
 * @typedef odp_stash_t
 * Stash handle
 */

/**
 * @def ODP_STASH_INVALID
 * Invalid stash handle
 */

/**
 * @def ODP_STASH_NAME_LEN
 * Maximum stash name length in chars including null char
 */

/**
 * Stash types
 */
typedef enum odp_stash_type_t {
	/** The default stash type
	 *
	 *  It is implementation specific in which order odp_stash_get() calls
	 *  return object handles from the stash. The order may be FIFO, LIFO
	 *  or something else. Use this for the best performance when any
	 *  particular ordering is not required.
	 */
	ODP_STASH_TYPE_DEFAULT = 0,

	/** Stash type FIFO
	 *
	 *  Stash is implemented as a FIFO. A stash maintains object handle
	 *  order of consecutive odp_stash_put() calls. Object handles stored
	 *  first in the stash are received first by following odp_stash_get()
	 *  calls. To maintain (strict) FIFO ordering of object handles,
	 *  application needs to ensure that odp_stash_put()
	 *  (or odp_stash_get()) operations are not performed concurrently from
	 *  multiple threads. When multiple threads put (or get) object handles
	 *  concurrently in the stash, object handles from different threads
	 *  may be interleaved on output.
	 */
	ODP_STASH_TYPE_FIFO

} odp_stash_type_t;

/**
 * Stash operation mode
 */
typedef enum odp_stash_op_mode_t {
	/** Multi-thread safe operation
	 *
	 *  Multiple threads operate on the stash. A stash operation
	 *  (odp_stash_put() or odp_stash_get()) may be performed concurrently
	 *  from multiple threads.
	 */
	ODP_STASH_OP_MT = 0,

	/** Single thread operation
	 *
	 *  Multiple threads operate on the stash, but application ensures that
	 *  a stash operation (odp_stash_put() or odp_stash_get()) is not
	 *  performed concurrently from multiple threads.
	 */
	ODP_STASH_OP_ST,

	/** Thread local operation
	 *
	 *  Only a single thread operates on the stash. Both stash operations
	 *  (odp_stash_put() and odp_stash_get()) are always performed from the
	 *  same thread.
	 */
	ODP_STASH_OP_LOCAL

} odp_stash_op_mode_t;

/**
 * Stash capabilities (per stash type)
 */
typedef struct odp_stash_capability_t {
	/** Maximum number of stashes of any type */
	uint32_t max_stashes_any_type;

	/** Maximum number of stashes of this type
	 *
	 *  The value of zero means that the requested stash type is not
	 *  supported.
	 */
	uint32_t max_stashes;

	/** Maximum number of object handles per stash
	 *
	 *  The value of zero means that limited only by the available
	 *  memory size.
	 */
	uint64_t max_num_obj;

	/** Maximum object handle size in bytes
	 *
	 *  At least 4 byte object handle size is always supported.
	 */
	uint32_t max_obj_size;

	/** Maximum size of thread local cache */
	uint32_t max_cache_size;

} odp_stash_capability_t;

/**
 * Stash parameters
 */
typedef struct odp_stash_param_t {
	/** Stash type
	 *
	 *  Select type of the stash to be created. The default value is
	 *  ODP_STASH_TYPE_DEFAULT. Use stash capability to check if additional
	 *  types are supported.
	 */
	odp_stash_type_t type;

	/** Put operation mode
	 *
	 *  The default value is ODP_STASH_OP_MT. Usage of ODP_STASH_OP_ST or
	 *  ODP_STASH_OP_LOCAL mode may improve performance when applicable.
	 *  If ODP_STASH_OP_LOCAL is used, it must be set to both put_mode and
	 *  get_mode.
	 */
	odp_stash_op_mode_t put_mode;

	/** Get operation mode
	 *
	 *  The default value is ODP_STASH_OP_MT. Usage of ODP_STASH_OP_ST or
	 *  ODP_STASH_OP_LOCAL mode may improve performance when applicable.
	 *  If ODP_STASH_OP_LOCAL is used, it must be set to both put_mode and
	 *  get_mode.
	 */
	odp_stash_op_mode_t get_mode;

	/** Maximum number of object handles
	 *
	 *  This is the maximum number of object handles application will store
	 *  in the stash. The value must not exceed 'max_num_obj' capability.
	 */
	uint64_t num_obj;

	/** Object handle size in bytes
	 *
	 *  Application uses object handles of this size in put and get
	 *  operations. Valid values are powers of two (1, 2, 4, 8, ... bytes)
	 *  and must not exceed 'max_obj_size' capability.
	 */
	uint32_t obj_size;

	/** Maximum number of object handles cached locally per thread
	 *
	 *  A non-zero value allows implementation to cache object handles
	 *  locally per each thread. Thread local caching may improve
	 *  performance, but requires application to take into account that
	 *  some object handles may be stored locally per thread and thus are
	 *  not available to odp_stash_get() calls from other threads.
	 *
	 *  Strict FIFO ordering of object handles cannot be maintained with
	 *  thread local caching. If application does not require strict
	 *  ordering, it may allow caching also with ODP_STASH_TYPE_FIFO type
	 *  stashes.
	 *
	 *  This is the maximum number of handles to be cached per thread. The
	 *  actual cache size and how it is divided between put and get
	 *  operations is implementation specific. The value must not exceed
	 *  'max_cache_size' capability. The default value is 0.
	 *
	 *  Thread local cache may be emptied with odp_stash_flush_cache().
	 */
	uint32_t cache_size;

} odp_stash_param_t;

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
 * stored in stash creation parameters. Application must not attempt to store
 * more handles into the stash than it specifies in the creation parameters.
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
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
