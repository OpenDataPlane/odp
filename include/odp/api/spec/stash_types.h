/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Nokia
 */

/**
 * @file
 *
 * ODP stash types
 */

#ifndef ODP_API_SPEC_STASH_TYPES_H_
#define ODP_API_SPEC_STASH_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @defgroup odp_stash ODP STASH
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
 * Maximum stash name length, including the null character
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
 * Stash statistics counters options
 *
 * Statistics counters listed in a bit field structure.
 */
typedef union odp_stash_stats_opt_t {
	/** Option flags */
	struct {
		/** See odp_stash_stats_t::count */
		uint64_t count          : 1;

		/** See odp_stash_stats_t::cache_count */
		uint64_t cache_count    : 1;

	} bit;

	/** All bits of the bit field structure
	 *
	 *  This field can be used to set/clear all flags, or for bitwise
	 *  operations over the entire structure. */
	uint64_t all;

} odp_stash_stats_opt_t;

/**
 * Stash statistics counters
 */
typedef struct odp_stash_stats_t {
	/** Object count in the stash
	 *
	 *  Number of objects currently stored in the stash. The count does not include objects
	 *  stored in thread local caches. When caching is enabled, the total object count
	 *  is the sum of 'count' and 'cache_count'.
	 */
	uint64_t count;

	/** Object count in thread local caches of the stash
	 *
	 *  Number of objects stored in all thread local caches of the stash.
	 */
	uint64_t cache_count;

} odp_stash_stats_t;

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

	/** Maximum common number of object handles per stash for any object size
	 *
	 *  An application is able to store at least this many objects when using any of the
	 *  supported object sizes. Some of the per object size values listed in 'max_num' may be
	 *  larger than this common value.
	 */
	uint64_t max_num_obj;

	/** Maximum number of object handles per stash for each object size
	 *
	 *  Values for unsupported object handle sizes are set to zero.
	 */
	struct {
		/** Maximum number of 1 byte object handles */
		uint64_t u8;

		/** Maximum number of 2 byte object handles */
		uint64_t u16;

		/** Maximum number of 4 byte object handles */
		uint64_t u32;

		/** Maximum number of 8 byte object handles */
		uint64_t u64;

		/** Maximum number of 16 byte object handles */
		uint64_t u128;

		/** Maximum number of 'max_obj_size' object handles */
		uint64_t max_obj_size;
	} max_num;

	/** Maximum object handle size in bytes
	 *
	 *  At least 4 byte object handle size is always supported.
	 */
	uint32_t max_obj_size;

	/** Maximum size of thread local cache */
	uint32_t max_cache_size;

	/** Maximum number of object handles in batch get operations
	 *
	 *  At least 1 object batch size is always supported.
	 */
	uint32_t max_get_batch;

	/** Maximum number of object handles in batch put operations
	 *
	 *  At least 1 object batch size is always supported.
	 */
	uint32_t max_put_batch;

	/** Supported statistics counters */
	odp_stash_stats_opt_t stats;

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

	/** Number of object handles
	 *
	 *  Application must be able to store at least this many object handles
	 *  into the stash. An implementation may round up the value. The given
	 *  value must not exceed 'max_num' capability.
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

	/**
	 * Configure statistics counters
	 *
	 * See stash capabilities for supported statistics counters. Use odp_stash_stats() to read
	 * the enabled counters. For optimal performance, enable only those counters that are
	 * actually used. All counters are disabled by default.
	 */
	odp_stash_stats_opt_t stats;

	/**
	 * Strict size
	 *
	 * If true, application never attempts to store more handles into the stash than specified
	 * in the 'num_obj' parameter. Implementation may use this value as a hint for performance
	 * optimizations. The default value is false.
	 */
	odp_bool_t strict_size;

} odp_stash_param_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
