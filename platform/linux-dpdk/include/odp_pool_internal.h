/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer pool - internal header
 */

#ifndef ODP_POOL_INTERNAL_H_
#define ODP_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_pool_subsystem.h>
#include <odp_buffer_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/plat/strong_types.h>
#include <string.h>

/* for DPDK */
#include <rte_mempool.h>

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK

/* Extra error checks */
/* #define POOL_ERROR_CHECK */


#ifdef POOL_USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#else
#include <odp/api/spinlock.h>
#endif

/* Control plane structure - Accessed only by control plane code */
typedef struct pool_entry_cp_t {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t	lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t		lock ODP_ALIGNED_CACHE;
#endif
	char			name[ODP_POOL_NAME_LEN];
	odp_pool_param_t	params;
	odp_pool_t		pool_hdl;
} pool_entry_cp_t;

/* Data plane structure - Accessed only by data plane code */
typedef struct pool_entry_dp_t {
	struct rte_mempool	*rte_mempool;
} pool_entry_dp_t;

/* Control plane only pool info */
typedef struct pool_table_cp_t {
	pool_entry_cp_t pool[ODP_CONFIG_POOLS];
	odp_shm_t shm_cp;
	odp_shm_t shm_dp;
} pool_table_cp_t;

/* Data plane only pool info */
typedef struct pool_table_dp_t {
	pool_entry_dp_t pool[ODP_CONFIG_POOLS];
} pool_table_dp_t ODP_ALIGNED_CACHE;

extern pool_table_cp_t *pool_tbl_cp;
extern pool_table_dp_t *pool_tbl_dp;

static inline uint32_t pool_handle_to_index(odp_pool_t pool_hdl)
{
	return _odp_typeval(pool_hdl);
}

static inline void *get_pool_entry_cp(uint32_t pool_id)
{
	return &pool_tbl_cp->pool[pool_id];
}

static inline void *get_pool_entry_dp(uint32_t pool_id)
{
	return &pool_tbl_dp->pool[pool_id];
}

static inline pool_entry_cp_t *odp_pool_to_entry_cp(odp_pool_t pool)
{
	return (pool_entry_cp_t *)get_pool_entry_cp(pool_handle_to_index(pool));
}

static inline pool_entry_dp_t *odp_pool_to_entry_dp(odp_pool_t pool)
{
	return (pool_entry_dp_t *)get_pool_entry_dp(pool_handle_to_index(pool));
}

static inline odp_pool_t pool_index_to_handle(uint32_t pool_id)
{
	return _odp_cast_scalar(odp_pool_t, pool_id);
}

#ifdef __cplusplus
}
#endif

#endif /* ODP_POOL_INTERNAL_H_ */
