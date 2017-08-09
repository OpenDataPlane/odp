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


struct pool_entry_s {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t	lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t		lock ODP_ALIGNED_CACHE;
#endif
	char			name[ODP_POOL_NAME_LEN];
	odp_pool_param_t	params;
	odp_pool_t		pool_hdl;
	struct rte_mempool	*rte_mempool;
};

typedef union pool_entry_u {
	struct pool_entry_s s;

	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct pool_entry_s))];

} pool_entry_t;

extern void *pool_entry_ptr[];

static inline uint32_t pool_handle_to_index(odp_pool_t pool_hdl)
{
	return _odp_typeval(pool_hdl);
}

static inline void *get_pool_entry(uint32_t pool_id)
{
	return pool_entry_ptr[pool_id];
}

static inline pool_entry_t *odp_pool_to_entry(odp_pool_t pool)
{
	return (pool_entry_t *)get_pool_entry(pool_handle_to_index(pool));
}

static inline odp_pool_t pool_index_to_handle(uint32_t pool_id)
{
	return _odp_cast_scalar(odp_pool_t, pool_id);
}

#ifdef __cplusplus
}
#endif

#endif /* ODP_POOL_INTERNAL_H_ */
