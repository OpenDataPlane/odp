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

#ifndef ODP_BUFFER_POOL_INTERNAL_H_
#define ODP_BUFFER_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_buffer_pool.h>
#include <odp_buffer_internal.h>
#include <odp_align.h>
#include <odp_hints.h>
#include <odp_config.h>
#include <odp_debug.h>

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK

/* Extra error checks */
/* #define POOL_ERROR_CHECK */


#ifdef POOL_USE_TICKETLOCK
#include <odp_ticketlock.h>
#else
#include <odp_spinlock.h>
#endif

struct pool_entry_s {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t          lock ODP_ALIGNED_CACHE;
#endif

	uint64_t                free_bufs;
	char                    name[ODP_BUFFER_POOL_NAME_LEN];

	odp_buffer_pool_t       pool ODP_ALIGNED_CACHE;
	uint64_t                num_bufs;
	void                   *pool_base_addr;
	uintptr_t               pool_base_paddr;
	uint64_t                pool_size;
	size_t                  payload_size;
	size_t                  payload_align;
	int                     buf_type;
	odp_queue_t             free_queue;

	uintptr_t               buf_base;
	size_t                  buf_size;
	size_t                  buf_offset;
	size_t                  hdr_size;
};

extern void *pool_entry_ptr[];


static inline void *get_pool_entry(odp_buffer_pool_t pool_id)
{
	return pool_entry_ptr[pool_id];
}

#ifdef __cplusplus
}
#endif

#endif
