/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer descriptor - implementation internal
 */

#ifndef ODP_BUFFER_INTERNAL_H_
#define ODP_BUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_atomic.h>
#include <odp_buffer_pool.h>
#include <odp_buffer.h>
#include <odp_debug.h>
#include <odp_align.h>
#include <rte_mbuf.h>

/* TODO: move these to correct files */

typedef uint64_t odp_phys_addr_t;

#define ODP_BUFFER_MAX_INDEX     (ODP_BUFFER_MAX_BUFFERS - 2)
#define ODP_BUFFER_INVALID_INDEX (ODP_BUFFER_MAX_BUFFERS - 1)

#define ODP_BUFS_PER_CHUNK       16
#define ODP_BUFS_PER_SCATTER      4

#define ODP_BUFFER_TYPE_CHUNK    0xffff


#define ODP_BUFFER_POOL_BITS   4
#define ODP_BUFFER_INDEX_BITS  (32 - ODP_BUFFER_POOL_BITS)
#define ODP_BUFFER_MAX_POOLS   (1 << ODP_BUFFER_POOL_BITS)
#define ODP_BUFFER_MAX_BUFFERS (1 << ODP_BUFFER_INDEX_BITS)

typedef union odp_buffer_bits_t {
	uint32_t     u32;
	odp_buffer_t handle;

	struct {
		uint32_t pool:ODP_BUFFER_POOL_BITS;
		uint32_t index:ODP_BUFFER_INDEX_BITS;
	};
} odp_buffer_bits_t;


/* forward declaration */
struct odp_buffer_hdr_t;


typedef struct odp_buffer_hdr_t {
	struct rte_mbuf mb;            /* Underlying DPDK rte_mbuf */
	struct odp_buffer_hdr_t *next; /* Next buf in a list */
	int type;                      /* ODP buffer type; not DPDK buf type */
	uint32_t index;                /* Index in the rte_mempool */
} odp_buffer_hdr_t;

int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf);


#ifdef __cplusplus
}
#endif

#endif
