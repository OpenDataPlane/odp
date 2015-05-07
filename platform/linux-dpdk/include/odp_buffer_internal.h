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

#include <odp/std_types.h>
#include <odp/atomic.h>
#include <odp/pool.h>
#include <odp/buffer.h>
#include <odp/debug.h>
#include <odp/align.h>
#include <odp_align_internal.h>
#include <odp/config.h>
#include <odp/byteorder.h>
#include <odp/thread.h>
#include <sys/types.h>

/* DPDK */
#include <rte_mbuf.h>

_ODP_STATIC_ASSERT(ODP_CONFIG_PACKET_SEG_LEN_MIN >= 256,
		   "ODP Segment size must be a minimum of 256 bytes");

_ODP_STATIC_ASSERT((ODP_CONFIG_PACKET_BUF_LEN_MAX %
		   ODP_CONFIG_PACKET_SEG_LEN_MIN) == 0,
		   "Packet max size must be a multiple of segment size");

#define ODP_BUFFER_MAX_SEG \
	(ODP_CONFIG_PACKET_BUF_LEN_MAX / ODP_CONFIG_PACKET_SEG_LEN_MIN)

/* We can optimize storage of small raw buffers within metadata area */
#define ODP_MAX_INLINE_BUF     ((sizeof(void *)) * (ODP_BUFFER_MAX_SEG - 1))

typedef union odp_buffer_bits_t {
	odp_buffer_t handle;
} odp_buffer_bits_t;

typedef struct odp_buffer_hdr_t {
	struct rte_mbuf mb;            /* Underlying DPDK rte_mbuf */
	struct odp_buffer_hdr_t *next;       /* next buf in a list */
	odp_buffer_bits_t        handle;     /* handle */
	int                      type;       /* ODP buffer type;
						not DPDK buf type */
	odp_pool_t		 pool_hdl;   /* buffer pool handle */
	union {
		uint64_t         buf_u64;    /* user u64 */
		void            *buf_ctx;    /* user context */
		const void      *buf_cctx;   /* const alias for ctx */
		void            *udata_addr; /* user metadata addr */
	};
	size_t                   udata_size; /* size of user metadata */
	uint32_t index;                /* Index in the rte_mempool */
} odp_buffer_hdr_t;

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

/*
 * Buffer type
 *
 * @param buf      Buffer handle
 *
 * @return Buffer type
 */
int _odp_buffer_type(odp_buffer_t buf);

/*
 * Buffer type set
 *
 * @param buf      Buffer handle
 * @param type     New type value
 *
 */
void _odp_buffer_type_set(odp_buffer_t buf, int type);

#ifdef __cplusplus
}
#endif

#endif
