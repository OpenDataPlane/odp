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

#include <odp/api/std_types.h>
#include <odp/api/atomic.h>
#include <odp/api/pool.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/byteorder.h>
#include <odp/api/thread.h>
#include <sys/types.h>
#include <odp/api/event.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_schedule_if.h>
#include <stddef.h>

/* DPDK */
#include <rte_mbuf.h>

ODP_STATIC_ASSERT(ODP_CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");

ODP_STATIC_ASSERT((ODP_CONFIG_PACKET_BUF_LEN_MAX %
		   ODP_CONFIG_PACKET_SEG_LEN_MIN) == 0,
		  "Packet max size must be a multiple of segment size");

#define ODP_BUFFER_MAX_SEG \
	(ODP_CONFIG_PACKET_BUF_LEN_MAX / ODP_CONFIG_PACKET_SEG_LEN_MIN)

/* We can optimize storage of small raw buffers within metadata area */
#define ODP_MAX_INLINE_BUF     ((sizeof(void *)) * (ODP_BUFFER_MAX_SEG - 1))

typedef union odp_buffer_bits_t {
	odp_buffer_t handle;
} odp_buffer_bits_t;

#define BUFFER_BURST_SIZE    CONFIG_BURST_SIZE

struct odp_buffer_hdr_t {
	struct rte_mbuf mb;            /* Underlying DPDK rte_mbuf */
	struct odp_buffer_hdr_t *next;       /* next buf in a list */
	union {                              /* Multi-use secondary link */
		struct odp_buffer_hdr_t *prev;
		struct odp_buffer_hdr_t *link;
	};
	odp_buffer_bits_t        handle;     /* handle */

	int burst_num;
	int burst_first;
	struct odp_buffer_hdr_t *burst[BUFFER_BURST_SIZE];

	int                      type;       /* ODP buffer type;
						not DPDK buf type */
	odp_event_type_t         event_type; /* for reuse as event */
	odp_pool_t		 pool_hdl;   /* buffer pool handle */
	union {
		uint64_t         buf_u64;    /* user u64 */
		void            *buf_ctx;    /* user context */
		const void      *buf_cctx;   /* const alias for ctx */
	};
	uint32_t totsize;              /* total size of all allocated segs */
	uint32_t index;                /* Index in the rte_mempool */
};

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
