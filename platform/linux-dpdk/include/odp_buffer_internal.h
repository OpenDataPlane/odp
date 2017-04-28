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

ODP_STATIC_ASSERT(CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");

ODP_STATIC_ASSERT(CONFIG_PACKET_MAX_SEGS < 256,
		  "Maximum of 255 segments supported");

typedef union odp_buffer_bits_t {
	odp_buffer_t handle;
} odp_buffer_bits_t;

#define BUFFER_BURST_SIZE    CONFIG_BURST_SIZE

struct odp_buffer_hdr_t {
	/* Underlying DPDK rte_mbuf */
	struct rte_mbuf mb;
	/* Handle union */
	odp_buffer_bits_t handle;

	 /* ODP buffer type, not DPDK buf type */
	int type;

	/* Burst counts */
	int burst_num;
	int burst_first;

	/* Next buf in a list */
	struct odp_buffer_hdr_t *next;

	/* User context pointer or u64 */
	union {
		uint64_t    buf_u64;
		void       *buf_ctx;
		const void *buf_cctx; /* const alias for ctx */
	};

	/* Event type. Maybe different than pool type (crypto compl event) */
	odp_event_type_t         event_type;

	/* Burst table */
	struct odp_buffer_hdr_t *burst[BUFFER_BURST_SIZE];

	/* Pool handle */
	odp_pool_t pool_hdl;

	/* Total size of all allocated segs */
	uint32_t totsize;
	/* Index in the rte_mempool */
	uint32_t index;
};

ODP_STATIC_ASSERT(BUFFER_BURST_SIZE < 256, "BUFFER_BURST_SIZE_TOO_LARGE");

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
