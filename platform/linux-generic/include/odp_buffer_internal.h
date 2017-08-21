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
#include <odp/api/event.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_schedule_if.h>
#include <stddef.h>

#define BUFFER_BURST_SIZE    CONFIG_BURST_SIZE

typedef struct seg_entry_t {
	void     *hdr;
	uint8_t  *data;
	uint32_t  len;
} seg_entry_t;

/* Common buffer header */
struct odp_buffer_hdr_t {

	/* Buffer index in the pool */
	uint32_t  index;

	/* Total segment count */
	uint16_t  segcount;

	/* Pool type */
	int8_t    type;

	/* Number of seg[] entries used */
	uint8_t   num_seg;

	/* Next header which continues the segment list */
	void *next_seg;

	/* Last header of the segment list */
	void *last_seg;

	/* Initial buffer data pointer */
	uint8_t  *base_data;

	/* Reference count */
	odp_atomic_u32_t ref_cnt;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* --- 37 bytes --- */

	/* Segments */
	seg_entry_t seg[CONFIG_PACKET_MAX_SEGS];

	/* Burst counts */
	uint8_t   burst_num;
	uint8_t   burst_first;

	/* Next buf in a list */
	struct odp_buffer_hdr_t *next;

	/* Burst table */
	struct odp_buffer_hdr_t *burst[BUFFER_BURST_SIZE];

	/* --- Mostly read only data --- */

	/* User context pointer or u64 */
	union {
		uint64_t    buf_u64;
		void       *buf_ctx;
		const void *buf_cctx; /* const alias for ctx */
	};

	/* Pool pointer */
	void *pool_ptr;

	/* Initial buffer tail pointer */
	uint8_t  *buf_end;

	/* User area pointer */
	void    *uarea_addr;

	/* User area size */
	uint32_t uarea_size;

	/* Max data size */
	uint32_t size;

	/* ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t ipc_data_offset;

	/* Pool handle: will be removed, used only for odp_packet_pool()
	 * inlining */
	odp_pool_t pool_hdl;

	/* Data or next header */
	uint8_t data[0];
} ODP_ALIGNED_CACHE;

ODP_STATIC_ASSERT(CONFIG_PACKET_MAX_SEGS < 256,
		  "CONFIG_PACKET_MAX_SEGS_TOO_LARGE");

ODP_STATIC_ASSERT(BUFFER_BURST_SIZE < 256, "BUFFER_BURST_SIZE_TOO_LARGE");

#ifdef __cplusplus
}
#endif

#endif
