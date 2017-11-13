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

/* Common buffer header */
struct odp_buffer_hdr_t {
	/* Total segment count */
	uint16_t  segcount;

	/* Pool type */
	int8_t    type;

	/* Offset used to restore base_data */
	uint8_t pristine_offset;

	/* Next header which continues the segment list */
	void *next_seg;

	/* Pointer to start of segment */
	uint8_t  *base_data;

	/* Pool pointer */
	void *pool_ptr;

#ifndef ODP_SCHEDULE_SCALABLE
	/* Burst counts */
	uint8_t   burst_num;
	uint8_t   burst_first;

	/* Next buf in a list */
	struct odp_buffer_hdr_t *next;

	/* Burst table */
	struct odp_buffer_hdr_t *burst[BUFFER_BURST_SIZE];
#endif
	/* --- Mostly read only data --- */

	/* User context pointer or u64 */
	union {
		uint64_t    buf_u64;
		void       *buf_ctx;
		const void *buf_cctx; /* const alias for ctx */
	};

	/* Reference count */
	odp_atomic_u32_t ref_cnt;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Initial buffer tail pointer */
	uint8_t  *buf_end;

	/* User area pointer */
	void    *uarea_addr;

	/* Max data size */
	uint32_t size;

	/* Event subtype. Should be ODP_EVENT_NO_SUBTYPE except packets. */
	int8_t    event_subtype;

	/* ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t ipc_data_offset;

	/* Pool handle: will be removed, used only for odp_packet_pool()
	 * inlining */
	odp_pool_t pool_hdl;

	/* Data or next header */
	uint8_t data[0];
} ODP_ALIGNED_CACHE;

ODP_STATIC_ASSERT(CONFIG_PACKET_SEGS_PER_HDR < 256,
		  "CONFIG_PACKET_SEGS_PER_HDR_TOO_LARGE");

ODP_STATIC_ASSERT(BUFFER_BURST_SIZE < 256, "BUFFER_BURST_SIZE_TOO_LARGE");

#ifdef __cplusplus
}
#endif

#endif
