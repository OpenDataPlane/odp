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

typedef union odp_buffer_bits_t {
	odp_buffer_t             handle;

	union {
		uint32_t         u32;

		struct {
			uint32_t pool_id: 8;
			uint32_t index:   24;
		};
	};
} odp_buffer_bits_t;

#define BUFFER_BURST_SIZE    CONFIG_BURST_SIZE

/* Common buffer header */
struct odp_buffer_hdr_t {
	/* Handle union */
	odp_buffer_bits_t handle;

	/* Initial buffer data pointer and length */
	uint8_t  *base_data;
	uint8_t  *buf_end;

	/* Max data size */
	uint32_t  size;

	/* Pool type */
	int8_t    type;

	/* Burst counts */
	uint8_t   burst_num;
	uint8_t   burst_first;

	/* Segment count */
	uint8_t   segcount;

	/* Segments */
	struct {
		void     *hdr;
		uint8_t  *data;
		uint32_t  len;
	} seg[CONFIG_PACKET_MAX_SEGS];

	/* Next buf in a list */
	struct odp_buffer_hdr_t *next;

	/* User context pointer or u64 */
	union {
		uint64_t    buf_u64;
		void       *buf_ctx;
		const void *buf_cctx; /* const alias for ctx */
	};

	/* User area pointer */
	void    *uarea_addr;

	/* User area size */
	uint32_t uarea_size;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Burst table */
	struct odp_buffer_hdr_t *burst[BUFFER_BURST_SIZE];

	/* Used only if _ODP_PKTIO_IPC is set.
	 * ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t ipc_data_offset;

	/* Pool handle */
	odp_pool_t pool_hdl;

	/* Data or next header */
	uint8_t data[0];
};

ODP_STATIC_ASSERT(CONFIG_PACKET_MAX_SEGS < 256,
		  "CONFIG_PACKET_MAX_SEGS_TOO_LARGE");

ODP_STATIC_ASSERT(BUFFER_BURST_SIZE < 256, "BUFFER_BURST_SIZE_TOO_LARGE");

/* Forward declarations */
int seg_alloc_tail(odp_buffer_hdr_t *buf_hdr, int segcount);
void seg_free_tail(odp_buffer_hdr_t *buf_hdr, int segcount);

#ifdef __cplusplus
}
#endif

#endif
