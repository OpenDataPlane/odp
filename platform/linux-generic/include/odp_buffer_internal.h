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

ODP_STATIC_ASSERT(ODP_CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");


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
	struct odp_buffer_hdr_t *next;       /* next buf in a list--keep 1st */
	union {                              /* Multi-use secondary link */
		struct odp_buffer_hdr_t *prev;
		struct odp_buffer_hdr_t *link;
	};
	odp_buffer_bits_t        handle;     /* handle */

	int burst_num;
	int burst_first;
	struct odp_buffer_hdr_t *burst[BUFFER_BURST_SIZE];

	union {
		uint32_t all;
		struct {
			uint32_t hdrdata:1;  /* Data is in buffer hdr */
			uint32_t sustain:1;  /* Sustain order */
		};
	} flags;

	int8_t                   type;       /* buffer type */
	odp_event_type_t         event_type; /* for reuse as event */
	uint32_t                 size;       /* max data size */
	odp_pool_t               pool_hdl;   /* buffer pool handle */
	union {
		uint64_t         buf_u64;    /* user u64 */
		void            *buf_ctx;    /* user context */
		const void      *buf_cctx;   /* const alias for ctx */
	};
	void                    *uarea_addr; /* user area address */
	uint32_t                 uarea_size; /* size of user area */
	uint32_t                 segcount;   /* segment count */
	uint32_t                 segsize;    /* segment size */
	/* block addrs */
	void                    *addr[ODP_CONFIG_PACKET_MAX_SEGS];
	uint64_t                 order;      /* sequence for ordered queues */
	queue_entry_t           *origin_qe;  /* ordered queue origin */
	union {
		queue_entry_t   *target_qe;  /* ordered queue target */
		uint64_t         sync[SCHEDULE_ORDERED_LOCKS_PER_QUEUE];
	};
#ifdef _ODP_PKTIO_IPC
	/* ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t		 ipc_addr_offset[ODP_CONFIG_PACKET_MAX_SEGS];
#endif

	/* Data or next header */
	uint8_t data[0];
};

/* Forward declarations */
int buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num);
void buffer_free_multi(const odp_buffer_t buf[], int num_free);

int seg_alloc_head(odp_buffer_hdr_t *buf_hdr, int segcount);
void seg_free_head(odp_buffer_hdr_t *buf_hdr, int segcount);
int seg_alloc_tail(odp_buffer_hdr_t *buf_hdr, int segcount);
void seg_free_tail(odp_buffer_hdr_t *buf_hdr, int segcount);

#ifdef __cplusplus
}
#endif

#endif
