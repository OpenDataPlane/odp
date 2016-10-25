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

#define ODP_BITSIZE(x) \
	((x) <=     2 ?  1 : \
	((x) <=     4 ?  2 : \
	((x) <=     8 ?  3 : \
	((x) <=    16 ?  4 : \
	((x) <=    32 ?  5 : \
	((x) <=    64 ?  6 : \
	((x) <=   128 ?  7 : \
	((x) <=   256 ?  8 : \
	((x) <=   512 ?  9 : \
	((x) <=  1024 ? 10 : \
	((x) <=  2048 ? 11 : \
	((x) <=  4096 ? 12 : \
	((x) <=  8196 ? 13 : \
	((x) <= 16384 ? 14 : \
	((x) <= 32768 ? 15 : \
	((x) <= 65536 ? 16 : \
	 (0/0)))))))))))))))))

ODP_STATIC_ASSERT(ODP_CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");

ODP_STATIC_ASSERT((ODP_CONFIG_PACKET_BUF_LEN_MAX %
		   ODP_CONFIG_PACKET_SEG_LEN_MIN) == 0,
		  "Packet max size must be a multiple of segment size");

#define ODP_BUFFER_MAX_SEG \
	(ODP_CONFIG_PACKET_BUF_LEN_MAX / ODP_CONFIG_PACKET_SEG_LEN_MIN)

/* We can optimize storage of small raw buffers within metadata area */
#define ODP_MAX_INLINE_BUF     ((sizeof(void *)) * (ODP_BUFFER_MAX_SEG - 1))

#define ODP_BUFFER_POOL_BITS   ODP_BITSIZE(ODP_CONFIG_POOLS)
#define ODP_BUFFER_SEG_BITS    ODP_BITSIZE(ODP_BUFFER_MAX_SEG)
#define ODP_BUFFER_INDEX_BITS  (32 - ODP_BUFFER_POOL_BITS - ODP_BUFFER_SEG_BITS)
#define ODP_BUFFER_PREFIX_BITS (ODP_BUFFER_POOL_BITS + ODP_BUFFER_INDEX_BITS)
#define ODP_BUFFER_MAX_POOLS   (1 << ODP_BUFFER_POOL_BITS)
#define ODP_BUFFER_MAX_BUFFERS (1 << ODP_BUFFER_INDEX_BITS)

#define ODP_BUFFER_MAX_INDEX     (ODP_BUFFER_MAX_BUFFERS - 2)
#define ODP_BUFFER_INVALID_INDEX (ODP_BUFFER_MAX_BUFFERS - 1)

typedef union odp_buffer_bits_t {
	odp_buffer_t handle;
	union {
		uint32_t     u32;
		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint32_t pool_id:ODP_BUFFER_POOL_BITS;
			uint32_t index:ODP_BUFFER_INDEX_BITS;
			uint32_t seg:ODP_BUFFER_SEG_BITS;
#else
			uint32_t seg:ODP_BUFFER_SEG_BITS;
			uint32_t index:ODP_BUFFER_INDEX_BITS;
			uint32_t pool_id:ODP_BUFFER_POOL_BITS;
#endif
		};

		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint32_t prefix:ODP_BUFFER_PREFIX_BITS;
			uint32_t pfxseg:ODP_BUFFER_SEG_BITS;
#else
			uint32_t pfxseg:ODP_BUFFER_SEG_BITS;
			uint32_t prefix:ODP_BUFFER_PREFIX_BITS;
#endif
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
	int16_t                  allocator;  /* allocating thread id */
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
	void                    *addr[ODP_BUFFER_MAX_SEG]; /* block addrs */
	uint64_t                 order;      /* sequence for ordered queues */
	queue_entry_t           *origin_qe;  /* ordered queue origin */
	union {
		queue_entry_t   *target_qe;  /* ordered queue target */
		uint64_t         sync[SCHEDULE_ORDERED_LOCKS_PER_QUEUE];
	};
#ifdef _ODP_PKTIO_IPC
	/* ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t		 ipc_addr_offset[ODP_BUFFER_MAX_SEG];
#endif
};

/** @internal Compile time assert that the
 * allocator field can handle any allocator id*/
ODP_STATIC_ASSERT(INT16_MAX >= ODP_THREAD_COUNT_MAX,
		  "ODP_BUFFER_HDR_T__ALLOCATOR__SIZE_ERROR");

typedef struct odp_buffer_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_buffer_hdr_t))];
} odp_buffer_hdr_stride;

typedef struct odp_buf_blk_t {
	struct odp_buf_blk_t *next;
	struct odp_buf_blk_t *prev;
} odp_buf_blk_t;

/* Raw buffer header */
typedef struct {
	odp_buffer_hdr_t buf_hdr;    /* common buffer header */
} odp_raw_buffer_hdr_t;

/* Free buffer marker */
#define ODP_FREEBUF -1

/* Forward declarations */
odp_buffer_t buffer_alloc(odp_pool_t pool, size_t size);
int buffer_alloc_multi(odp_pool_t pool_hdl, size_t size,
		       odp_buffer_t buf[], int num);
void buffer_free(uint32_t pool_id, const odp_buffer_t buf);
void buffer_free_multi(uint32_t pool_id,
		       const odp_buffer_t buf[], int num_free);
int seg_alloc_head(odp_buffer_hdr_t *buf_hdr, int segcount);
void seg_free_head(odp_buffer_hdr_t *buf_hdr, int segcount);
int seg_alloc_tail(odp_buffer_hdr_t *buf_hdr, int segcount);
void seg_free_tail(odp_buffer_hdr_t *buf_hdr, int segcount);

#ifdef __cplusplus
}
#endif

#endif
