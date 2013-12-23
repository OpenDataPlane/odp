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




struct odp_buffer_hdr_t;


/*
 * Scatter/gather list of buffers
 */
typedef struct odp_buffer_scatter_t {
	/* buffer pointers */
	struct odp_buffer_hdr_t *buf[ODP_BUFS_PER_SCATTER];
	int                      num_bufs;   /* num buffers */
	int                      pos;        /* position on the list */
	size_t                   total_len;  /* Total length */

} odp_buffer_scatter_t;


/*
 * Chunk of buffers (in single pool)
 */
typedef struct odp_buffer_chunk_t {
	uint32_t num_bufs;                      /* num buffers */
	uint32_t buf_index[ODP_BUFS_PER_CHUNK]; /* buffers */

} odp_buffer_chunk_t;


typedef struct odp_buffer_hdr_t {
	struct odp_buffer_hdr_t *next;       /* next buf in a list */
	odp_buffer_bits_t        handle;     /* handle */
	odp_phys_addr_t          phys_addr;  /* physical data start address */
	void                    *addr;       /* virtual data start address */
	uint32_t                 index;	     /* buf index in the pool */
	size_t                   size;       /* max data size */
	size_t                   cur_offset; /* current offset */
	odp_atomic_int_t         ref_count;  /* reference count */
	odp_buffer_scatter_t     scatter;    /* Scatter/gather list */
	int                      type;       /* type of next header */
	odp_buffer_pool_t        pool;       /* buffer pool */

	uint8_t                  payload[];  /* next header or data */
} odp_buffer_hdr_t;


typedef struct odp_buffer_chunk_hdr_t {
	odp_buffer_hdr_t   buf_hdr;
	odp_buffer_chunk_t chunk;
} odp_buffer_chunk_hdr_t;



odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf);

int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf);


#ifdef __cplusplus
}
#endif

#endif







