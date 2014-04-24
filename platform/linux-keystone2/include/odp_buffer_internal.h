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
#include <odp_queue.h>
#include <odp_debug.h>
#include <odp_align.h>

#include <event_machine_macros.h>
#include <event_machine_types.h>
#include <event_machine_group.h>
#include <event_machine_hw_macros.h>
#include <event_machine_hw_types.h>
#include <event_machine_hw_ti_macros.h>
#include <event_machine_hw_ti_types.h>
#include <ti_em_osal_cppi.h>
#include <src/event_machine_hwpform.h>

/* TODO: move these to correct files */

typedef uintptr_t odp_phys_addr_t;

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

typedef struct odp_buffer_hdr_t {
	Cppi_HostDesc   desc;
	void		*buf_vaddr;
	uint32_t	free_queue;
	int type;
	struct odp_buffer_hdr_t *next;       /* next buf in a list */
	odp_buffer_bits_t        handle;     /* handle */
} odp_buffer_hdr_t;


/*
 * Chunk of buffers (in single pool)
 */

ODP_ASSERT(sizeof(odp_buffer_hdr_t) <= ODP_CACHE_LINE_SIZE*2,
	   ODP_BUFFER_HDR_T__SIZE_ERROR);

static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)buf;
}
static inline odp_buffer_t hdr_to_odp_buf(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t)hdr;
}

extern odp_buffer_pool_t odp_buf_to_pool(odp_buffer_t buf);


int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf);

void odp_buffer_copy_scatter(odp_buffer_t buf_dst, odp_buffer_t buf_src);


#ifdef __cplusplus
}
#endif

#endif
