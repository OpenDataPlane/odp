/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
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
#include <odp_debug_internal.h>
#include <odp_align.h>

typedef struct odp_bufhdr {
	int type;
} odp_buffer_hdr_t;

ODP_STATIC_ASSERT(sizeof(Cppi_HostDesc) <= ODP_CACHE_LINE_SIZE,
		  "ODP_BUFFER_HDR_T__SIZE_ERROR");

static inline struct odp_bufhdr *odp_buffer_hdr(odp_buffer_t buf)
{
	return (struct odp_bufhdr *)(_odp_buf_to_cppi_desc(buf)->origBuffPtr);
}

/* Compatibility function for timer code reused from linux-generic */
static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)odp_buffer_hdr(buf);
}

extern odp_buffer_pool_t odp_buf_to_pool(odp_buffer_t buf);


int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf);

void odp_buffer_copy_scatter(odp_buffer_t buf_dst, odp_buffer_t buf_src);


#ifdef __cplusplus
}
#endif

#endif
