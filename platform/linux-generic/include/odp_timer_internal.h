/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP timeout descriptor - implementation internal
 */

#ifndef ODP_TIMER_INTERNAL_H_
#define ODP_TIMER_INTERNAL_H_

#include <odp/align.h>
#include <odp/debug.h>
#include <odp_debug_internal.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/timer.h>

/**
 * Internal Timeout header
 * For compatibility with buffers, we use the buffer_hdr here and nothing else
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;
} odp_timeout_fakehdr_t;

/* The real timeout header is in a separate struct in a separate location */
typedef struct {
	/* Requested expiration time */
	uint64_t expiration;
	/* User ptr inherited from parent timer */
	void *user_ptr;
	/* Handle of buffer we are located in */
	odp_buffer_t buf;
	/* Parent timer */
	odp_timer_t timer;
} odp_timeout_hdr_t;

typedef struct odp_timeout_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_timeout_fakehdr_t))];
} odp_timeout_hdr_stride;


/**
 * Return the timeout header
 */
static inline odp_timeout_hdr_t *odp_timeout_hdr_from_buf(odp_buffer_t buf)
{
	/* The real timeout header is stored in the buffer data */
	ODP_ASSERT(odp_buffer_size(buf) == sizeof(odp_timeout_hdr_t));
	return (odp_timeout_hdr_t *)odp_buffer_addr(buf);
}

#endif
