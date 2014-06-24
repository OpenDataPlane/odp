/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP timer timeout descriptor - implementation internal
 */

#ifndef ODP_TIMER_INTERNAL_H_
#define ODP_TIMER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_queue.h>
#include <odp_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>
#include <odp_timer.h>

struct timeout_t;

typedef struct timeout_t {
	struct timeout_t *next;
	int               timer_id;
	int               tick;
	uint64_t          tmo_tick;
	odp_queue_t       queue;
	odp_buffer_t      buf;
	odp_buffer_t      tmo_buf;
} timeout_t;


struct odp_timeout_hdr_t;

/**
 * Timeout notification header
 */
typedef struct odp_timeout_hdr_t {
	odp_buffer_hdr_t buf_hdr;

	timeout_t meta;

	uint8_t payload[];
} odp_timeout_hdr_t;



ODP_ASSERT(sizeof(odp_timeout_hdr_t) ==
	   ODP_OFFSETOF(odp_timeout_hdr_t, payload),
	   ODP_TIMEOUT_HDR_T__SIZE_ERR);

ODP_ASSERT(sizeof(odp_timeout_hdr_t) % sizeof(uint64_t) == 0,
	   ODP_TIMEOUT_HDR_T__SIZE_ERR2);


/**
 * Return timeout header
 */
static inline odp_timeout_hdr_t *odp_timeout_hdr(odp_timeout_t tmo)
{
	return (odp_timeout_hdr_t *)odp_buf_to_hdr((odp_buffer_t)tmo);
}



#ifdef __cplusplus
}
#endif

#endif
