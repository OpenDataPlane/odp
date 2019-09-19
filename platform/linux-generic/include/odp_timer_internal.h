/* Copyright (c) 2014-2018, Linaro Limited
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

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/timer.h>
#include <odp_global_data.h>

/**
 * Internal Timeout header
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/* Requested expiration time */
	uint64_t expiration;
	/* User ptr inherited from parent timer */
	void *user_ptr;
	/* Parent timer */
	odp_timer_t timer;
} odp_timeout_hdr_t;

/* A larger decrement value should be used after receiving events compared to
 * an 'empty' call. */
void _timer_run_inline(int dec);

/* Static inline wrapper to minimize modification of schedulers. */
static inline void timer_run(int dec)
{
	if (odp_global_rw->inline_timers)
		_timer_run_inline(dec);
}

#endif
