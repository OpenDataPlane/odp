/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2022 Nokia
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
#include <odp/api/timer.h>

#include <odp_event_internal.h>
#include <odp_global_data.h>
#include <odp_pool_internal.h>

/*
 * Use as the argument to timer_run() to force a scan and to ignore rate
 * limit.
 */
#define TIMER_SCAN_FORCE INT32_MAX

/**
 * Internal Timeout header
 */
typedef struct ODP_ALIGNED_CACHE odp_timeout_hdr_t {
	/* Common event header */
	_odp_event_hdr_t event_hdr;

	/* Requested expiration time */
	uint64_t expiration;

	/* User ptr inherited from parent timer */
	const void *user_ptr;

	/* Parent timer */
	odp_timer_t timer;

} odp_timeout_hdr_t;

ODP_STATIC_ASSERT(sizeof(odp_timeout_hdr_t) <= ODP_CACHE_LINE_SIZE,
		  "TIMEOUT_HDR_SIZE_ERROR");

/* A larger decrement value should be used after receiving events compared to
 * an 'empty' call. */
uint64_t _odp_timer_run_inline(int dec);

/* Static inline wrapper to minimize modification of schedulers. */
static inline uint64_t timer_run(int dec)
{
	if (odp_global_rw->inline_timers)
		return _odp_timer_run_inline(dec);

	return UINT64_MAX;
}

static inline void _odp_timeout_free_sp(odp_timeout_t tmo[], int num)
{
	_odp_event_free_sp((_odp_event_hdr_t **)(uintptr_t)tmo, num);
}

#endif
