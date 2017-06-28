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

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/timer.h>

/* Minimum number of nanoseconds between checking timer pools. */
#define CONFIG_TIMER_RUN_RATELIMIT_NS 100

/* Minimum number of scheduling rounds between checking timer pools. */
#define CONFIG_TIMER_RUN_RATELIMIT_ROUNDS 1

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

/*
 * Whether to run timer pool processing 'inline' (on worker cores) or in
 * background threads (thread-per-timerpool).
 *
 * If the application will use both scheduler and timer this flag is set
 * to true, otherwise false. This application conveys this information via
 * the 'not_used' bits in odp_init_t which are passed to odp_global_init().
 */
extern odp_bool_t inline_timers;

unsigned _timer_run(void);

/* Static inline wrapper to minimize modification of schedulers. */
static inline unsigned timer_run(void)
{
	return inline_timers ? _timer_run() : 0;
}

#endif
