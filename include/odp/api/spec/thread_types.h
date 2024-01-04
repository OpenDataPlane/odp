/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP thread API types
 */

#ifndef ODP_API_SPEC_THREAD_TYPES_H_
#define ODP_API_SPEC_THREAD_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_thread ODP THREAD
 *  @{
 */

/**
 * @def ODP_THREAD_COUNT_MAX
 * Maximum number of threads supported in build time. Use odp_thread_count_max()
 * for maximum number of threads supported in run time, which depends on system
 * configuration and may be lower than this number.
 */

/**
 * Thread type
 */
typedef enum odp_thread_type_e {
	/**
	 * Worker thread
	 *
	 * Worker threads do most part of ODP application packet processing.
	 * These threads provide high packet and data rates, with low and
	 * predictable latency. Typically, worker threads are pinned to isolated
	 * CPUs and packets are processed in a run-to-completion loop with very
	 * low interference from the operating system.
	 */
	ODP_THREAD_WORKER = 0,

	/**
	 * Control thread
	 *
	 * Control threads do not participate the main packet flow through the
	 * system, but e.g. control or monitor the worker threads, or handle
	 * exceptions. These threads may perform general purpose processing,
	 * use system calls, share the CPU with other threads and be interrupt
	 * driven.
	 */
	ODP_THREAD_CONTROL
} odp_thread_type_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
