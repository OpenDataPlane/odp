/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP configuration
 */

#ifndef ODP_CONFIG_H_
#define ODP_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Maximum number of threads
 */
#define ODP_CONFIG_MAX_THREADS  128

/**
 * Maximum number of buffer pools
 */
#define ODP_CONFIG_BUFFER_POOLS 16

/**
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES       1024

/**
 * Number of scheduling priorities
 */
#define ODP_CONFIG_SCHED_PRIOS  8

/**
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

#ifdef __cplusplus
}
#endif

#endif
