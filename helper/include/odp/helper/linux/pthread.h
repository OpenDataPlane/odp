/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Linux helper for pthreads
 *
 * This file is not part of ODP APIs, but can be optionally used to ease common
 * setups in a Linux system. User is free to implement the same setups in
 * other ways (not via this file).
 */

#ifndef ODPH_LINUX_PTHREAD_H_
#define ODPH_LINUX_PTHREAD_H_

#include <odp/helper/threads.h>
#include <odp_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup odph_thread
 * @{
 */

/**
 * Creates and launches pthreads
 *
 * Creates, pins and launches threads to separate CPU's based on the cpumask.
 *
 * @param[out] pthread_tbl Table of pthread state information records. Table
 *                         must have at least as many entries as there are
 *                         CPUs in the CPU mask.
 * @param      mask        CPU mask
 * @param      thr_params  Linux helper thread parameters
 *
 * @return Number of threads created
 */
int odph_linux_pthread_create(odph_linux_pthread_t *pthread_tbl,
			      const odp_cpumask_t *mask,
			      const odph_linux_thr_params_t *thr_params);

/**
 * Waits pthreads to exit
 *
 * Returns when all threads have been exit.
 *
 * @param thread_tbl    Thread table
 * @param num           Number of threads to create
 *
 */
void odph_linux_pthread_join(odph_linux_pthread_t *thread_tbl, int num);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
