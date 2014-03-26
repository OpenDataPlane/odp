/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Linux helper API
 *
 * This file is an optional helper to odp.h APIs. Application can manage
 * pthreads also by other means.
 */

#ifndef ODP_LINUX_H_
#define ODP_LINUX_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <pthread.h>

/** Pthread status data */
typedef struct {
	pthread_t      thread; /**< @private Pthread */
	pthread_attr_t attr;   /**< @private Pthread attributes */

} odp_linux_pthread_t;


/**
 * Creates and launches pthreads
 *
 * Creates, pins and launches num threads to separate cores starting from
 * first_core.
 *
 * @param thread_tbl    Thread table
 * @param num           Number of threads to create
 * @param first_core    First physical core
 * @param start_routine Thread start function
 * @param arg           Thread argument
 */
void odp_linux_pthread_create(odp_linux_pthread_t *thread_tbl,
			      int num, int first_core,
			      void *(*start_routine) (void *), void *arg);


/**
 * Waits pthreads to exit
 *
 * Returns when all threads have been exit.
 *
 * @param thread_tbl    Thread table
 * @param num           Number of threads to create
 *
 */
void odp_linux_pthread_join(odp_linux_pthread_t *thread_tbl, int num);


#ifdef __cplusplus
}
#endif

#endif







