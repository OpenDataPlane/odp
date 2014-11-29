/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test application common headers
 */

#ifndef ODP_CUNICT_COMMON_H
#define ODP_CUNICT_COMMON_H

#define MAX_WORKERS 32 /**< Maximum number of work threads */

typedef struct {
	uint32_t foo;
	uint32_t bar;
} test_shared_data_t;

/**
 * Thread argument
 */
typedef struct {
	int testcase; /**< specifies which set of API's to exercise */
	int numthrds; /**< no of pthreads to create */
} pthrd_arg;

/** create thread fro start_routine function */
extern int odp_cunit_thread_create(void *func_ptr(void *), pthrd_arg *arg);
extern int odp_cunit_thread_exit(pthrd_arg *);

#endif /* ODP_CUNICT_COMMON_H */
