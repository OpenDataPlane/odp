/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test application common
 */

#include <string.h>
#include <odp.h>
#include "odp_cunit_common.h"
#include "odph_linux.h"
/* Globals */
static odph_linux_pthread_t thread_tbl[MAX_WORKERS];

/** create test thread */
int odp_cunit_thread_create(void *func_ptr(void *), pthrd_arg *arg)
{
	/* Create and init additional threads */
	odph_linux_pthread_create(thread_tbl, arg->numthrds, 0, func_ptr,
				  (void *)arg);

	return 0;
}

/** exit from test thread */
int odp_cunit_thread_exit(pthrd_arg *arg)
{
	/* Wait for other threads to exit */
	odph_linux_pthread_join(thread_tbl, arg->numthrds);

	return 0;
}
