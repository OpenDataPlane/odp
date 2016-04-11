/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_LINUX_TEST_SHMEM_H_
#define _ODP_LINUX_TEST_SHMEM_H_

#include <odp_cunit_common.h>

/* test functions: */
void shmem_test_odp_shm_proc(void);

/* test arrays: */
extern odp_testinfo_t shmem_linux_suite[];

/* test registry: */
extern odp_suiteinfo_t shmem_linux_suites[];

#endif
