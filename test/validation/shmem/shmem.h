/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_SHMEM_H_
#define _ODP_TEST_SHMEM_H_

#include <CUnit/Basic.h>

/* test functions: */
void shmem_test_odp_shm_sunnyday(void);

/* test arrays: */
extern CU_TestInfo shmem_suite[];

/* test registry: */
extern CU_SuiteInfo shmem_suites[];

/* main test program: */
int shmem_main(void);

#endif
