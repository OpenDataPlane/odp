/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_SHMEM_H_
#define _ODP_TEST_SHMEM_H_

#include <odp_cunit_common.h>

/* test functions: */
void shmem_test_basic(void);
void shmem_test_reserve_after_fork(void);
void shmem_test_singleva_after_fork(void);
void shmem_test_stress(void);

/* test arrays: */
extern odp_testinfo_t shmem_suite[];

/* test registry: */
extern odp_suiteinfo_t shmem_suites[];

/* main test program: */
int shmem_main(int argc, char *argv[]);

#endif
