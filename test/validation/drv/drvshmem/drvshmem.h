/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_DRVSHMEM_H_
#define _ODP_TEST_DRVSHMEM_H_

#include <odp_cunit_common.h>

/* test functions: */
void drvshmem_test_basic(void);
void drvshmem_test_reserve_after_fork(void);
void drvshmem_test_singleva_after_fork(void);
void drvshmem_test_stress(void);
void drvshmem_test_buddy_basic(void);
void drvshmem_test_slab_basic(void);
void drvshmem_test_buddy_stress(void);

/* test arrays: */
extern odp_testinfo_t drvshmem_suite[];

/* test registry: */
extern odp_suiteinfo_t drvshmem_suites[];

/* main test program: */
int drvshmem_main(int argc, char *argv[]);

#endif
