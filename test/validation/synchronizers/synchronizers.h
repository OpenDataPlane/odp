/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_SYNCHRONIZERS_H_
#define _ODP_TEST_SYNCHRONIZERS_H_

#include <odp_cunit_common.h>

/* test functions: */
void synchronizers_test_no_barrier_functional(void);
void synchronizers_test_barrier_functional(void);
void synchronizers_test_no_lock_functional(void);
void synchronizers_test_spinlock_api(void);
void synchronizers_test_spinlock_functional(void);
void synchronizers_test_spinlock_recursive_api(void);
void synchronizers_test_spinlock_recursive_functional(void);
void synchronizers_test_ticketlock_api(void);
void synchronizers_test_ticketlock_functional(void);
void synchronizers_test_rwlock_api(void);
void synchronizers_test_rwlock_functional(void);
void synchronizers_test_rwlock_recursive_api(void);
void synchronizers_test_rwlock_recursive_functional(void);
void synchronizers_test_atomic_inc_dec(void);
void synchronizers_test_atomic_add_sub(void);
void synchronizers_test_atomic_fetch_inc_dec(void);
void synchronizers_test_atomic_fetch_add_sub(void);

/* test arrays: */
extern odp_testinfo_t synchronizers_suite_barrier[];
extern odp_testinfo_t synchronizers_suite_no_locking[];
extern odp_testinfo_t synchronizers_suite_spinlock[];
extern odp_testinfo_t synchronizers_suite_spinlock_recursive[];
extern odp_testinfo_t synchronizers_suite_ticketlock[];
extern odp_testinfo_t synchronizers_suite_rwlock[];
extern odp_testinfo_t synchronizers_suite_rwlock_recursive[];
extern odp_testinfo_t synchronizers_suite_atomic[];

/* test array init/term functions: */
int synchronizers_suite_init(void);

/* test registry: */
extern odp_suiteinfo_t synchronizers_suites[];

/* executable init/term functions: */
int synchronizers_init(void);

/* main test program: */
int synchronizers_main(void);

#endif
