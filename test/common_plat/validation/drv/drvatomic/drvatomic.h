/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_DRVATOMIC_H_
#define _ODP_TEST_DRVATOMIC_H_

#include <odp_cunit_common.h>

/* test functions: */
void drvatomic_test_atomic_inc_dec(void);
void drvatomic_test_atomic_add_sub(void);
void drvatomic_test_atomic_fetch_inc_dec(void);
void drvatomic_test_atomic_fetch_add_sub(void);
void drvatomic_test_atomic_max_min(void);
void drvatomic_test_atomic_cas_inc_dec(void);
void drvatomic_test_atomic_xchg(void);
void drvatomic_test_atomic_non_relaxed(void);
void drvatomic_test_atomic_op_lock_free(void);

/* test arrays: */
extern odp_testinfo_t drvatomic_suite_atomic[];

/* test registry: */
extern odp_suiteinfo_t drvatomic_suites[];

/* executable init/term functions: */
int drvatomic_init(odp_instance_t *inst);

/* main test program: */
int drvatomic_main(int argc, char *argv[]);

#endif
