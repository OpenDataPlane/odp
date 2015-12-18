/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_TIME_H_
#define _ODP_TEST_TIME_H_

#include <odp_cunit_common.h>

/* test functions: */
void time_test_odp_constants(void);
void time_test_odp_conversion(void);
void time_test_monotony(void);
void time_test_odp_cmp(void);
void time_test_odp_diff(void);
void time_test_odp_sum(void);
void time_test_odp_to_u64(void);

/* test arrays: */
extern odp_testinfo_t time_suite_time[];

/* test registry: */
extern odp_suiteinfo_t time_suites[];

/* main test program: */
int time_main(void);

#endif
