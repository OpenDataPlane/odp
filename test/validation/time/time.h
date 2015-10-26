/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_TIME_H_
#define _ODP_TEST_TIME_H_

#include <odp_cunit_common.h>

/* test functions: */
void time_test_odp_cycles_diff(void);
void time_test_odp_cycles_negative_diff(void);
void time_test_odp_time_conversion(void);

/* test arrays: */
extern odp_testinfo_t time_suite_time[];

/* test registry: */
extern odp_suiteinfo_t time_suites[];

/* main test program: */
int time_main(void);

#endif
