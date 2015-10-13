/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _ODP_TEST_SYSTEM_H_
#define _ODP_TEST_SYSTEM_H_

#include <CUnit/Basic.h>

/* test functions: */
void system_test_odp_version_numbers(void);
void system_test_odp_cpu_count(void);
void system_test_odp_sys_cache_line_size(void);
void system_test_odp_cpu_model_str(void);
void system_test_odp_cpu_model_str_id(void);
void system_test_odp_sys_page_size(void);
void system_test_odp_sys_huge_page_size(void);
void system_test_odp_cpu_hz(void);
void system_test_odp_cpu_hz_id(void);
void system_test_odp_cpu_hz_max(void);
void system_test_odp_cpu_hz_max_id(void);

/* test arrays: */
extern CU_TestInfo system_suite[];

/* test registry: */
extern CU_SuiteInfo system_suites[];

/* main test program: */
int system_main(void);

#endif
