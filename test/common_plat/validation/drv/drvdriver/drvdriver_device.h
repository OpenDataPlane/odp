/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_DRVDRIVER_DEVICE_H_
#define _ODP_TEST_DRVDRIVER_DEVICE_H_

#include <odp_cunit_common.h>

/* test functions: */
void drvdriver_test_device_register(void);

/* test arrays: */
extern odp_testinfo_t drvdriver_suite_device[];

/* test registry: */
extern odp_suiteinfo_t drvdriver_suites_device[];

/* main test program: */
int drvdriver_device_main(int argc, char *argv[]);

#endif
