/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_DRVDRIVER_ENUMR_CLASS_H_
#define _ODP_TEST_DRVDRIVER_ENUMR_CLASS_H_

#include <odp_cunit_common.h>

/* test functions: */
void drvdriver_test_enumr_class_register(void);

/* test arrays: */
extern odp_testinfo_t drvdriver_suite_enumr_class[];

/* test registry: */
extern odp_suiteinfo_t drvdriver_suites_enumr_class[];

/* main test program: */
int drvdriver_enumr_class_main(int argc, char *argv[]);

#endif
