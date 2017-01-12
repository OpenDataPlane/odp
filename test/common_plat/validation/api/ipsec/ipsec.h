/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_IPSEC_H_
#define _ODP_TEST_IPSEC_H_

#include <odp_cunit_common.h>

/* test functions: */
void ipsec_test_capability(void);

/* test arrays: */
extern odp_testinfo_t ipsec_suite[];

/* test registry: */
extern odp_suiteinfo_t ipsec_suites[];

/* main test program: */
int ipsec_main(int argc, char *argv[]);

#endif
