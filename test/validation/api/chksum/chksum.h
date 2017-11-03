/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_CHKSUM_H_
#define _ODP_TEST_CHKSUM_H_

#include <odp_cunit_common.h>

/* test functions: */
void chksum_ones_complement_ip(void);
void chksum_ones_complement_udp(void);
void chksum_ones_complement_udp_long(void);

/* test arrays: */
extern odp_testinfo_t chksum_suite[];

/* test registry: */
extern odp_suiteinfo_t chksum_suites[];

/* main test program: */
int chksum_main(int argc, char *argv[]);

#endif
