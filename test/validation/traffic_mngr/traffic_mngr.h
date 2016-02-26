/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _ODP_TEST_TRAFFIC_MNGR_H_
#define _ODP_TEST_TRAFFIC_MNGR_H_

#include <odp_cunit_common.h>

/* test functions: */
void traffic_mngr_test_create_tm(void);
void traffic_mngr_test_shaper_profile(void);
void traffic_mngr_test_sched_profile(void);
void traffic_mngr_test_threshold_profile(void);
void traffic_mngr_test_wred_profile(void);
void traffic_mngr_test_shaper(void);
void traffic_mngr_test_scheduler(void);
void traffic_mngr_test_thresholds(void);
void traffic_mngr_test_byte_wred(void);
void traffic_mngr_test_pkt_wred(void);
void traffic_mngr_test_query(void);

/* test arrays: */
extern odp_testinfo_t traffic_mngr_suite[];

/* test suite init/term functions: */
int traffic_mngr_suite_init(void);
int traffic_mngr_suite_term(void);

/* test registry: */
extern odp_suiteinfo_t traffic_mngr_suites[];

/* main test program: */
int traffic_mngr_main(void);

#endif
