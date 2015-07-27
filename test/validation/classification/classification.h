/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_CLASSIFICATION_H_
#define _ODP_TEST_CLASSIFICATION_H_

#include <CUnit/Basic.h>

/* test functions: */
void classification_test_create_cos(void);
void classification_test_destroy_cos(void);
void classification_test_create_pmr_match(void);
void classification_test_destroy_pmr(void);
void classification_test_cos_set_queue(void);
void classification_test_cos_set_drop(void);
void classification_test_pmr_match_set_create(void);
void classification_test_pmr_match_set_destroy(void);

void classification_test_pktio_set_skip(void);
void classification_test_pktio_set_headroom(void);
void classification_test_pmr_terms_avail(void);
void classification_test_pmr_terms_cap(void);
void classification_test_pktio_configure(void);
void classification_test_pktio_test(void);

/* test arrays: */
extern CU_TestInfo classification_suite_basic[];
extern CU_TestInfo classification_suite[];

/* test array init/term functions: */
int classification_suite_init(void);
int classification_suite_term(void);

/* test registry: */
extern CU_SuiteInfo classification_suites[];

/* main test program: */
int classification_main(void);

#endif
