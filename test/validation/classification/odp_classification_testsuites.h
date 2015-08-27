/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CLASSIFICATION_TESTSUITES_H_
#define ODP_CLASSIFICATION_TESTSUITES_H_

#include <odp.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

extern CU_TestInfo classification_suite[];
extern CU_TestInfo classification_suite_basic[];

int classification_suite_init(void);
int classification_suite_term(void);

odp_packet_t create_packet(bool vlan);
void configure_pktio_default_cos(void);
void test_pktio_default_cos(void);
void configure_pktio_error_cos(void);
void test_pktio_error_cos(void);
void configure_cls_pmr_chain(void);
void test_cls_pmr_chain(void);
void configure_cos_with_l2_priority(void);
void test_cos_with_l2_priority(void);
void configure_pmr_cos(void);
void test_pmr_cos(void);
void configure_pktio_pmr_match_set_cos(void);
void test_pktio_pmr_match_set_cos(void);


#endif /* ODP_BUFFER_TESTSUITES_H_ */
