/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_PARSER_H_
#define _ODP_TEST_PARSER_H_

#include <odp_cunit_common.h>

/* test functions: */
void parser_test_arp(void);
void parser_test_ipv4_icmp(void);
void parser_test_ipv4_tcp(void);
void parser_test_ipv4_udp(void);
void parser_test_vlan_ipv4_udp(void);
void parser_test_vlan_qinq_ipv4_udp(void);
void parser_test_ipv6_icmp(void);
void parser_test_ipv6_tcp(void);
void parser_test_ipv6_udp(void);
void parser_test_vlan_ipv6_udp(void);

/* test array init/term functions: */
int parser_suite_term(void);
int parser_suite_init(void);

/* test arrays: */
extern odp_testinfo_t parser_suite[];

#endif
