/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CLASSIFICATION_TESTSUITES_H_
#define ODP_CLASSIFICATION_TESTSUITES_H_

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp_cunit_common.h>
#include <stdbool.h>

typedef enum cls_packet_l4_info {
	CLS_PKT_L4_TCP,
	CLS_PKT_L4_UDP,
	CLS_PKT_L4_SCTP,
	CLS_PKT_L4_ICMP,
	CLS_PKT_L4_GTP,
	CLS_PKT_L4_IGMP,
} cls_packet_l4_info;

typedef struct cls_packet_info {
	odp_pool_t pool;
	bool	vlan;
	bool	vlan_qinq;
	odp_atomic_u32_t *seq;
	cls_packet_l4_info l4_type;
	odp_bool_t ipv6;
	uint8_t dscp;
	uint32_t len;
} cls_packet_info_t;

typedef union odp_cls_testcase {
	struct  {
		uint32_t default_cos:1;
		uint32_t drop_cos:1;
		uint32_t error_cos:1;
		uint32_t pmr_chain:1;
		uint32_t l2_priority:1;
		uint32_t pmr_cos:1;
		uint32_t pmr_composite_cos:1;
	};
	uint32_t all_bits;
} odp_cls_testcase_u;

extern odp_testinfo_t classification_suite[];
extern odp_testinfo_t classification_suite_basic[];
extern odp_testinfo_t classification_suite_pmr[];
extern odp_testinfo_t classification_suite_pktv[];

int classification_suite_init(void);
int classification_suite_term(void);

int classification_suite_pmr_term(void);
int classification_suite_pmr_init(void);

int classification_suite_pktv_init(void);
int classification_suite_pktv_term(void);

odp_packet_t create_packet(cls_packet_info_t pkt_info);
int cls_pkt_set_seq(odp_packet_t pkt);
uint32_t cls_pkt_get_seq(odp_packet_t pkt);
odp_pktio_t create_pktio(odp_queue_type_t q_type, odp_pool_t pool,
			 odp_bool_t cls_enable);
void configure_default_cos(odp_pktio_t pktio, odp_cos_t *cos,
			   odp_queue_t *queue, odp_pool_t *pool);
int parse_ipv4_string(const char *ipaddress, uint32_t *addr, uint32_t *mask);
void enqueue_pktio_interface(odp_packet_t pkt, odp_pktio_t pktio);
odp_packet_t receive_packet(odp_queue_t *queue, uint64_t ns, odp_bool_t enable_pktv);
odp_pool_t pool_create(const char *poolname);
odp_pool_t pktv_pool_create(const char *poolname);
odp_queue_t queue_create(const char *queuename, bool sched);
void configure_pktio_default_cos(odp_bool_t enable_pktv);
void test_pktio_default_cos(odp_bool_t enable_pktv);
void configure_pktio_drop_cos(odp_bool_t enable_pktv, uint32_t max_cos_stats);
void test_pktio_drop_cos(odp_bool_t enable_pktv);
void configure_pktio_error_cos(odp_bool_t enable_pktv);
void test_pktio_error_cos(odp_bool_t enable_pktv);
void configure_cls_pmr_chain(odp_bool_t enable_pktv);
void test_cls_pmr_chain(odp_bool_t enable_pktv);
void configure_cos_with_l2_priority(odp_bool_t enable_pktv);
void test_cos_with_l2_priority(odp_bool_t enable_pktv);
void configure_pmr_cos(odp_bool_t enable_pktv);
void test_pmr_cos(odp_bool_t enable_pktv);
void configure_pktio_pmr_composite(odp_bool_t enable_pktv);
void test_pktio_pmr_composite_cos(odp_bool_t enable_pktv);
int stop_pktio(odp_pktio_t pktio);
odp_cls_pmr_term_t find_first_supported_l3_pmr(void);
int set_first_supported_pmr_port(odp_packet_t pkt, uint16_t port);

#endif /* ODP_BUFFER_TESTSUITES_H_ */
