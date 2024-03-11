/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>

typedef struct test_packet_md_t {
	int has_error;
	int has_l2_error;
	int has_l3_error;
	int has_l4_error;
	int has_l2;
	int has_l3;
	int has_l4;
	int has_eth;
	int has_eth_bcast;
	int has_eth_mcast;
	int has_jumbo;
	int has_vlan;
	int has_vlan_qinq;
	int has_arp;
	int has_ipv4;
	int has_ipv6;
	int has_ip_bcast;
	int has_ip_mcast;
	int has_ipfrag;
	int has_ipopt;
	int has_ipsec;
	int has_udp;
	int has_tcp;
	int has_sctp;
	int has_icmp;
	int has_flow_hash;
	int has_ts;
	uint32_t len;
	odp_pool_t packet_pool;
	odp_pktio_t packet_input;
	void *user_ptr;
	uint16_t user_area_chksum;
	int user_flag;
	uint32_t l2_offset;
	uint32_t l3_offset;
	uint32_t l4_offset;
	odp_proto_l2_type_t l2_type;
	odp_proto_l3_type_t l3_type;
	odp_proto_l4_type_t l4_type;
	odp_packet_chksum_status_t l3_chksum_status;
	odp_packet_chksum_status_t l4_chksum_status;
	uint32_t flow_hash;
	odp_time_t ts;
	odp_packet_color_t color;
	odp_bool_t drop_eligible;
	int8_t shaper_len_adjust;
	uint64_t cls_mark;
	int has_lso_request;
	uint32_t payload_offset;
	uint64_t aging_tmo;
	int has_tx_compl_request;
	odp_proto_stats_t proto_stats;
} test_packet_md_t;

void test_packet_set_md(odp_packet_t pkt);
void test_packet_get_md(odp_packet_t pkt, test_packet_md_t *md);
int test_packet_is_md_equal(const test_packet_md_t *md_1,
			    const test_packet_md_t *md_2);
