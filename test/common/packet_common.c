/* Copyright (c) 2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <packet_common.h>
#include <string.h>

void test_packet_set_md(odp_packet_t pkt)
{
	const int binary_flag = 1;
	const uint32_t offset = 1;
	uint8_t *uarea = odp_packet_user_area(pkt);
	uint32_t uarea_size = odp_packet_user_area_size(pkt);

	for (uint32_t n = 0; n < uarea_size; n++)
		uarea[n] = n;

	/*
	 * Some of these flags cannot be set simultaneously, but we do not
	 * care here if some flags get cleared.
	 */
	odp_packet_has_l2_set(pkt, binary_flag);
	odp_packet_has_l3_set(pkt, binary_flag);
	odp_packet_has_l4_set(pkt, binary_flag);
	odp_packet_has_eth_set(pkt, binary_flag);
	odp_packet_has_eth_bcast_set(pkt, binary_flag);
	odp_packet_has_eth_mcast_set(pkt, !binary_flag);
	odp_packet_has_jumbo_set(pkt, binary_flag);
	odp_packet_has_vlan_set(pkt, binary_flag);
	odp_packet_has_vlan_qinq_set(pkt, binary_flag);
	odp_packet_has_arp_set(pkt, binary_flag);
	odp_packet_has_ipv4_set(pkt, binary_flag);
	odp_packet_has_ipv6_set(pkt, !binary_flag);
	odp_packet_has_ip_bcast_set(pkt, binary_flag);
	odp_packet_has_ip_mcast_set(pkt, binary_flag);
	odp_packet_has_ipfrag_set(pkt, binary_flag);
	odp_packet_has_ipopt_set(pkt, binary_flag);
	odp_packet_has_ipsec_set(pkt, binary_flag);
	odp_packet_has_udp_set(pkt, binary_flag);
	odp_packet_has_tcp_set(pkt, !binary_flag);
	odp_packet_has_sctp_set(pkt, binary_flag);
	odp_packet_has_icmp_set(pkt, binary_flag);

	odp_packet_user_ptr_set(pkt, &pkt);
	odp_packet_user_flag_set(pkt, binary_flag);
	(void)odp_packet_l2_offset_set(pkt, offset);
	(void)odp_packet_l3_offset_set(pkt, offset);
	(void)odp_packet_l4_offset_set(pkt, offset);
	odp_packet_flow_hash_set(pkt, 0x12345678);
	odp_packet_ts_set(pkt, odp_time_local_from_ns(ODP_TIME_SEC_IN_NS));
	odp_packet_color_set(pkt, ODP_PACKET_YELLOW);
	odp_packet_drop_eligible_set(pkt, binary_flag);
	odp_packet_shaper_len_adjust_set(pkt, -42);
	(void)odp_packet_payload_offset_set(pkt, offset);
}

void test_packet_get_md(odp_packet_t pkt, test_packet_md_t *md)
{
	uint8_t *uarea = odp_packet_user_area(pkt);
	uint32_t uarea_size = odp_packet_user_area_size(pkt);

	memset(md, 0, sizeof(*md));

	if (uarea)
		md->user_area_chksum = odp_chksum_ones_comp16(uarea, uarea_size);

	md->has_error		= !!odp_packet_has_error(pkt);
	md->has_l2_error	= !!odp_packet_has_l2_error(pkt);
	md->has_l3_error	= !!odp_packet_has_l3_error(pkt);
	md->has_l4_error	= !!odp_packet_has_l4_error(pkt);
	md->has_l2		= !!odp_packet_has_l2(pkt);
	md->has_l3		= !!odp_packet_has_l3(pkt);
	md->has_l4		= !!odp_packet_has_l4(pkt);
	md->has_eth		= !!odp_packet_has_eth(pkt);
	md->has_eth_bcast	= !!odp_packet_has_eth_bcast(pkt);
	md->has_eth_mcast	= !!odp_packet_has_eth_mcast(pkt);
	md->has_jumbo		= !!odp_packet_has_jumbo(pkt);
	md->has_vlan		= !!odp_packet_has_vlan(pkt);
	md->has_vlan_qinq	= !!odp_packet_has_vlan_qinq(pkt);
	md->has_arp		= !!odp_packet_has_arp(pkt);
	md->has_ipv4		= !!odp_packet_has_ipv4(pkt);
	md->has_ipv6		= !!odp_packet_has_ipv6(pkt);
	md->has_ip_bcast	= !!odp_packet_has_ip_bcast(pkt);
	md->has_ip_mcast	= !!odp_packet_has_ip_mcast(pkt);
	md->has_ipfrag		= !!odp_packet_has_ipfrag(pkt);
	md->has_ipopt		= !!odp_packet_has_ipopt(pkt);
	md->has_ipsec		= !!odp_packet_has_ipsec(pkt);
	md->has_udp		= !!odp_packet_has_udp(pkt);
	md->has_tcp		= !!odp_packet_has_tcp(pkt);
	md->has_sctp		= !!odp_packet_has_sctp(pkt);
	md->has_icmp		= !!odp_packet_has_icmp(pkt);
	md->has_flow_hash	= !!odp_packet_has_flow_hash(pkt);
	md->has_ts		= !!odp_packet_has_ts(pkt);

	md->len = odp_packet_len(pkt);
	md->packet_pool = odp_packet_pool(pkt);
	md->packet_input = odp_packet_input(pkt);
	md->user_ptr = odp_packet_user_ptr(pkt);
	md->user_flag = odp_packet_user_flag(pkt);
	md->l2_offset = odp_packet_l2_offset(pkt);
	md->l3_offset = odp_packet_l3_offset(pkt);
	md->l4_offset = odp_packet_l4_offset(pkt);
	md->l2_type = odp_packet_l2_type(pkt);
	md->l3_type = odp_packet_l3_type(pkt);
	md->l4_type = odp_packet_l4_type(pkt);
	md->l3_chksum_status = odp_packet_l3_chksum_status(pkt);
	md->l4_chksum_status = odp_packet_l4_chksum_status(pkt);
	md->flow_hash = md->has_flow_hash ? odp_packet_flow_hash(pkt) : 0;
	md->ts = md->has_ts ? odp_packet_ts(pkt) : odp_time_global_from_ns(0);
	md->color = odp_packet_color(pkt);
	md->drop_eligible = !!odp_packet_drop_eligible(pkt);
	md->shaper_len_adjust = odp_packet_shaper_len_adjust(pkt);
	md->cls_mark = odp_packet_cls_mark(pkt);
	md->has_lso_request = !!odp_packet_has_lso_request(pkt);
	md->payload_offset = odp_packet_payload_offset(pkt);
	md->aging_tmo = odp_packet_aging_tmo(pkt);
	md->has_tx_compl_request = !!odp_packet_has_tx_compl_request(pkt);
	md->proto_stats = odp_packet_proto_stats(pkt);
}

int test_packet_is_md_equal(const test_packet_md_t *md_1,
			    const test_packet_md_t *md_2)
{
	/*
	 * With certain assumptions this should typically work. If it does
	 * not, we would get false negatives which we should spot as test
	 * failures.
	 */

	return (!memcmp(md_1, md_2, sizeof(*md_1)));
}
