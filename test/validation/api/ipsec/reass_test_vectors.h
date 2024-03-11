/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Marvell
 */

#ifndef _ODP_REASS_TEST_VECTORS_H_
#define _ODP_REASS_TEST_VECTORS_H_

extern ipsec_test_packet pkt_ipv6_udp_p1;
extern ipsec_test_packet pkt_ipv6_udp_p1_f1;
extern ipsec_test_packet pkt_ipv6_udp_p1_f2;
extern ipsec_test_packet pkt_ipv6_udp_p2;
extern ipsec_test_packet pkt_ipv6_udp_p2_f1;
extern ipsec_test_packet pkt_ipv6_udp_p2_f2;
extern ipsec_test_packet pkt_ipv6_udp_p2_f3;
extern ipsec_test_packet pkt_ipv6_udp_p2_f4;

extern ipsec_test_packet pkt_ipv4_udp_p1;
extern ipsec_test_packet pkt_ipv4_udp_p1_f1;
extern ipsec_test_packet pkt_ipv4_udp_p1_f2;
extern ipsec_test_packet pkt_ipv4_udp_p2;
extern ipsec_test_packet pkt_ipv4_udp_p2_f1;
extern ipsec_test_packet pkt_ipv4_udp_p2_f2;
extern ipsec_test_packet pkt_ipv4_udp_p2_f3;
extern ipsec_test_packet pkt_ipv4_udp_p2_f4;

static inline void
test_vector_payload_populate(ipsec_test_packet *pkt, odp_bool_t first_frag)
{
	uint32_t i = pkt->l4_offset;

	/* For non-fragmented packets and first frag, skip 8 bytes from
	 * l4_offset for UDP header */

	if (first_frag)
		i += 8;

	for (; i < pkt->len; i++)
		pkt->data[i] = 0x58;
}

static inline void
reass_test_vectors_init(void)
{
	test_vector_payload_populate(&pkt_ipv6_udp_p1, true);
	test_vector_payload_populate(&pkt_ipv6_udp_p1_f1, true);
	test_vector_payload_populate(&pkt_ipv6_udp_p1_f2, false);

	test_vector_payload_populate(&pkt_ipv6_udp_p2, true);
	test_vector_payload_populate(&pkt_ipv6_udp_p2_f1, true);
	test_vector_payload_populate(&pkt_ipv6_udp_p2_f2, false);
	test_vector_payload_populate(&pkt_ipv6_udp_p2_f3, false);
	test_vector_payload_populate(&pkt_ipv6_udp_p2_f4, false);

	test_vector_payload_populate(&pkt_ipv4_udp_p1, true);
	test_vector_payload_populate(&pkt_ipv4_udp_p1_f1, true);
	test_vector_payload_populate(&pkt_ipv4_udp_p1_f2, false);

	test_vector_payload_populate(&pkt_ipv4_udp_p2, true);
	test_vector_payload_populate(&pkt_ipv4_udp_p2_f1, true);
	test_vector_payload_populate(&pkt_ipv4_udp_p2_f2, false);
	test_vector_payload_populate(&pkt_ipv4_udp_p2_f3, false);
	test_vector_payload_populate(&pkt_ipv4_udp_p2_f4, false);
}

#endif
