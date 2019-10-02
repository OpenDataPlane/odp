/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipsec.h"

#include "test_vectors.h"

static void test_out_ipv4_ah_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

#define IPV4ADDR(a, b, c, d) odp_cpu_to_be_32((a << 24) | \
					      (b << 16) | \
					      (c << 8) | \
					      (d << 0))

static void test_out_ipv4_ah_sha256_tun_ipv4(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	ipsec_sa_param_fill(&param,
			    false, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_ah_tun_ipv4_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_ah_sha256_tun_ipv6(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint8_t src[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x43, 0xff, 0xfe, 0x4a, 0xd7, 0x0a,
	};
	uint8_t dst[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	};

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
	tunnel.ipv6.src_addr = src;
	tunnel.ipv6.dst_addr = dst;
	tunnel.ipv6.hlimit = 64;

	ipsec_sa_param_fill(&param,
			    false, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_ah_tun_ipv6_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_esp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_sha256_tun_ipv4(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out =
				  &pkt_ipv4_icmp_0_esp_tun_ipv4_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_sha256_tun_ipv6(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint8_t src[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x43, 0xff, 0xfe, 0x4a, 0xd7, 0x0a,
	};
	uint8_t dst[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	};

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
	tunnel.ipv6.src_addr = src;
	tunnel.ipv6.dst_addr = dst;
	tunnel.ipv6.hlimit = 64;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out =
				  &pkt_ipv4_icmp_0_esp_tun_ipv6_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_aes_cbc_null(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    NULL, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_out = &pkt_ipv4_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_udp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.opt.udp_encap = 1;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_esp_udp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_aes_cbc_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_out = &pkt_ipv4_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_aes_ctr_null(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CTR, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    &key_mcgrew_gcm_salt_3, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CTR, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    &key_mcgrew_gcm_salt_3, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_out = &pkt_ipv4_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_aes_gcm128(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_GCM, &key_a5_128,
			    ODP_AUTH_ALG_AES_GCM, &key_a5_128,
			    &key_mcgrew_gcm_salt_2, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_GCM, &key_a5_128,
			    ODP_AUTH_ALG_AES_GCM, &key_a5_128,
			    &key_mcgrew_gcm_salt_2, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_out = &pkt_ipv4_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_ah_aes_gmac_128(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_AES_GMAC, &key_a5_128,
			    NULL, &key_mcgrew_gcm_salt_2);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_ah_aes_gmac_128_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_aes_gmac_128(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_AES_GMAC, &key_a5_128,
			    NULL, &key_mcgrew_gcm_salt_2);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_esp_null_aes_gmac_128_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_chacha20_poly1305(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_CHACHA20_POLY1305, &key_rfc7634,
			    ODP_AUTH_ALG_CHACHA20_POLY1305, NULL,
			    &key_rfc7634_salt, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_CHACHA20_POLY1305, &key_rfc7634,
			    ODP_AUTH_ALG_CHACHA20_POLY1305, NULL,
			    &key_rfc7634_salt, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_out = &pkt_ipv4_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_ah_sha256_frag_check(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.mtu = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_test_part test2 = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_opt = 1,
		.opt = { .flag.frag_mode = 1,
			 .frag_mode = ODP_IPSEC_FRAG_DISABLED, },
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_check_out_one(&test2, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_ah_sha256_frag_check_2(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.mtu = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_test_part test2 = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	odp_ipsec_sa_mtu_update(sa, 256);

	ipsec_check_out_one(&test2, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_sha256_frag_check(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.mtu = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_test_part test2 = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_opt = 1,
		.opt = { .flag.frag_mode = 1,
			 .frag_mode = ODP_IPSEC_FRAG_DISABLED, },
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_esp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_check_out_one(&test2, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_sha256_frag_check_2(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.mtu = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_test_part test2 = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_icmp_0_esp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	odp_ipsec_sa_mtu_update(sa, 256);

	ipsec_check_out_one(&test2, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_ah_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv6_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_ah_sha256_tun_ipv4(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	ipsec_sa_param_fill(&param,
			    false, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv6_icmp_0_ah_tun_ipv4_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_ah_sha256_tun_ipv6(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint8_t src[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x43, 0xff, 0xfe, 0x4a, 0xd7, 0x0a,
	};
	uint8_t dst[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	};

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
	tunnel.ipv6.src_addr = src;
	tunnel.ipv6.dst_addr = dst;
	tunnel.ipv6.hlimit = 64;

	ipsec_sa_param_fill(&param,
			    false, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv6_icmp_0_ah_tun_ipv6_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_esp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv6_icmp_0_esp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_esp_null_sha256_tun_ipv4(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out =
				  &pkt_ipv6_icmp_0_esp_tun_ipv4_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_esp_null_sha256_tun_ipv6(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	uint8_t src[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x43, 0xff, 0xfe, 0x4a, 0xd7, 0x0a,
	};
	uint8_t dst[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	};

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
	tunnel.ipv6.src_addr = &src;
	tunnel.ipv6.dst_addr = &dst;
	tunnel.ipv6.hlimit = 64;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out =
				  &pkt_ipv6_icmp_0_esp_tun_ipv6_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv6_esp_udp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.opt.udp_encap = 1;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv6_icmp_0_esp_udp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_dummy_esp_null_sha256_tun_ipv4(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	/* This test will not work properly inbound inline mode.
	 * Packet might be dropped and we will not check for that. */
	if (suite_context.inbound_op_mode == ODP_IPSEC_OP_MODE_INLINE)
		return;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_test_nodata,
		.num_opt = 1,
		.opt = { .flag.tfc_dummy = 1,
			 .tfc_pad_len = 16, },
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_NO_NEXT,
			  .pkt_out = NULL },
		},
	};

	ipsec_test_part test_empty = {
		.pkt_in = &pkt_test_emtpy,
		.num_opt = 1,
		.opt = { .flag.tfc_dummy = 1,
			 .tfc_pad_len = 16, },
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_NO_NEXT,
			  .pkt_out = NULL },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);
	ipsec_check_out_in_one(&test_empty, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_dummy_esp_null_sha256_tun_ipv6(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;
	uint8_t src[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x43, 0xff, 0xfe, 0x4a, 0xd7, 0x0a,
	};
	uint8_t dst[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	};

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
	tunnel.ipv6.src_addr = src;
	tunnel.ipv6.dst_addr = dst;
	tunnel.ipv6.hlimit = 64;

	/* This test will not work properly inbound inline mode.
	 * Packet might be dropped and we will not check for that. */
	if (suite_context.inbound_op_mode == ODP_IPSEC_OP_MODE_INLINE)
		return;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_test_nodata,
		.num_opt = 1,
		.opt = { .flag.tfc_dummy = 1,
			 .tfc_pad_len = 16, },
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_NO_NEXT,
			  .pkt_out = NULL },
		},
	};

	ipsec_test_part test_empty = {
		.pkt_in = &pkt_test_emtpy,
		.num_opt = 1,
		.opt = { .flag.tfc_dummy = 1,
			 .tfc_pad_len = 16, },
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_NO_NEXT,
			  .pkt_out = NULL },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);
	ipsec_check_out_in_one(&test_empty, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_udp_esp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_udp,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_ipv4_udp_esp_null_sha256 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void ipsec_test_capability(void)
{
	odp_ipsec_capability_t capa;

	CU_ASSERT(odp_ipsec_capability(&capa) == 0);
}

odp_testinfo_t ipsec_out_suite[] = {
	ODP_TEST_INFO(ipsec_test_capability),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_ah_sha256,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_ah_sha256_tun_ipv4,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_ah_sha256_tun_ipv6,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_null_sha256,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_null_sha256_tun_ipv4,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_null_sha256_tun_ipv6,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_udp_null_sha256,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_aes_cbc_null,
				  ipsec_check_esp_aes_cbc_128_null),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_aes_cbc_sha256,
				  ipsec_check_esp_aes_cbc_128_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_aes_ctr_null,
				  ipsec_check_esp_aes_ctr_128_null),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_aes_gcm128,
				  ipsec_check_esp_aes_gcm_128),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_ah_aes_gmac_128,
				  ipsec_check_ah_aes_gmac_128),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_null_aes_gmac_128,
				  ipsec_check_esp_null_aes_gmac_128),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_chacha20_poly1305,
				  ipsec_check_esp_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_ah_sha256_frag_check,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_ah_sha256_frag_check_2,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_null_sha256_frag_check,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_null_sha256_frag_check_2,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_ah_sha256,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_ah_sha256_tun_ipv4,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_ah_sha256_tun_ipv6,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_esp_null_sha256,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_esp_null_sha256_tun_ipv4,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_esp_null_sha256_tun_ipv6,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv6_esp_udp_null_sha256,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_dummy_esp_null_sha256_tun_ipv4,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_dummy_esp_null_sha256_tun_ipv6,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_udp_esp_null_sha256,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_NULL,
};
