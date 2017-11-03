/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include "ipsec.h"

#include "test_vectors.h"

static void test_out_ah_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

#define IPV4ADDR(a, b, c, d) odp_cpu_to_be_32((a << 24) | \
					      (b << 16) | \
					      (c << 8) | \
					      (d << 0))

static void test_out_ah_sha256_tun(void)
{
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);
	odp_ipsec_tunnel_param_t tunnel = {
		.type = ODP_IPSEC_TUNNEL_IPV4,
		.ipv4.src_addr = &src,
		.ipv4.dst_addr = &dst,
		.ipv4.ttl = 64,
	};
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0_ah_tun_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_esp_null_sha256_out(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0_esp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_esp_null_sha256_tun_out(void)
{
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);
	odp_ipsec_tunnel_param_t tunnel = {
		.type = ODP_IPSEC_TUNNEL_IPV4,
		.ipv4.src_addr = &src,
		.ipv4.dst_addr = &dst,
		.ipv4.ttl = 64,
	};
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0_esp_tun_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_esp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_esp_aes_cbc_null(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_esp_aes_cbc_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_esp_aes_ctr_null(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CTR, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    &key_mcgrew_gcm_salt_3);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CTR, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL,
			    &key_mcgrew_gcm_salt_3);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_esp_aes_gcm128(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_GCM, &key_a5_128,
			    ODP_AUTH_ALG_AES_GCM, &key_a5_128,
			    &key_mcgrew_gcm_salt_2);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_GCM, &key_a5_128,
			    ODP_AUTH_ALG_AES_GCM, &key_a5_128,
			    &key_mcgrew_gcm_salt_2);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void ipsec_test_capability(void)
{
	odp_ipsec_capability_t capa;

	CU_ASSERT(odp_ipsec_capability(&capa) == 0);
}

odp_testinfo_t ipsec_out_suite[] = {
	ODP_TEST_INFO(ipsec_test_capability),
	ODP_TEST_INFO_CONDITIONAL(test_out_ah_sha256,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ah_sha256_tun,
				  ipsec_check_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_null_sha256_out,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_null_sha256_tun_out,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_null_sha256,
				  ipsec_check_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_aes_cbc_null,
				  ipsec_check_esp_aes_cbc_128_null),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_aes_cbc_sha256,
				  ipsec_check_esp_aes_cbc_128_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_aes_ctr_null,
				  ipsec_check_esp_aes_ctr_128_null),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_aes_gcm128,
				  ipsec_check_esp_aes_gcm_128),
	ODP_TEST_INFO_NULL,
};
