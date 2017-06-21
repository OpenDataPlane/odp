/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipsec.h"

#include "test_vectors.h"

static
void test_out_ah_sha256(void)
{
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

#define IPv4ADDR(a, b, c, d) odp_cpu_to_be_32((a << 24) | \
					      (b << 16) | \
					      (c << 8) | \
					      (d << 0))

static
void test_out_ah_sha256_tun(void)
{
	uint32_t src = IPv4ADDR(10, 0, 111, 2);
	uint32_t dst = IPv4ADDR(10, 0, 222, 2);
	odp_ipsec_tunnel_param_t tunnel = {
		.type = ODP_IPSEC_TUNNEL_IPV4,
		.ipv4.src_addr = &src,
		.ipv4.dst_addr = &dst,
		.ipv4.ttl = 64,
	};
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0_ah_tun_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_out_esp_null_sha256_out(void)
{
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0_esp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_out_esp_null_sha256_tun_out(void)
{
	uint32_t src = IPv4ADDR(10, 0, 111, 2);
	uint32_t dst = IPv4ADDR(10, 0, 222, 2);
	odp_ipsec_tunnel_param_t tunnel = {
		.type = ODP_IPSEC_TUNNEL_IPV4,
		.ipv4.src_addr = &src,
		.ipv4.dst_addr = &dst,
		.ipv4.ttl = 64,
	};
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0_esp_tun_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_out_esp_null_sha256(void)
{
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static
void test_out_esp_aes_cbc_null(void)
{
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static
void test_out_esp_aes_cbc_sha256(void)
{
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    false, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_sa_param_fill(&param,
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa2);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_out_in_one(&test, sa, sa2);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static
int ipsec_check_out_ah_sha256(void)
{
	return ipsec_check_ah(false,
			      ODP_AUTH_ALG_SHA256_HMAC);
}

static
int ipsec_check_out_esp_null_sha256(void)
{
	return  ipsec_check_esp(false,
				ODP_CIPHER_ALG_NULL,
				ODP_AUTH_ALG_SHA256_HMAC);
}

static
int ipsec_check_both_esp_aes_cbc_null(void)
{
	return  ipsec_check_esp(false,
				ODP_CIPHER_ALG_AES_CBC,
				ODP_AUTH_ALG_NULL) &&
		ipsec_check_esp(true,
				ODP_CIPHER_ALG_AES_CBC,
				ODP_AUTH_ALG_NULL);
}

static
int ipsec_check_both_esp_aes_cbc_sha256(void)
{
	return  ipsec_check_esp(false,
				ODP_CIPHER_ALG_AES_CBC,
				ODP_AUTH_ALG_SHA256_HMAC) &&
		ipsec_check_esp(true,
				ODP_CIPHER_ALG_AES_CBC,
				ODP_AUTH_ALG_SHA256_HMAC);
}

odp_testinfo_t ipsec_out_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(test_out_ah_sha256,
				  ipsec_check_out_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_ah_sha256_tun,
				  ipsec_check_out_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_null_sha256_out,
				  ipsec_check_out_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_null_sha256_tun_out,
				  ipsec_check_out_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_null_sha256,
				  ipsec_check_out_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_aes_cbc_null,
				  ipsec_check_both_esp_aes_cbc_null),
	ODP_TEST_INFO_CONDITIONAL(test_out_esp_aes_cbc_sha256,
				  ipsec_check_both_esp_aes_cbc_sha256),
	ODP_TEST_INFO_NULL,
};
