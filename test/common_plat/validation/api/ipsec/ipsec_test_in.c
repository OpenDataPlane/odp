/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipsec.h"

#include "test_vectors.h"

static
void test_in_ah_sha256(void)
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
			    true, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_ah_sha256_tun(void)
{
	odp_ipsec_tunnel_param_t tunnel = {};
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    true, true, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_tun_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_ah_sha256_tun_notun(void)
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
			    true, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_tun_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0_ipip },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_esp_null_sha256(void)
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
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_null_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_esp_aes_cbc_null(void)
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
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_aes_cbc_null_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_esp_aes_cbc_sha256(void)
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
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_aes_cbc_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_lookup_ah_sha256(void)
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
			    true, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_lookup_esp_null_sha256(void)
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
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_null_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_esp_null_sha256_tun(void)
{
	odp_ipsec_tunnel_param_t tunnel = {};
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    true, false, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_tun_null_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_icmp_0 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_ah_esp_pkt(void)
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
			    true, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_null_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.error.proto = 1,
			  .pkt_out =  NULL },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_esp_ah_pkt(void)
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
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_sha256_1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.error.proto = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_ah_sha256_bad1(void)
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
			    true, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_sha256_1_bad1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.error.auth = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_ah_sha256_bad2(void)
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
			    true, true, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_ah_sha256_1_bad2,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.error.auth = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_esp_null_sha256_bad1(void)
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
			    true, false, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_icmp_0_esp_null_sha256_1_bad1,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.error.auth = 1,
			  .pkt_out = NULL },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_rfc3602_5_esp(void)
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
			    true, false, 0x4321, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_rfc3602,
			    ODP_AUTH_ALG_NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_rfc3602_5_esp,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_rfc3602_5 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_rfc3602_6_esp(void)
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
			    true, false, 0x4321, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_rfc3602,
			    ODP_AUTH_ALG_NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_rfc3602_6_esp,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_rfc3602_6 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_rfc3602_7_esp(void)
{
	odp_ipsec_tunnel_param_t tunnel = {};
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    true, false, 0x8765, &tunnel,
			    ODP_CIPHER_ALG_AES_CBC, &key_rfc3602_2,
			    ODP_AUTH_ALG_NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_rfc3602_7_esp,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_rfc3602_7 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
void test_in_rfc3602_8_esp(void)
{
	odp_ipsec_tunnel_param_t tunnel = {};
	odp_ipsec_config_t ipsec_config;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.pref_mode;
	ipsec_config.outbound_mode = suite_context.pref_mode;
	ipsec_config.inbound.default_queue = suite_context.queue;

	CU_ASSERT_EQUAL_FATAL(ODP_IPSEC_OK, odp_ipsec_config(&ipsec_config));

	ipsec_sa_param_fill(&param,
			    true, false, 0x8765, &tunnel,
			    ODP_CIPHER_ALG_AES_CBC, &key_rfc3602_2,
			    ODP_AUTH_ALG_NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_NOT_EQUAL_FATAL(ODP_IPSEC_SA_INVALID, sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_rfc3602_8_esp,
		.out_pkt = 1,
		.out = {
			{ .status.all_flag = 0,
			  .status.all_error = 0,
			  .pkt_out = &pkt_rfc3602_8 },
		},
	};

	ipsec_check_in_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static
int ipsec_check_in_ah_sha256(void)
{
	return ipsec_check_ah(true,
			      ODP_AUTH_ALG_SHA256_HMAC);
}

static
int ipsec_check_in_esp_null_sha256(void)
{
	return  ipsec_check_esp(true,
				ODP_CIPHER_ALG_NULL,
				ODP_AUTH_ALG_SHA256_HMAC);
}

static
int ipsec_check_in_esp_aes_cbc_null(void)
{
	return  ipsec_check_esp(true,
				ODP_CIPHER_ALG_AES_CBC,
				ODP_AUTH_ALG_NULL);
}

static
int ipsec_check_in_esp_aes_cbc_sha256(void)
{
	return  ipsec_check_esp(true,
				ODP_CIPHER_ALG_AES_CBC,
				ODP_AUTH_ALG_SHA256_HMAC);
}

odp_testinfo_t ipsec_in_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(test_in_rfc3602_5_esp,
				  ipsec_check_in_esp_aes_cbc_null),
	ODP_TEST_INFO_CONDITIONAL(test_in_rfc3602_6_esp,
				  ipsec_check_in_esp_aes_cbc_null),
	ODP_TEST_INFO_CONDITIONAL(test_in_rfc3602_7_esp,
				  ipsec_check_in_esp_aes_cbc_null),
	ODP_TEST_INFO_CONDITIONAL(test_in_rfc3602_8_esp,
				  ipsec_check_in_esp_aes_cbc_null),
	ODP_TEST_INFO_CONDITIONAL(test_in_ah_sha256,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_ah_sha256_tun,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_ah_sha256_tun_notun,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_esp_null_sha256,
				  ipsec_check_in_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_esp_aes_cbc_null,
				  ipsec_check_in_esp_aes_cbc_null),
	ODP_TEST_INFO_CONDITIONAL(test_in_esp_aes_cbc_sha256,
				  ipsec_check_in_esp_aes_cbc_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_lookup_ah_sha256,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_lookup_esp_null_sha256,
				  ipsec_check_in_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_esp_null_sha256_tun,
				  ipsec_check_in_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_ah_esp_pkt,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_esp_ah_pkt,
				  ipsec_check_in_esp_null_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_ah_sha256_bad1,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_ah_sha256_bad2,
				  ipsec_check_in_ah_sha256),
	ODP_TEST_INFO_CONDITIONAL(test_in_esp_null_sha256_bad1,
				  ipsec_check_in_esp_null_sha256),
	ODP_TEST_INFO_NULL,
};
