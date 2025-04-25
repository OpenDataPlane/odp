/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2020 Marvell
 * Copyright (c) 2020-2022 Nokia
 */

#include <odp/helper/odph_api.h>

#include "ipsec.h"
#include "test_vectors.h"

/*
 * Miscellaneous parameters for combined out+in tests
 */
typedef struct {
	ipsec_test_part_flags_t part_flags;
	odp_bool_t display_algo;
	odp_bool_t ah;
	odp_bool_t v6;
	odp_bool_t tunnel;
	odp_bool_t tunnel_is_v6;
	odp_bool_t udp_encap;
	enum ipsec_test_stats stats;
} ipsec_test_flags;

static void test_out_in_all(const ipsec_test_flags *flags);

struct cipher_param {
	const char *name;
	odp_cipher_alg_t algo;
	const odp_crypto_key_t *key;
	const odp_crypto_key_t *key_extra;
};

struct auth_param {
	const char *name;
	odp_auth_alg_t algo;
	const odp_crypto_key_t *key;
	const odp_crypto_key_t *key_extra;
};

#define ALG(alg, key, key_extra) { #alg, alg, key, key_extra }

/*
 * Ciphers that can be used in ESP and combined with any integrity
 * algorithm. This excludes combined mode algorithms such as AES-GCM.
 */
static struct cipher_param ciphers[] = {
	ALG(ODP_CIPHER_ALG_NULL, NULL, NULL),
	ALG(ODP_CIPHER_ALG_DES, &key_des_64, NULL),
	ALG(ODP_CIPHER_ALG_3DES_CBC, &key_des_192, NULL),
	ALG(ODP_CIPHER_ALG_AES_CBC, &key_a5_128, NULL),
	ALG(ODP_CIPHER_ALG_AES_CBC, &key_a5_192, NULL),
	ALG(ODP_CIPHER_ALG_AES_CBC, &key_a5_256, NULL),
	ALG(ODP_CIPHER_ALG_AES_CTR, &key_a5_128, &key_mcgrew_gcm_salt_3),
	ALG(ODP_CIPHER_ALG_AES_CTR, &key_a5_192, &key_mcgrew_gcm_salt_3),
	ALG(ODP_CIPHER_ALG_AES_CTR, &key_a5_256, &key_mcgrew_gcm_salt_3)
};

/*
 * Integrity algorithms that can be used in ESP and AH. This excludes
 * AES-GMAC which is defined for ESP as a combined-mode algorithm.
 */
static struct auth_param auths[] = {
	ALG(ODP_AUTH_ALG_NULL, NULL, NULL),
	ALG(ODP_AUTH_ALG_MD5_HMAC, &key_5a_128, NULL),
	ALG(ODP_AUTH_ALG_SHA1_HMAC, &key_5a_160, NULL),
	ALG(ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256, NULL),
	ALG(ODP_AUTH_ALG_SHA384_HMAC, &key_5a_384, NULL),
	ALG(ODP_AUTH_ALG_SHA512_HMAC, &key_5a_512, NULL),
	ALG(ODP_AUTH_ALG_AES_CMAC, &key_5a_128, NULL),
	ALG(ODP_AUTH_ALG_AES_XCBC_MAC, &key_5a_128, NULL)
};

/*
 * Integrity algorithms that can be used in AH but not in ESP as
 * individual algorithms (combined with a cipher).
 */
static struct auth_param ah_auths[] = {
	ALG(ODP_AUTH_ALG_AES_GMAC, &key_a5_128, &key_mcgrew_gcm_salt_2),
	ALG(ODP_AUTH_ALG_AES_GMAC, &key_a5_192, &key_mcgrew_gcm_salt_2),
	ALG(ODP_AUTH_ALG_AES_GMAC, &key_a5_256, &key_mcgrew_gcm_salt_2),
};

struct cipher_auth_comb_param {
	struct cipher_param cipher;
	struct auth_param auth;
};

static struct cipher_auth_comb_param cipher_auth_comb[] = {
	{
		ALG(ODP_CIPHER_ALG_AES_GCM, &key_a5_128, &key_mcgrew_gcm_salt_2),
		ALG(ODP_AUTH_ALG_AES_GCM, NULL, NULL),
	},
	{
		ALG(ODP_CIPHER_ALG_AES_GCM, &key_a5_192, &key_mcgrew_gcm_salt_2),
		ALG(ODP_AUTH_ALG_AES_GCM, NULL, NULL),
	},
	{
		ALG(ODP_CIPHER_ALG_AES_GCM, &key_a5_256, &key_mcgrew_gcm_salt_2),
		ALG(ODP_AUTH_ALG_AES_GCM, NULL, NULL),
	},
	{
		ALG(ODP_CIPHER_ALG_NULL, NULL, NULL),
		ALG(ODP_AUTH_ALG_AES_GMAC, &key_a5_128, &key_mcgrew_gcm_salt_2),
	},
	{
		ALG(ODP_CIPHER_ALG_NULL, NULL, NULL),
		ALG(ODP_AUTH_ALG_AES_GMAC, &key_a5_192, &key_mcgrew_gcm_salt_2),
	},
	{
		ALG(ODP_CIPHER_ALG_NULL, NULL, NULL),
		ALG(ODP_AUTH_ALG_AES_GMAC, &key_a5_256, &key_mcgrew_gcm_salt_2),
	},
	{
		ALG(ODP_CIPHER_ALG_AES_CCM, &key_a5_128, &key_3byte_salt),
		ALG(ODP_AUTH_ALG_AES_CCM, NULL, NULL),
	},
	{
		ALG(ODP_CIPHER_ALG_AES_CCM, &key_a5_192, &key_3byte_salt),
		ALG(ODP_AUTH_ALG_AES_CCM, NULL, NULL),
	},
	{
		ALG(ODP_CIPHER_ALG_AES_CCM, &key_a5_256, &key_3byte_salt),
		ALG(ODP_AUTH_ALG_AES_CCM, NULL, NULL),
	},
	{
		ALG(ODP_CIPHER_ALG_CHACHA20_POLY1305, &key_rfc7634, &key_rfc7634_salt),
		ALG(ODP_AUTH_ALG_CHACHA20_POLY1305, NULL, NULL),
	},
};

static void test_out_ipv4_ah_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_ah_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_ah_tun_ipv4_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_ah_tun_ipv6_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_esp_null_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res =
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res =
				  &pkt_ipv4_icmp_0_esp_tun_ipv6_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_ipsec_stats_zero_assert(odp_ipsec_stats_t *stats)
{
	CU_ASSERT(stats->success == 0);
	CU_ASSERT(stats->proto_err == 0);
	CU_ASSERT(stats->auth_err == 0);
	CU_ASSERT(stats->antireplay_err == 0);
	CU_ASSERT(stats->alg_err == 0);
	CU_ASSERT(stats->mtu_err == 0);
	CU_ASSERT(stats->hard_exp_bytes_err == 0);
	CU_ASSERT(stats->hard_exp_pkts_err == 0);
	CU_ASSERT(stats->success_bytes == 0);
}

static void test_ipsec_stats_test_assert(odp_ipsec_stats_t *stats,
					 enum ipsec_test_stats test,
					 uint64_t succ_bytes)
{
	if (test == IPSEC_TEST_STATS_SUCCESS) {
		CU_ASSERT(stats->success == 1);
		CU_ASSERT(stats->success_bytes >= succ_bytes);
	} else {
		CU_ASSERT(stats->success == 0);
		CU_ASSERT(stats->success_bytes == 0);
	}

	if (test == IPSEC_TEST_STATS_PROTO_ERR) {
		/* Braces needed by CU macro */
		CU_ASSERT(stats->proto_err == 1);
	} else {
		/* Braces needed by CU macro */
		CU_ASSERT(stats->proto_err == 0);
	}

	if (test == IPSEC_TEST_STATS_AUTH_ERR) {
		/* Braces needed by CU macro */
		CU_ASSERT(stats->auth_err == 1);
	} else {
		/* Braces needed by CU macro */
		CU_ASSERT(stats->auth_err == 0);
	}

	CU_ASSERT(stats->antireplay_err == 0);
	CU_ASSERT(stats->alg_err == 0);
	CU_ASSERT(stats->mtu_err == 0);
	CU_ASSERT(stats->hard_exp_bytes_err == 0);
	CU_ASSERT(stats->hard_exp_pkts_err == 0);
}

static void ipsec_pkt_proto_err_set(odp_packet_t pkt)
{
	uint32_t l3_off = odp_packet_l3_offset(pkt);
	odph_ipv4hdr_t ip;

	memset(&ip, 0, sizeof(ip));

	/* Simulate proto error by corrupting protocol field */

	odp_packet_copy_to_mem(pkt, l3_off, sizeof(ip), &ip);

	if (ip.proto == ODPH_IPPROTO_ESP)
		ip.proto = ODPH_IPPROTO_AH;
	else
		ip.proto = ODPH_IPPROTO_ESP;

	odp_packet_copy_from_mem(pkt, l3_off, sizeof(ip), &ip);
}

static void ipsec_pkt_auth_err_set(odp_packet_t pkt)
{
	uint32_t data, len;

	/* Simulate auth error by corrupting ICV */

	len = odp_packet_len(pkt);
	odp_packet_copy_to_mem(pkt, len - sizeof(data), sizeof(data), &data);
	data = ~data;
	odp_packet_copy_from_mem(pkt, len - sizeof(data), sizeof(data), &data);
}

static void ipsec_pkt_update(odp_packet_t pkt, const ipsec_test_flags *flags)
{
	if (flags && flags->stats == IPSEC_TEST_STATS_PROTO_ERR)
		ipsec_pkt_proto_err_set(pkt);

	if (flags && flags->stats == IPSEC_TEST_STATS_AUTH_ERR)
		ipsec_pkt_auth_err_set(pkt);
}

static void ipsec_check_out_in_one(const ipsec_test_part *part_outbound,
				   const ipsec_test_part *part_inbound,
				   odp_ipsec_sa_t sa,
				   odp_ipsec_sa_t sa_in,
				   const ipsec_test_flags *flags)
{
	int num_out = part_outbound->num_pkt;
	odp_packet_t pkto[num_out];
	int i;

	num_out = ipsec_check_out(part_outbound, sa, pkto);

	for (i = 0; i < num_out; i++) {
		ipsec_test_part part_in = *part_inbound;
		ipsec_test_packet pkt_in;

		ipsec_pkt_update(pkto[i], flags);

		ipsec_test_packet_from_pkt(&pkt_in, &pkto[i]);
		part_in.pkt_in = &pkt_in;

		ipsec_check_in_one(&part_in, sa_in);
	}
}

static int sa_creation_failure_ok(const odp_ipsec_sa_param_t *param)
{
	odp_cipher_alg_t cipher = param->crypto.cipher_alg;
	odp_auth_alg_t auth     = param->crypto.auth_alg;

	/* Single algorithm must not fail */
	if (cipher == ODP_CIPHER_ALG_NULL || auth == ODP_AUTH_ALG_NULL)
		return 0;

	/* Combined mode algorithms must not fail */
	if (cipher == ODP_CIPHER_ALG_AES_GCM ||
	    cipher == ODP_CIPHER_ALG_AES_CCM ||
	    cipher == ODP_CIPHER_ALG_CHACHA20_POLY1305)
		return 0;

	/* Combination of mandatory algorithms must not fail */
	if (cipher == ODP_CIPHER_ALG_AES_CBC && auth == ODP_AUTH_ALG_SHA1_HMAC)
		return 0;

	printf("\n      Algorithm combination (%d, %d) maybe not supported.\n", cipher, auth);
	printf("      SA creation failed, skipping test.\n");
	return 1;
}

static void test_out_in_common(const ipsec_test_flags *flags,
			       odp_cipher_alg_t cipher,
			       const odp_crypto_key_t *cipher_key,
			       odp_auth_alg_t auth,
			       const odp_crypto_key_t *auth_key,
			       const odp_crypto_key_t *cipher_key_extra,
			       const odp_crypto_key_t *auth_key_extra)
{
	odp_ipsec_tunnel_param_t *tun_ptr = NULL;
	odp_ipsec_tunnel_param_t tunnel;
	uint32_t src_v4 = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst_v4 = IPV4ADDR(10, 0, 222, 2);
	uint8_t src_v6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x11, 0x43, 0xff, 0xfe, 0x4a, 0xd7, 0x0a,
	};
	uint8_t dst_v6[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
	};
	odp_ipsec_sa_param_t param;
	odp_ipsec_stats_t stats;
	odp_ipsec_protocol_t proto = flags->ah ? ODP_IPSEC_AH : ODP_IPSEC_ESP;
	odp_ipsec_sa_t sa_out;
	odp_ipsec_sa_t sa_in;
	odp_proto_l3_type_t out_l3_type = ODP_PROTO_L3_TYPE_IPV4;
	odp_proto_l4_type_t out_l4_type = ODP_PROTO_L4_TYPE_ESP;

	CU_ASSERT_FATAL(flags != NULL);

	/* ICV won't be generated for NULL AUTH */
	if ((flags->stats == IPSEC_TEST_STATS_AUTH_ERR) &&
	    (auth == ODP_AUTH_ALG_NULL))
		return;

	if (flags->tunnel) {
		if (flags->tunnel_is_v6) {
			memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
			tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
			tunnel.ipv6.src_addr = &src_v6;
			tunnel.ipv6.dst_addr = &dst_v6;
			tunnel.ipv6.hlimit = 64;
			tun_ptr = &tunnel;
		} else {
			memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
			tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
			tunnel.ipv4.src_addr = &src_v4;
			tunnel.ipv4.dst_addr = &dst_v4;
			tunnel.ipv4.ttl = 64;
			tun_ptr = &tunnel;
		}
	}

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, proto, 123, tun_ptr,
			    cipher, cipher_key,
			    auth, auth_key,
			    cipher_key_extra, auth_key_extra);

	if (flags->udp_encap)
		param.opt.udp_encap = 1;

	sa_out = odp_ipsec_sa_create(&param);

	if (sa_out == ODP_IPSEC_SA_INVALID && sa_creation_failure_ok(&param))
		return;

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa_out);

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_INBOUND, proto, 123, tun_ptr,
			    cipher, cipher_key,
			    auth, auth_key,
			    cipher_key_extra, auth_key_extra);

	if (flags->udp_encap)
		param.opt.udp_encap = 1;

	sa_in = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa_in);

	if ((flags->tunnel && flags->tunnel_is_v6) ||
	    (!flags->tunnel && flags->v6))
		out_l3_type = ODP_PROTO_L3_TYPE_IPV6;
	if (flags->ah)
		out_l4_type = ODP_PROTO_L4_TYPE_AH;
	if (flags->udp_encap)
		out_l4_type = ODP_PROTO_L4_TYPE_UDP;

	ipsec_test_part test_out = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = out_l3_type,
			  .l4_type = out_l4_type,
			},
		},
	};
	ipsec_test_part test_in = {
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_res = &pkt_ipv4_icmp_0 },
		},
	};

	if (flags->v6) {
		test_out.pkt_in = &pkt_ipv6_icmp_0;
		test_in.out[0].l3_type = ODP_PROTO_L3_TYPE_IPV6;
		test_in.out[0].l4_type = ODP_PROTO_L4_TYPE_ICMPV6;
		test_in.out[0].pkt_res = &pkt_ipv6_icmp_0;
	}

	test_out.flags = flags->part_flags;
	test_in.flags = flags->part_flags;

	if (flags->stats == IPSEC_TEST_STATS_PROTO_ERR)
		test_in.out[0].status.error.proto = 1;
	if (flags->stats == IPSEC_TEST_STATS_AUTH_ERR)
		test_in.out[0].status.error.auth = 1;

	if (flags->stats != IPSEC_TEST_STATS_NONE) {
		CU_ASSERT(odp_ipsec_stats(sa_out, &stats) == 0);
		test_ipsec_stats_zero_assert(&stats);
		CU_ASSERT(odp_ipsec_stats(sa_in, &stats) == 0);
		test_ipsec_stats_zero_assert(&stats);
	}

	if (flags->part_flags.test_sa_seq_num) {
		int rc;

		test_out.out[0].seq_num = 0x1235;
		rc = ipsec_test_sa_update_seq_num(sa_out,
						  test_out.out[0].seq_num);

		/* Skip further checks related to this specific test if the
		 * SA update call was not successful.
		 */
		if (rc < 0) {
			printf("\t >> skipped");
			test_out.flags.test_sa_seq_num = false;
		}
	}

	ipsec_check_out_in_one(&test_out, &test_in, sa_out, sa_in, flags);

	if (flags->stats != IPSEC_TEST_STATS_NONE) {
		uint64_t succ_bytes = 0;

		/* Minimum bytes to be counted for stats.success_bytes */
		if (!flags->ah) {
			succ_bytes = test_out.pkt_in[0].len -
				     test_out.pkt_in[0].l4_offset;

			if (flags->tunnel)
				succ_bytes += test_out.pkt_in[0].l4_offset -
					      test_out.pkt_in[0].l3_offset;
		} else {
			succ_bytes = test_out.pkt_in[0].len -
				     test_out.pkt_in[0].l3_offset;

			if (flags->tunnel)
				succ_bytes += (flags->tunnel_is_v6 ?
					       ODPH_IPV6HDR_LEN :
					       ODPH_IPV4HDR_LEN);
		}

		/* All stats tests have outbound operation success and inbound
		 * varying.
		 */
		CU_ASSERT(odp_ipsec_stats(sa_out, &stats) == 0);
		test_ipsec_stats_test_assert(&stats, IPSEC_TEST_STATS_SUCCESS,
					     succ_bytes);

		CU_ASSERT(odp_ipsec_stats(sa_in, &stats) == 0);
		test_ipsec_stats_test_assert(&stats, flags->stats, succ_bytes);
	}

	ipsec_sa_destroy(sa_out);
	ipsec_sa_destroy(sa_in);
}

static void test_esp_out_in(struct cipher_param *cipher,
			    struct auth_param *auth,
			    const ipsec_test_flags *flags)
{
	int cipher_keylen = cipher->key ? 8 * cipher->key->length : 0;
	int auth_keylen = auth->key ? 8 * auth->key->length : 0;

	if (ipsec_check_esp(cipher->algo, cipher_keylen,
			    auth->algo, auth_keylen) != ODP_TEST_ACTIVE)
		return;

	if (flags->display_algo)
		printf("\n    %s (keylen %d) %s (keylen %d) ",
		       cipher->name, cipher_keylen, auth->name, auth_keylen);

	test_out_in_common(flags, cipher->algo, cipher->key,
			   auth->algo, auth->key,
			   cipher->key_extra, auth->key_extra);
}

static void test_esp_out_in_all(const ipsec_test_flags *flags_in)
{
	uint32_t c;
	uint32_t a;
	ipsec_test_flags flags = *flags_in;

	flags.ah = false;

	for (c = 0; c < ODPH_ARRAY_SIZE(ciphers); c++)
		for (a = 0; a < ODPH_ARRAY_SIZE(auths); a++)
			test_esp_out_in(&ciphers[c], &auths[a], &flags);

	for (c = 0; c < ODPH_ARRAY_SIZE(cipher_auth_comb); c++)
		test_esp_out_in(&cipher_auth_comb[c].cipher,
				&cipher_auth_comb[c].auth,
				&flags);
}

/*
 * Test ESP output followed by input with all combinations of ciphers and
 * integrity algorithms.
 */
static void test_esp_out_in_all_basic(void)
{
	ipsec_test_flags flags;

	memset(&flags, 0, sizeof(flags));
	flags.display_algo = true;

	test_esp_out_in_all(&flags);

	printf("\n  ");
}

static int is_out_mode_inline(void)
{
	return suite_context.outbound_op_mode == ODP_IPSEC_OP_MODE_INLINE;
}

static void test_inline_hdr_in_packet(void)
{
	ipsec_test_flags flags = {
		.part_flags.inline_hdr_in_packet = true,
	};
	test_out_in_all(&flags);
}

static void test_ah_out_in(struct auth_param *auth,
			   const ipsec_test_flags *flags_in)
{
	int auth_keylen = auth->key ? 8 * auth->key->length : 0;
	ipsec_test_flags flags = *flags_in;

	if (ipsec_check_ah(auth->algo, auth_keylen) != ODP_TEST_ACTIVE)
		return;

	if (flags.display_algo)
		printf("\n    %s (keylen %d) ", auth->name, auth_keylen);

	flags.ah = true;

	test_out_in_common(&flags, ODP_CIPHER_ALG_NULL, NULL,
			   auth->algo, auth->key,
			   NULL, auth->key_extra);
}

static void test_ah_out_in_all(const ipsec_test_flags *flags)
{
	uint32_t a;

	for (a = 0; a < ODPH_ARRAY_SIZE(auths); a++)
		test_ah_out_in(&auths[a], flags);
	for (a = 0; a < ODPH_ARRAY_SIZE(ah_auths); a++)
		test_ah_out_in(&ah_auths[a], flags);
}

static void test_ah_out_in_all_basic(void)
{
	ipsec_test_flags flags;

	memset(&flags, 0, sizeof(flags));
	flags.display_algo = true;

	test_ah_out_in_all(&flags);

	printf("\n  ");
}

static void test_out_in_all(const ipsec_test_flags *flags)
{
	test_esp_out_in_all(flags);
	test_ah_out_in_all(flags);
}

static void test_out_ipv4_esp_udp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.opt.udp_encap = 1;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_esp_udp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_ah_sha256_frag_check(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	ipsec_test_part test;
	ipsec_test_part test2;

	memset(&test, 0, sizeof(ipsec_test_part));
	memset(&test2, 0, sizeof(ipsec_test_part));

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	test.pkt_in = &pkt_ipv4_icmp_0;
	test.num_pkt = 1;
	test.out[0].status.error.mtu = 1;
	test.out[0].l3_type = ODP_PROTO_L3_TYPE_IPV4;
	test.out[0].l4_type = ODP_PROTO_L4_TYPE_ICMPV4;

	test2.pkt_in = &pkt_ipv4_icmp_0;
	test2.num_opt = 1;
	test2.opt.flag.frag_mode = 1;
	test2.opt.frag_mode = ODP_IPSEC_FRAG_DISABLED;
	test2.num_pkt = 1;
	test2.out[0].pkt_res = &pkt_ipv4_icmp_0_ah_sha256_1;

	ipsec_check_out_one(&test, sa);

	ipsec_check_out_one(&test2, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_ah_sha256_frag_check_2(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	ipsec_test_part test;

	memset(&test, 0, sizeof(ipsec_test_part));

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	test.pkt_in = &pkt_ipv4_icmp_0;
	test.num_pkt = 1;
	test.out[0].status.error.mtu = 1;
	test.out[0].l3_type = ODP_PROTO_L3_TYPE_IPV4;
	test.out[0].l4_type = ODP_PROTO_L4_TYPE_ICMPV4;

	ipsec_test_part test2 = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_ah_sha256_1 },
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
	ipsec_test_part test;
	ipsec_test_part test2;

	memset(&test, 0, sizeof(ipsec_test_part));
	memset(&test2, 0, sizeof(ipsec_test_part));

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	test.pkt_in = &pkt_ipv4_icmp_0;
	test.num_pkt = 1;
	test.out[0].status.error.mtu = 1;
	test.out[0].l3_type = ODP_PROTO_L3_TYPE_IPV4;
	test.out[0].l4_type = ODP_PROTO_L4_TYPE_ICMPV4;

	test2.pkt_in = &pkt_ipv4_icmp_0;
	test2.num_opt = 1;
	test2.opt.flag.frag_mode = 1;
	test2.opt.frag_mode = ODP_IPSEC_FRAG_DISABLED;
	test2.num_pkt = 1;
	test2.out[0].pkt_res = &pkt_ipv4_icmp_0_esp_null_sha256_1;

	ipsec_check_out_one(&test, sa);

	ipsec_check_out_one(&test2, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_esp_null_sha256_frag_check_2(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	ipsec_test_part test;

	memset(&test, 0, sizeof(ipsec_test_part));

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	param.outbound.frag_mode = ODP_IPSEC_FRAG_CHECK;
	param.outbound.mtu = 100;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	test.pkt_in = &pkt_ipv4_icmp_0;
	test.num_pkt = 1;
	test.out[0].status.error.mtu = 1;
	test.out[0].l3_type = ODP_PROTO_L3_TYPE_IPV4;
	test.out[0].l4_type = ODP_PROTO_L4_TYPE_ICMPV4;

	ipsec_test_part test2 = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_icmp_0_esp_null_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv6_icmp_0_ah_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv6_icmp_0_ah_tun_ipv4_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_AH, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv6_icmp_0_ah_tun_ipv6_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv6_icmp_0_esp_null_sha256_1 },
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res =
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res =
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
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);
	param.opt.udp_encap = 1;

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv6_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv6_icmp_0_esp_udp_null_sha256_1 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_dummy_esp_null_sha256_tun(odp_ipsec_tunnel_param_t tunnel)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;
	odp_ipsec_sa_t sa2;
	ipsec_test_part test;
	ipsec_test_part test_in;
	ipsec_test_part test_empty;
	odp_proto_l3_type_t out_l3_type = ODP_PROTO_L3_TYPE_IPV4;

	if (tunnel.type == ODP_IPSEC_TUNNEL_IPV6)
		out_l3_type = ODP_PROTO_L3_TYPE_IPV6;

	memset(&test, 0, sizeof(ipsec_test_part));
	memset(&test_in, 0, sizeof(ipsec_test_part));
	memset(&test_empty, 0, sizeof(ipsec_test_part));

	/* This test will not work properly in inbound inline mode.
	 * Packet might be dropped and we will not check for that. */
	if (suite_context.inbound_op_mode == ODP_IPSEC_OP_MODE_INLINE)
		return;

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_INBOUND, ODP_IPSEC_ESP, 123, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa2 = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa2);

	test.pkt_in = &pkt_test_nodata;
	test.num_opt = 1;
	test.opt.flag.tfc_dummy = 1;
	test.opt.tfc_pad_len = 16;
	test.num_pkt = 1;
	test.out[0].l3_type = out_l3_type;
	test.out[0].l4_type = ODP_PROTO_L4_TYPE_ESP;

	test_in.num_pkt = 1;
	test_in.out[0].l3_type = ODP_PROTO_L3_TYPE_IPV4;
	test_in.out[0].l4_type = ODP_PROTO_L4_TYPE_NO_NEXT;

	test_empty.pkt_in = &pkt_test_empty;
	test_empty.num_opt = 1;
	test_empty.opt.flag.tfc_dummy = 1;
	test_empty.opt.tfc_pad_len = 16;
	test_empty.num_pkt = 1;
	test_empty.out[0].l3_type = out_l3_type;
	test_empty.out[0].l4_type = ODP_PROTO_L4_TYPE_ESP;

	ipsec_check_out_in_one(&test, &test_in, sa, sa2, NULL);
	ipsec_check_out_in_one(&test_empty, &test_in, sa, sa2, NULL);

	ipsec_sa_destroy(sa2);
	ipsec_sa_destroy(sa);
}

static void test_out_dummy_esp_null_sha256_tun_ipv4(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	test_out_dummy_esp_null_sha256_tun(tunnel);
}

static void test_out_dummy_esp_null_sha256_tun_ipv6(void)
{
	odp_ipsec_tunnel_param_t tunnel;
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

	test_out_dummy_esp_null_sha256_tun(tunnel);
}

static void test_out_ipv4_udp_esp_null_sha256(void)
{
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_SHA256_HMAC, &key_5a_256,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_udp,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .pkt_res = &pkt_ipv4_udp_esp_null_sha256 },
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_out_ipv4_null_aes_xcbc(void)
{
	odp_ipsec_tunnel_param_t tunnel;
	odp_ipsec_sa_param_t param;
	odp_ipsec_sa_t sa;

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);

	memset(&tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));
	tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel.ipv4.src_addr = &src;
	tunnel.ipv4.dst_addr = &dst;
	tunnel.ipv4.ttl = 64;

	ipsec_sa_param_fill(&param,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP,
			    0x100, &tunnel,
			    ODP_CIPHER_ALG_NULL, NULL,
			    ODP_AUTH_ALG_AES_XCBC_MAC, &key_auth_aes_xcbc_128,
			    NULL, NULL);

	sa = odp_ipsec_sa_create(&param);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa);

	ipsec_test_part test = {
		.pkt_in = &pkt_ipv4_null_aes_xcbc_plain,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = _ODP_PROTO_L4_TYPE_UNDEF,
			  .pkt_res = &pkt_ipv4_null_aes_xcbc_esp,
			},
		},
	};

	ipsec_check_out_one(&test, sa);

	ipsec_sa_destroy(sa);
}

static void test_sa_info(void)
{
	uint32_t src = IPV4ADDR(10, 0, 111, 2);
	uint32_t dst = IPV4ADDR(10, 0, 222, 2);
	odp_ipsec_tunnel_param_t tunnel_out;
	odp_ipsec_tunnel_param_t tunnel_in;
	odp_ipsec_sa_param_t param_out;
	odp_ipsec_sa_param_t param_in;
	odp_ipsec_sa_info_t info_out;
	odp_ipsec_sa_info_t info_in;
	odp_ipsec_sa_t sa_out;
	odp_ipsec_sa_t sa_in;

	memset(&tunnel_out, 0, sizeof(tunnel_out));
	memset(&tunnel_in, 0, sizeof(tunnel_in));

	tunnel_out.type = ODP_IPSEC_TUNNEL_IPV4;
	tunnel_out.ipv4.src_addr = &src;
	tunnel_out.ipv4.dst_addr = &dst;

	ipsec_sa_param_fill(&param_out,
			    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP,
			    123, &tunnel_out,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA1_HMAC, &key_5a_160,
			    NULL, NULL);

	sa_out = odp_ipsec_sa_create(&param_out);

	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != sa_out);

	ipsec_sa_param_fill(&param_in,
			    ODP_IPSEC_DIR_INBOUND, ODP_IPSEC_ESP,
			    123, &tunnel_in,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA1_HMAC, &key_5a_160,
			    NULL, NULL);

	param_in.inbound.antireplay_ws = 32;
	sa_in = odp_ipsec_sa_create(&param_in);
	CU_ASSERT_FATAL(sa_in != ODP_IPSEC_SA_INVALID);

	memset(&info_out, 0, sizeof(info_out));
	CU_ASSERT_FATAL(0 == odp_ipsec_sa_info(sa_out, &info_out));

	CU_ASSERT(info_out.param.dir == param_out.dir);
	CU_ASSERT(info_out.param.proto == param_out.proto);
	CU_ASSERT(info_out.param.mode == param_out.mode);

	CU_ASSERT(info_out.param.crypto.cipher_alg == param_out.crypto.cipher_alg);
	CU_ASSERT(info_out.param.crypto.auth_alg == param_out.crypto.auth_alg);
	CU_ASSERT(info_out.param.opt.udp_encap == param_out.opt.udp_encap);
	CU_ASSERT(info_out.param.spi == param_out.spi);
	CU_ASSERT(info_out.param.opt.esn == param_out.opt.esn);
	CU_ASSERT(info_out.param.opt.udp_encap == param_out.opt.udp_encap);
	CU_ASSERT(info_out.param.opt.copy_dscp == param_out.opt.copy_dscp);
	CU_ASSERT(info_out.param.opt.copy_flabel == param_out.opt.copy_flabel);
	CU_ASSERT(info_out.param.opt.copy_df == param_out.opt.copy_df);

	CU_ASSERT(ODP_IPSEC_MODE_TUNNEL == info_out.param.mode);

	CU_ASSERT(info_out.param.outbound.tunnel.type == param_out.outbound.tunnel.type);
	CU_ASSERT(info_out.param.outbound.tunnel.ipv4.dscp == param_out.outbound.tunnel.ipv4.dscp);
	CU_ASSERT(info_out.param.outbound.tunnel.ipv4.df == param_out.outbound.tunnel.ipv4.df);
	CU_ASSERT_FATAL(NULL != info_out.param.outbound.tunnel.ipv4.src_addr);
	CU_ASSERT(0 == memcmp(info_out.param.outbound.tunnel.ipv4.src_addr,
			      param_out.outbound.tunnel.ipv4.src_addr,
			      ODP_IPV4_ADDR_SIZE));
	CU_ASSERT_FATAL(NULL != info_out.param.outbound.tunnel.ipv4.dst_addr);
	CU_ASSERT(0 == memcmp(info_out.param.outbound.tunnel.ipv4.dst_addr,
			      param_out.outbound.tunnel.ipv4.dst_addr,
			      ODP_IPV4_ADDR_SIZE));

	CU_ASSERT(info_out.param.lifetime.soft_limit.bytes == param_out.lifetime.soft_limit.bytes);
	CU_ASSERT(info_out.param.lifetime.hard_limit.bytes == param_out.lifetime.hard_limit.bytes);
	CU_ASSERT(info_out.param.lifetime.soft_limit.packets ==
		  param_out.lifetime.soft_limit.packets);
	CU_ASSERT(info_out.param.lifetime.hard_limit.packets ==
		  param_out.lifetime.hard_limit.packets);

	CU_ASSERT(0 == info_out.outbound.seq_num);

	memset(&info_in, 0, sizeof(info_in));
	CU_ASSERT_FATAL(0 == odp_ipsec_sa_info(sa_in, &info_in));
	CU_ASSERT(0 == info_in.inbound.antireplay_window_top);

	ipsec_test_part test_out = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ESP,
			},
		},
	};
	ipsec_test_part test_in = {
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			},
		},
	};

	ipsec_check_out_in_one(&test_out, &test_in, sa_out, sa_in, NULL);

	memset(&info_out, 0, sizeof(info_out));
	CU_ASSERT_FATAL(0 == odp_ipsec_sa_info(sa_out, &info_out));
	CU_ASSERT(1 == info_out.outbound.seq_num);

	memset(&info_in, 0, sizeof(info_in));
	CU_ASSERT_FATAL(0 == odp_ipsec_sa_info(sa_in, &info_in));
	CU_ASSERT(1 == info_in.inbound.antireplay_window_top);

	ipsec_sa_destroy(sa_out);
	ipsec_sa_destroy(sa_in);

	/*
	 * Additional check for SA lookup parameters. Let's use transport
	 * mode SA and ODP_IPSEC_DSTADD_SPI lookup mode.
	 */
	ipsec_sa_param_fill(&param_in,
			    ODP_IPSEC_DIR_INBOUND, ODP_IPSEC_ESP, 123, NULL,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA1_HMAC, &key_5a_160,
			    NULL, NULL);
	param_in.inbound.lookup_mode = ODP_IPSEC_LOOKUP_DSTADDR_SPI;
	param_in.inbound.lookup_param.ip_version = ODP_IPSEC_IPV4;
	param_in.inbound.lookup_param.dst_addr = &dst;
	sa_in = odp_ipsec_sa_create(&param_in);
	CU_ASSERT_FATAL(sa_in != ODP_IPSEC_SA_INVALID);

	memset(&info_in, 0, sizeof(info_in));
	CU_ASSERT_FATAL(odp_ipsec_sa_info(sa_in, &info_in) == 0);

	CU_ASSERT(info_in.param.inbound.lookup_mode ==
		  ODP_IPSEC_LOOKUP_DSTADDR_SPI);
	CU_ASSERT_FATAL(info_in.param.inbound.lookup_param.dst_addr ==
			&info_in.inbound.lookup_param.dst_addr);
	CU_ASSERT(!memcmp(info_in.param.inbound.lookup_param.dst_addr,
			  &dst,
			  ODP_IPV4_ADDR_SIZE));
	ipsec_sa_destroy(sa_in);
}

static void test_test_sa_update_seq_num(void)
{
	ipsec_test_flags flags;

	memset(&flags, 0, sizeof(flags));
	flags.display_algo = true;
	flags.part_flags.test_sa_seq_num = true;

	test_out_in_all(&flags);

	printf("\n  ");
}

#define SOFT_LIMIT_PKT_CNT 1024UL
#define HARD_LIMIT_PKT_CNT 2048UL
#define DELTA_PKT_CNT 320

static void test_out_ipv4_esp_sa_expiry(enum ipsec_test_sa_expiry expiry)
{
	int byte_count_per_packet = pkt_ipv4_icmp_0.len - pkt_ipv4_icmp_0.l3_offset;
	uint32_t src = IPV4ADDR(10, 0, 11, 2);
	uint32_t dst = IPV4ADDR(10, 0, 22, 2);
	odp_ipsec_tunnel_param_t out_tunnel;
	odp_ipsec_sa_param_t param_out;
	int i, inc, limit, delta;
	uint64_t soft_limit_byte;
	uint64_t hard_limit_byte;
	uint64_t soft_limit_pkt;
	uint64_t hard_limit_pkt;
	odp_ipsec_sa_t out_sa;

	switch (expiry)	{
	case IPSEC_TEST_EXPIRY_SOFT_PKT:
		soft_limit_pkt = SOFT_LIMIT_PKT_CNT;
		hard_limit_pkt = HARD_LIMIT_PKT_CNT;
		soft_limit_byte = 0;
		hard_limit_byte = 0;
		delta = DELTA_PKT_CNT;
		limit = soft_limit_pkt;
		inc = 1;
		break;
	case IPSEC_TEST_EXPIRY_HARD_PKT:
		soft_limit_pkt = SOFT_LIMIT_PKT_CNT;
		hard_limit_pkt = HARD_LIMIT_PKT_CNT;
		soft_limit_byte = 0;
		hard_limit_byte = 0;
		delta = DELTA_PKT_CNT;
		limit = hard_limit_pkt;
		inc = 1;
		break;
	case IPSEC_TEST_EXPIRY_SOFT_BYTE:
		soft_limit_pkt = 0;
		hard_limit_pkt = 0;
		soft_limit_byte = byte_count_per_packet * SOFT_LIMIT_PKT_CNT;
		hard_limit_byte = byte_count_per_packet * HARD_LIMIT_PKT_CNT;
		delta = byte_count_per_packet * DELTA_PKT_CNT;
		limit = soft_limit_byte;
		inc = byte_count_per_packet;
		break;
	case IPSEC_TEST_EXPIRY_HARD_BYTE:
		soft_limit_pkt = 0;
		hard_limit_pkt = 0;
		soft_limit_byte = byte_count_per_packet * SOFT_LIMIT_PKT_CNT;
		hard_limit_byte = byte_count_per_packet * HARD_LIMIT_PKT_CNT;
		delta = byte_count_per_packet * DELTA_PKT_CNT;
		limit = hard_limit_byte;
		inc = byte_count_per_packet;
		break;
	default:
		return;
	}

	memset(&out_tunnel, 0, sizeof(odp_ipsec_tunnel_param_t));

	out_tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	out_tunnel.ipv4.src_addr = &src;
	out_tunnel.ipv4.dst_addr = &dst;

	ipsec_sa_param_fill(&param_out, ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP,
			    0x4a2cbfe7, &out_tunnel,
			    ODP_CIPHER_ALG_AES_CBC, &key_a5_128,
			    ODP_AUTH_ALG_SHA1_HMAC, &key_5a_160,
			    NULL, NULL);

	param_out.lifetime.soft_limit.bytes = soft_limit_byte;
	param_out.lifetime.hard_limit.bytes = hard_limit_byte;
	param_out.lifetime.soft_limit.packets = soft_limit_pkt;
	param_out.lifetime.hard_limit.packets = hard_limit_pkt;

	out_sa = odp_ipsec_sa_create(&param_out);
	CU_ASSERT_FATAL(ODP_IPSEC_SA_INVALID != out_sa);

	ipsec_test_part test_out = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ESP,
			},
		},
	};

	test_out.out[0].sa_expiry = IPSEC_TEST_EXPIRY_IGNORED;

	for (i = 0; i < limit - delta; i += inc)
		ipsec_check_out_one(&test_out, out_sa);

	sa_expiry_notified = false;
	test_out.out[0].sa_expiry = expiry;

	for (; i <= limit && !sa_expiry_notified; i += inc)
		ipsec_check_out_one(&test_out, out_sa);

	CU_ASSERT(sa_expiry_notified);

	for (; i <= limit + delta; i += inc)
		ipsec_check_out_one(&test_out, out_sa);

	ipsec_sa_destroy(out_sa);
}

static void test_out_ipv4_esp_sa_pkt_expiry(void)
{
	printf("\n	IPv4 IPsec SA packet soft expiry");
	test_out_ipv4_esp_sa_expiry(IPSEC_TEST_EXPIRY_SOFT_PKT);

	printf("\n	IPv4 IPsec SA packet hard expiry");
	test_out_ipv4_esp_sa_expiry(IPSEC_TEST_EXPIRY_HARD_PKT);

	printf("\n");
}

static void test_out_ipv4_esp_sa_byte_expiry(void)
{
	printf("\n	IPv4 IPsec SA byte soft expiry");
	test_out_ipv4_esp_sa_expiry(IPSEC_TEST_EXPIRY_SOFT_BYTE);

	printf("\n	IPv4 IPsec SA byte hard expiry");
	test_out_ipv4_esp_sa_expiry(IPSEC_TEST_EXPIRY_HARD_BYTE);

	printf("\n");
}

static void ipsec_test_capability(void)
{
	odp_ipsec_capability_t capa;

	CU_ASSERT(odp_ipsec_capability(&capa) == 0);
}

static void test_defaults(uint8_t fill)
{
	odp_ipsec_config_t config;
	odp_ipsec_sa_param_t sa_param;

	memset(&config, fill, sizeof(config));
	odp_ipsec_config_init(&config);
	CU_ASSERT(config.inbound.lookup.min_spi == 0);
	CU_ASSERT(config.inbound.lookup.max_spi == UINT32_MAX);
	CU_ASSERT(config.inbound.lookup.spi_overlap == 0);
	CU_ASSERT(config.inbound.retain_outer == ODP_PROTO_LAYER_NONE);
	CU_ASSERT(config.inbound.parse_level == ODP_PROTO_LAYER_NONE);
	CU_ASSERT(config.inbound.chksums.all_chksum == 0);
	CU_ASSERT(!config.inbound.reassembly.en_ipv4);
	CU_ASSERT(!config.inbound.reassembly.en_ipv6);
	CU_ASSERT(config.inbound.reassembly.max_wait_time == 0);
	CU_ASSERT(config.inbound.reassembly.max_num_frags == 2);
	CU_ASSERT(!config.inbound.reass_async);
	CU_ASSERT(!config.inbound.reass_inline);
	CU_ASSERT(config.outbound.all_chksum == 0);
	CU_ASSERT(!config.stats_en);
	CU_ASSERT(!config.vector.enable);

	memset(&sa_param, fill, sizeof(sa_param));
	odp_ipsec_sa_param_init(&sa_param);
	CU_ASSERT(sa_param.proto == ODP_IPSEC_ESP);
	CU_ASSERT(sa_param.crypto.cipher_alg == ODP_CIPHER_ALG_NULL);
	CU_ASSERT(sa_param.crypto.auth_alg == ODP_AUTH_ALG_NULL);
	CU_ASSERT(sa_param.crypto.icv_len == 0);
	CU_ASSERT(sa_param.opt.esn == 0);
	CU_ASSERT(sa_param.opt.udp_encap == 0);
	CU_ASSERT(sa_param.opt.copy_dscp == 0);
	CU_ASSERT(sa_param.opt.copy_flabel == 0);
	CU_ASSERT(sa_param.opt.copy_df == 0);
	CU_ASSERT(sa_param.opt.dec_ttl == 0);
	CU_ASSERT(sa_param.lifetime.soft_limit.bytes == 0);
	CU_ASSERT(sa_param.lifetime.soft_limit.packets == 0);
	CU_ASSERT(sa_param.lifetime.hard_limit.bytes == 0);
	CU_ASSERT(sa_param.lifetime.hard_limit.packets == 0);
	CU_ASSERT(sa_param.context == NULL);
	CU_ASSERT(sa_param.context_len == 0);
	CU_ASSERT(sa_param.inbound.lookup_mode == ODP_IPSEC_LOOKUP_DISABLED);
	CU_ASSERT(sa_param.inbound.antireplay_ws == 0);
	CU_ASSERT(sa_param.inbound.pipeline == ODP_IPSEC_PIPELINE_NONE);
	CU_ASSERT(!sa_param.inbound.reassembly_en);
	CU_ASSERT(sa_param.outbound.tunnel.type == ODP_IPSEC_TUNNEL_IPV4);
	CU_ASSERT(sa_param.outbound.tunnel.ipv4.dscp == 0);
	CU_ASSERT(sa_param.outbound.tunnel.ipv4.df == 0);
	CU_ASSERT(sa_param.outbound.tunnel.ipv4.ttl == 255);
	CU_ASSERT(sa_param.outbound.tunnel.ipv6.flabel == 0);
	CU_ASSERT(sa_param.outbound.tunnel.ipv6.dscp == 0);
	CU_ASSERT(sa_param.outbound.tunnel.ipv6.hlimit == 255);
	CU_ASSERT(sa_param.outbound.frag_mode == ODP_IPSEC_FRAG_DISABLED);
}

static void ipsec_test_default_values(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

static void test_ipsec_stats(void)
{
	ipsec_test_flags flags;

	memset(&flags, 0, sizeof(flags));

	printf("\n        Stats : success");
	flags.stats = IPSEC_TEST_STATS_SUCCESS;
	test_out_in_all(&flags);

	printf("\n        Stats : proto err");
	flags.stats = IPSEC_TEST_STATS_PROTO_ERR;
	test_out_in_all(&flags);

	printf("\n        Stats : auth err");
	flags.stats = IPSEC_TEST_STATS_AUTH_ERR;
	test_out_in_all(&flags);

	printf("\n  ");
}

static void test_udp_encap(void)
{
	ipsec_test_flags flags;

	memset(&flags, 0, sizeof(flags));
	flags.udp_encap = 1;
	flags.tunnel = 0;

	printf("\n        IPv4 Transport");
	flags.v6 = 0;
	test_esp_out_in_all(&flags);

	printf("\n        IPv6 Transport");
	flags.v6 = 1;
	test_esp_out_in_all(&flags);

	flags.tunnel = 1;

	printf("\n        IPv4-in-IPv4 Tunnel");
	flags.v6 = 0;
	flags.tunnel_is_v6 = 0;
	test_esp_out_in_all(&flags);

	printf("\n        IPv4-in-IPv6 Tunnel");
	flags.v6 = 0;
	flags.tunnel_is_v6 = 1;
	test_esp_out_in_all(&flags);

	printf("\n        IPv6-in-IPv4 Tunnel");
	flags.v6 = 1;
	flags.tunnel_is_v6 = 0;
	test_esp_out_in_all(&flags);

	printf("\n        IPv6-in-IPv6 Tunnel");
	flags.v6 = 1;
	flags.tunnel_is_v6 = 1;
	test_esp_out_in_all(&flags);

	printf("\n  ");
}

static void test_max_num_sa(void)
{
	odp_ipsec_capability_t capa;
	uint32_t sa_pairs;
	odp_bool_t odd = false;
	uint32_t n;
	uint8_t cipher_key_data[128 / 8]; /* 128 bit key for AES */
	uint8_t auth_key_data[160 / 8];   /* 160 bit key for SHA-1 */
	odp_crypto_key_t cipher_key;
	odp_crypto_key_t auth_key;
	uint32_t tun_src;
	uint32_t tun_dst;
	odp_ipsec_tunnel_param_t tun = {
		.type = ODP_IPSEC_TUNNEL_IPV4,
		.ipv4.src_addr = &tun_src,
		.ipv4.dst_addr = &tun_dst,
		.ipv4.ttl = 64,
	};
	odp_ipsec_sa_param_t param;
	const uint32_t spi_start = 256;
	odp_ipsec_sa_t sa_odd = ODP_IPSEC_SA_INVALID;
	ipsec_test_part test_out = {
		.pkt_in = &pkt_ipv4_icmp_0,
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ESP,
			},
		},
	};
	ipsec_test_part test_in = {
		.flags = {
			/* Test lookup now that we have lots of SAs */
			.lookup = 1,
		},
		.num_pkt = 1,
		.out = {
			{ .status.warn.all = 0,
			  .status.error.all = 0,
			  .l3_type = ODP_PROTO_L3_TYPE_IPV4,
			  .l4_type = ODP_PROTO_L4_TYPE_ICMPV4,
			  .pkt_res = &pkt_ipv4_icmp_0 },
		},
	};

	CU_ASSERT_FATAL(odp_ipsec_capability(&capa) == 0);
	sa_pairs = capa.max_num_sa / 2;
	if (capa.max_num_sa > 2 && capa.max_num_sa % 2)
		odd = true;

	odp_ipsec_sa_t sa_out[sa_pairs];
	odp_ipsec_sa_t sa_in[sa_pairs];

	memset(cipher_key_data, 0xa5, sizeof(cipher_key_data));
	cipher_key.data = cipher_key_data;
	cipher_key.length = sizeof(cipher_key_data);

	memset(auth_key_data, 0x5a, sizeof(auth_key_data));
	auth_key.data = auth_key_data;
	auth_key.length = sizeof(auth_key_data);

	for (n = 0; n < sa_pairs; n++) {
		/* Make keys unique */
		if (cipher_key.length > sizeof(n))
			memcpy(cipher_key.data, &n, sizeof(n));
		if (auth_key.length > sizeof(n))
			memcpy(auth_key.data, &n, sizeof(n));

		/* These are for outbound SAs only */
		tun_src = 0x0a000000 + n;
		tun_dst = 0x0a800000 + n;

		ipsec_sa_param_fill(&param,
				    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP,
				    spi_start + n, &tun,
				    ODP_CIPHER_ALG_AES_CBC, &cipher_key,
				    ODP_AUTH_ALG_SHA1_HMAC, &auth_key,
				    NULL, NULL);
		sa_out[n] = odp_ipsec_sa_create(&param);
		CU_ASSERT_FATAL(sa_out[n] != ODP_IPSEC_SA_INVALID);

		ipsec_sa_param_fill(&param,
				    ODP_IPSEC_DIR_INBOUND, ODP_IPSEC_ESP,
				    spi_start + n, &tun,
				    ODP_CIPHER_ALG_AES_CBC, &cipher_key,
				    ODP_AUTH_ALG_SHA1_HMAC, &auth_key,
				    NULL, NULL);
		sa_in[n] = odp_ipsec_sa_create(&param);
		CU_ASSERT_FATAL(sa_in[n] != ODP_IPSEC_SA_INVALID);
	}

	n = sa_pairs - 1;
	if (odd) {
		/*
		 * We have an odd number of max SAs. Let's create a similar
		 * SA as the last created outbound SA and test it against
		 * the last created inbound SA.
		 */
		tun_src = 0x0a000000 + n;
		tun_dst = 0x0a800000 + n;

		ipsec_sa_param_fill(&param,
				    ODP_IPSEC_DIR_OUTBOUND, ODP_IPSEC_ESP,
				    spi_start + n, &tun,
				    ODP_CIPHER_ALG_AES_CBC, &cipher_key,
				    ODP_AUTH_ALG_SHA1_HMAC, &auth_key,
				    NULL, NULL);
		sa_odd = odp_ipsec_sa_create(&param);
		CU_ASSERT_FATAL(sa_odd != ODP_IPSEC_SA_INVALID);

		ipsec_check_out_in_one(&test_out, &test_in,
				       sa_odd, sa_in[n], NULL);
	}

	for (n = 0; n < sa_pairs; n++)
		ipsec_check_out_in_one(&test_out, &test_in,
				       sa_out[n], sa_in[n], NULL);

	for (n = 0; n < sa_pairs; n++) {
		ipsec_sa_destroy(sa_out[n]);
		ipsec_sa_destroy(sa_in[n]);
	}
	if (odd)
		ipsec_sa_destroy(sa_odd);
}

odp_testinfo_t ipsec_out_suite[] = {
	ODP_TEST_INFO(ipsec_test_capability),
	ODP_TEST_INFO(ipsec_test_default_values),
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
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_null_aes_xcbc,
				  ipsec_check_esp_null_aes_xcbc),
	ODP_TEST_INFO_CONDITIONAL(test_sa_info,
				  ipsec_check_esp_aes_cbc_128_sha1),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_sa_pkt_expiry,
				  ipsec_check_esp_aes_cbc_128_sha1),
	ODP_TEST_INFO_CONDITIONAL(test_out_ipv4_esp_sa_byte_expiry,
				  ipsec_check_esp_aes_cbc_128_sha1),
	ODP_TEST_INFO_CONDITIONAL(test_test_sa_update_seq_num,
				  ipsec_check_test_sa_update_seq_num),
	ODP_TEST_INFO(test_esp_out_in_all_basic),
	ODP_TEST_INFO_CONDITIONAL(test_inline_hdr_in_packet,
				  is_out_mode_inline),
	ODP_TEST_INFO(test_ah_out_in_all_basic),
	ODP_TEST_INFO(test_ipsec_stats),
	ODP_TEST_INFO(test_udp_encap),
	ODP_TEST_INFO_CONDITIONAL(test_max_num_sa,
				  ipsec_check_esp_aes_cbc_128_sha1),
	ODP_TEST_INFO_NULL,
};
