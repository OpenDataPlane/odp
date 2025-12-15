/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2020 Marvell
 * Copyright (c) 2020 Nokia
 */

#ifndef _ODP_TEST_IPSEC_H_
#define _ODP_TEST_IPSEC_H_

#include <odp_cunit_common.h>

#define IPV4ADDR(a, b, c, d) odp_cpu_to_be_32(((a) << 24) | \
					      ((b) << 16) | \
					      ((c) << 8) | \
					      ((d) << 0))

/* test arrays: */
extern odp_testinfo_t ipsec_in_suite[];
extern odp_testinfo_t ipsec_out_suite[];
extern odp_testinfo_t ipsec_out_in_suite[];

int ipsec_init(odp_instance_t *inst);
int ipsec_term(odp_instance_t inst);

int ipsec_in_inline_init(void);
int ipsec_out_inline_init(void);

int ipsec_suite_sync_init(void);
int ipsec_suite_plain_init(void);
int ipsec_suite_sched_init(void);
int ipsec_suite_term(void);

struct suite_context_s {
	odp_bool_t reass_ipv4;
	odp_bool_t reass_ipv6;
	odp_ipsec_op_mode_t inbound_op_mode;
	odp_ipsec_op_mode_t outbound_op_mode;
	odp_pool_t pool;
	odp_queue_t default_queue;
	odp_queue_t queue;
	odp_pktio_t pktio;
	odp_queue_type_t q_type;
};

extern struct suite_context_s suite_context;

#define MAX_FRAG_LEN 1500
#define MAX_FRAGS 4
#define MAX_PKT_LEN (MAX_FRAG_LEN * MAX_FRAGS)

typedef struct {
	uint32_t len;
	uint32_t l2_offset;
	uint32_t l3_offset;
	uint32_t l4_offset;
	uint8_t data[MAX_PKT_LEN];
} ipsec_test_packet;

#define _ODP_PROTO_L3_TYPE_UNDEF ((odp_proto_l3_type_t)-1)
#define _ODP_PROTO_L4_TYPE_UNDEF ((odp_proto_l4_type_t)-1)

enum ipsec_test_stats {
	IPSEC_TEST_STATS_NONE = 0,
	IPSEC_TEST_STATS_SUCCESS,
	IPSEC_TEST_STATS_PROTO_ERR,
	IPSEC_TEST_STATS_AUTH_ERR,
};

enum ipsec_test_sa_expiry {
	IPSEC_TEST_EXPIRY_NONE = 0,
	IPSEC_TEST_EXPIRY_IGNORED,
	IPSEC_TEST_EXPIRY_SOFT_BYTE,
	IPSEC_TEST_EXPIRY_SOFT_PKT,
	IPSEC_TEST_EXPIRY_HARD_BYTE,
	IPSEC_TEST_EXPIRY_HARD_PKT,
};

typedef struct {
	odp_bool_t lookup;
	odp_bool_t inline_hdr_in_packet;
	odp_bool_t test_sa_seq_num;
} ipsec_test_part_flags_t;

typedef struct {
	ipsec_test_part_flags_t flags;

	/* if nonzero, use a segmented test packet */
	uint32_t first_seg_len;

	/* Input for the inbound or outbound IPsec operation */
	const ipsec_test_packet *pkt_in;
	int num_opt;
	odp_ipsec_out_opt_t opt;

	/* Expected output */
	int num_pkt;
	struct {
		odp_ipsec_op_status_t status;
		odp_packet_reass_status_t reass_status;
		uint16_t num_frags;
		const ipsec_test_packet *pkt_res;
		odp_proto_l3_type_t l3_type;
		odp_proto_l4_type_t l4_type;
		uint32_t seq_num;
		/*
		 * Expected original IP length. Non zero only when expected len
		 * differs from that of input test packet (pkt_in).
		 */
		uint32_t orig_ip_len;
		enum ipsec_test_sa_expiry sa_expiry;
	} out[MAX_FRAGS];
} ipsec_test_part;

extern odp_bool_t sa_expiry_notified;

void ipsec_sa_param_fill(odp_ipsec_sa_param_t *param,
			 odp_ipsec_dir_t dir,
			 odp_ipsec_protocol_t proto,
			 uint32_t spi,
			 odp_ipsec_tunnel_param_t *tun,
			 odp_cipher_alg_t cipher_alg,
			 const odp_crypto_key_t *cipher_key,
			 odp_auth_alg_t auth_alg,
			 const odp_crypto_key_t *auth_key,
			 const odp_crypto_key_t *cipher_key_extra,
			 const odp_crypto_key_t *auth_key_extra);

void ipsec_sa_destroy(odp_ipsec_sa_t sa);
odp_packet_t ipsec_packet(const ipsec_test_packet *itp, uint32_t first_seg_len);
void ipsec_check_in_one(const ipsec_test_part *part, odp_ipsec_sa_t sa);
int ipsec_check_out(const ipsec_test_part *part,
		    odp_ipsec_sa_t sa,
		    odp_packet_t *pkto);
void ipsec_check_out_one(const ipsec_test_part *part, odp_ipsec_sa_t sa);
int ipsec_test_sa_update_seq_num(odp_ipsec_sa_t sa, uint32_t seq_num);
void ipsec_test_packet_from_pkt(ipsec_test_packet *test_pkt, odp_packet_t *pkt);
void rebuild_ethernet_header(ipsec_test_packet *pkt);
int ipsec_check(odp_bool_t ah,
		odp_cipher_alg_t cipher,
		uint32_t cipher_bits,
		odp_auth_alg_t auth,
		uint32_t auth_bits);
#define ipsec_check_ah(auth, auth_bits) \
	ipsec_check(true, ODP_CIPHER_ALG_NULL, 0, auth, auth_bits)
#define ipsec_check_esp(cipher, cipher_bits, auth, auth_bits) \
	ipsec_check(false, cipher, cipher_bits, auth, auth_bits)
int ipsec_check_ah_sha256(void);
int ipsec_check_esp_null_sha256(void);
int ipsec_check_esp_aes_cbc_128_null(void);
int ipsec_check_esp_aes_cbc_128_sha1(void);
int ipsec_check_esp_aes_cbc_128_sha256(void);
int ipsec_check_esp_aes_cbc_128_sha384(void);
int ipsec_check_esp_aes_cbc_128_sha512(void);
int ipsec_check_esp_aes_ctr_128_null(void);
int ipsec_check_esp_aes_gcm_128(void);
int ipsec_check_esp_aes_gcm_256(void);
int ipsec_check_ah_aes_gmac_128(void);
int ipsec_check_esp_null_aes_gmac_128(void);
int ipsec_check_esp_chacha20_poly1305(void);
int ipsec_check_test_sa_update_seq_num(void);
int ipsec_check_esp_aes_gcm_128_reass_ipv4(void);
int ipsec_check_esp_aes_gcm_128_reass_ipv6(void);
int ipsec_check_esp_null_aes_xcbc(void);
void ipsec_status_event_get(odp_ipsec_sa_t sa,
			    enum ipsec_test_sa_expiry sa_expiry);

void test_ipsec_proto_err(void);
void test_ipsec_auth_err(void);

#endif
