/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_IPSEC_H_
#define _ODP_TEST_IPSEC_H_

#include <odp_cunit_common.h>

/* test arrays: */
extern odp_testinfo_t ipsec_in_suite[];
extern odp_testinfo_t ipsec_out_suite[];

/* main test program: */
int ipsec_main(int argc, char *argv[]);

struct suite_context_s {
	odp_ipsec_op_mode_t pref_mode;
	odp_pool_t pool;
	odp_queue_t queue;
};

extern struct suite_context_s suite_context;

typedef struct {
	uint32_t len;
	uint32_t l2_offset;
	uint32_t l3_offset;
	uint32_t l4_offset;
	uint8_t data[256];
} ipsec_test_packet;

typedef struct {
	const ipsec_test_packet *pkt_in;
	int out_pkt;
	struct {
		odp_ipsec_op_status_t status;
		const ipsec_test_packet *pkt_out;
	} out[1];
} ipsec_test_part;

void ipsec_sa_param_fill(odp_ipsec_sa_param_t *param,
			 odp_bool_t in,
			 odp_bool_t ah,
			 uint32_t spi,
			 odp_ipsec_tunnel_param_t *tun,
			 odp_cipher_alg_t cipher_alg,
			 const odp_crypto_key_t *cipher_key,
			 odp_auth_alg_t auth_alg,
			 const odp_crypto_key_t *auth_key);

void ipsec_sa_destroy(odp_ipsec_sa_t sa);
odp_packet_t ipsec_packet(const ipsec_test_packet *itp);
odp_bool_t ipsec_check_packet(const ipsec_test_packet *itp, odp_packet_t pkt);
void ipsec_check_in_one(const ipsec_test_part *part, odp_ipsec_sa_t sa);
void ipsec_check_out_one(const ipsec_test_part *part, odp_ipsec_sa_t sa);
void ipsec_check_out_in_one(const ipsec_test_part *part,
			    odp_ipsec_sa_t sa,
			    odp_ipsec_sa_t sa_in);

int ipsec_check(odp_bool_t in,
		odp_bool_t ah,
		odp_cipher_alg_t cipher,
		odp_auth_alg_t auth);
#define ipsec_check_ah(in, auth) \
	ipsec_check(in, true, ODP_CIPHER_ALG_NULL, auth)
#define ipsec_check_esp(in, cipher, auth) \
	ipsec_check(in, false, cipher, auth)

#endif
