/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <unistd.h>

#include "ipsec.h"

#include "test_vectors.h"

struct suite_context_s suite_context;

#define PKT_POOL_NUM  64
#define PKT_POOL_LEN  (1 * 1024)

int ipsec_check(odp_bool_t in, odp_bool_t ah,
		odp_cipher_alg_t cipher,
		odp_auth_alg_t auth)
{
	odp_ipsec_capability_t capa;

	if (odp_ipsec_capability(&capa) < 0)
		return ODP_TEST_INACTIVE;

	if ((ODP_IPSEC_OP_MODE_SYNC == suite_context.pref_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_sync) ||
	    (ODP_IPSEC_OP_MODE_ASYNC == suite_context.pref_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_async) ||
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.pref_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_inline_in && in) ||
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.pref_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_inline_out && !in))
		return ODP_TEST_INACTIVE;

	if (ah && (ODP_SUPPORT_NO == capa.proto_ah))
		return ODP_TEST_INACTIVE;

	/* Cipher algorithms */
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		if (!capa.ciphers.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_DES:
		if (!capa.ciphers.bit.des)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		if (!capa.ciphers.bit.trides_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (!capa.ciphers.bit.aes_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (!capa.ciphers.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported cipher algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	/* Authentication algorithms */
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		if (!capa.auths.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		if (!capa.auths.bit.md5_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		if (!capa.auths.bit.sha1_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		if (!capa.auths.bit.sha256_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (!capa.auths.bit.sha512_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (!capa.auths.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

void ipsec_sa_param_fill(odp_ipsec_sa_param_t *param,
			 odp_bool_t in,
			 odp_bool_t ah,
			 uint32_t spi,
			 odp_ipsec_tunnel_param_t *tun,
			 odp_cipher_alg_t cipher_alg,
			 const odp_crypto_key_t *cipher_key,
			 odp_auth_alg_t auth_alg,
			 const odp_crypto_key_t *auth_key)
{
	odp_ipsec_sa_param_init(param);
	param->dir = in ? ODP_IPSEC_DIR_INBOUND :
			  ODP_IPSEC_DIR_OUTBOUND;
	param->lookup_mode = in ? ODP_IPSEC_LOOKUP_SPI :
				  ODP_IPSEC_LOOKUP_DISABLED;
	param->proto = ah ? ODP_IPSEC_AH :
			    ODP_IPSEC_ESP;

	if (tun) {
		param->mode = ODP_IPSEC_MODE_TUNNEL;
		param->tunnel = *tun;
	} else {
		param->mode = ODP_IPSEC_MODE_TRANSPORT;
	}

	param->spi = spi;
	param->seq = 0;

	param->dest_queue = suite_context.queue;

	if (cipher_key) {
		param->crypto.cipher_alg = cipher_alg;
		param->crypto.cipher_key = *cipher_key;
	}

	if (auth_key) {
		param->crypto.auth_alg = auth_alg;
		param->crypto.auth_key = *auth_key;
	}
}

void ipsec_sa_destroy(odp_ipsec_sa_t sa)
{
	odp_event_t event;
	odp_ipsec_status_t status;

	CU_ASSERT_EQUAL(ODP_IPSEC_OK, odp_ipsec_sa_disable(sa));

	if (ODP_QUEUE_INVALID != suite_context.queue) {
		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT_EQUAL(ODP_EVENT_IPSEC_STATUS, odp_event_type(event));

		CU_ASSERT_EQUAL(ODP_IPSEC_OK, odp_ipsec_status(&status, event));

		CU_ASSERT_EQUAL(ODP_IPSEC_STATUS_SA_DISABLE, status.id);
		CU_ASSERT_EQUAL(0, status.ret);
		CU_ASSERT_EQUAL(sa, status.sa);

		odp_event_free(event);
	}

	CU_ASSERT_EQUAL(ODP_IPSEC_OK, odp_ipsec_sa_destroy(sa));
}

#define PACKET_USER_PTR	((void *)0x1212fefe)

odp_packet_t ipsec_packet(const ipsec_test_packet *itp)
{
	odp_packet_t pkt = odp_packet_alloc(suite_context.pool, itp->len);

	CU_ASSERT_NOT_EQUAL(ODP_PACKET_INVALID, pkt);
	if (ODP_PACKET_INVALID == pkt)
		return pkt;

	CU_ASSERT_EQUAL(0, odp_packet_copy_from_mem(pkt, 0, itp->len,
						    itp->data));
	if (itp->l2_offset != ODP_PACKET_OFFSET_INVALID)
		CU_ASSERT_EQUAL(0, odp_packet_l2_offset_set(pkt,
							    itp->l2_offset));
	if (itp->l3_offset != ODP_PACKET_OFFSET_INVALID)
		CU_ASSERT_EQUAL(0, odp_packet_l3_offset_set(pkt,
							    itp->l3_offset));
	if (itp->l4_offset != ODP_PACKET_OFFSET_INVALID)
		CU_ASSERT_EQUAL(0, odp_packet_l4_offset_set(pkt,
							    itp->l4_offset));

	odp_packet_user_ptr_set(pkt, PACKET_USER_PTR);

	return pkt;
}

/*
 * Compare packages ignoring everything before L3 header
 */
odp_bool_t ipsec_check_packet(const ipsec_test_packet *itp, odp_packet_t pkt)
{
	uint32_t len = (ODP_PACKET_INVALID == pkt) ? 1 : odp_packet_len(pkt);
	uint32_t l3, l4;
	uint8_t data[len];

	if (!itp)
		return true;

	if (ODP_PACKET_INVALID == pkt)
		return false;

	CU_ASSERT_EQUAL(PACKET_USER_PTR, odp_packet_user_ptr(pkt));

	l3 = odp_packet_l3_offset(pkt);
	l4 = odp_packet_l4_offset(pkt);
	odp_packet_copy_to_mem(pkt, 0, len, data);

	if (len - l3 != itp->len - itp->l3_offset)
		return false;

	if (l4 - l3 != itp->l4_offset - itp->l3_offset)
		return false;

	return memcmp(data + l3,
		      itp->data + itp->l3_offset,
		      len - l3) ? false : true;
}

void ipsec_check_in_one(const ipsec_test_part *part, odp_ipsec_sa_t sa)
{
	odp_ipsec_op_param_t op_param;
	odp_ipsec_op_result_t op_result;
	odp_packet_t pkt;
	odp_packet_t pkto[part->out_pkt];
	odp_ipsec_packet_result_t result[part->out_pkt];
	int i;

	pkt = ipsec_packet(part->pkt_in);

	memset(&op_param, 0, sizeof(op_param));
	op_param.num_pkt = 1;
	op_param.pkt = &pkt;
	if (ODP_IPSEC_SA_INVALID != sa) {
		op_param.num_sa = 1;
		op_param.sa = &sa;
	} else {
		op_param.num_sa = 0;
		op_param.sa = NULL;
	}
	op_param.num_opt = 0;
	op_param.opt = NULL;

	op_result.num_pkt = part->out_pkt;
	op_result.pkt = pkto;
	op_result.res = result;

	if (ODP_IPSEC_OP_MODE_SYNC == suite_context.pref_mode) {
		CU_ASSERT_EQUAL(part->out_pkt, odp_ipsec_in(&op_param,
							    &op_result));
	} else if (ODP_IPSEC_OP_MODE_ASYNC == suite_context.pref_mode) {
		odp_event_t event;

		CU_ASSERT_EQUAL(1, odp_ipsec_in_enq(&op_param));

		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT_EQUAL(ODP_EVENT_IPSEC_RESULT,
				odp_event_type(event));
		CU_ASSERT_EQUAL(part->out_pkt,
				odp_ipsec_result(&op_result, event));
	} else {
		CU_FAIL("INLINE not supported");
	}

	CU_ASSERT_EQUAL(part->out_pkt, op_result.num_pkt);

	for (i = 0; i < op_result.num_pkt && i < part->out_pkt; i++) {
		CU_ASSERT_EQUAL(part->out[i].status.all_error,
				result[i].status.all_error);
		CU_ASSERT_EQUAL(sa, result[i].sa);
		if (ODP_PACKET_INVALID == pkto[i]) {
			CU_FAIL("ODP_PACKET_INVALID received");
		} else {
			CU_ASSERT(ipsec_check_packet(part->out[i].pkt_out,
						     pkto[i]));
			odp_packet_free(pkto[i]);
		}
	}
}

void ipsec_check_out_one(const ipsec_test_part *part, odp_ipsec_sa_t sa)
{
	odp_ipsec_op_param_t op_param;
	odp_ipsec_op_result_t op_result;
	odp_packet_t pkt;
	odp_packet_t pkto[part->out_pkt];
	odp_ipsec_packet_result_t result[part->out_pkt];
	int i;

	pkt = ipsec_packet(part->pkt_in);

	memset(&op_param, 0, sizeof(op_param));
	op_param.num_pkt = 1;
	op_param.pkt = &pkt;
	op_param.num_sa = 1;
	op_param.sa = &sa;
	op_param.num_opt = 0;
	op_param.opt = NULL;

	op_result.num_pkt = part->out_pkt;
	op_result.pkt = pkto;
	op_result.res = result;

	if (ODP_IPSEC_OP_MODE_SYNC == suite_context.pref_mode) {
		CU_ASSERT_EQUAL(part->out_pkt,
				odp_ipsec_out(&op_param, &op_result));
	} else if (ODP_IPSEC_OP_MODE_ASYNC == suite_context.pref_mode) {
		odp_event_t event;

		CU_ASSERT_EQUAL(1, odp_ipsec_out_enq(&op_param));

		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT_EQUAL(ODP_EVENT_IPSEC_RESULT,
				odp_event_type(event));
		CU_ASSERT_EQUAL(part->out_pkt,
				odp_ipsec_result(&op_result, event));
	} else {
		CU_FAIL("INLINE not supported");
	}

	CU_ASSERT_EQUAL(part->out_pkt, op_result.num_pkt);

	for (i = 0; i < op_result.num_pkt && i < part->out_pkt; i++) {
		CU_ASSERT_EQUAL(part->out[i].status.all_error,
				result[i].status.all_error);
		CU_ASSERT_EQUAL(sa, result[i].sa);
		if (ODP_PACKET_INVALID == pkto[i]) {
			CU_FAIL("ODP_PACKET_INVALID received");
		} else {
			CU_ASSERT(ipsec_check_packet(part->out[i].pkt_out,
						     pkto[i]));
			odp_packet_free(pkto[i]);
		}
	}
}

void ipsec_check_out_in_one(const ipsec_test_part *part,
			    odp_ipsec_sa_t sa,
			    odp_ipsec_sa_t sa_in)
{
	odp_ipsec_op_param_t op_param;
	odp_ipsec_op_result_t op_result;
	odp_packet_t pkt;
	odp_packet_t pkto[part->out_pkt];
	odp_ipsec_packet_result_t result[part->out_pkt];
	int i;

	pkt = ipsec_packet(part->pkt_in);

	memset(&op_param, 0, sizeof(op_param));
	op_param.num_pkt = 1;
	op_param.pkt = &pkt;
	op_param.num_sa = 1;
	op_param.sa = &sa;
	op_param.num_opt = 0;
	op_param.opt = NULL;

	op_result.num_pkt = part->out_pkt;
	op_result.pkt = pkto;
	op_result.res = result;

	if (ODP_IPSEC_OP_MODE_SYNC == suite_context.pref_mode) {
		CU_ASSERT_EQUAL(part->out_pkt,
				odp_ipsec_out(&op_param, &op_result));
	} else if (ODP_IPSEC_OP_MODE_ASYNC == suite_context.pref_mode) {
		odp_event_t event;

		CU_ASSERT_EQUAL(1, odp_ipsec_out_enq(&op_param));

		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT_EQUAL(ODP_EVENT_IPSEC_RESULT,
				odp_event_type(event));
		CU_ASSERT_EQUAL(part->out_pkt,
				odp_ipsec_result(&op_result, event));
	} else {
		CU_FAIL("INLINE not supported");
	}

	CU_ASSERT_EQUAL(part->out_pkt, op_result.num_pkt);

	for (i = 0; i < op_result.num_pkt && i < part->out_pkt; i++) {
		CU_ASSERT_EQUAL(part->out[i].status.all_error,
				result[i].status.all_error);
		CU_ASSERT_EQUAL(sa, result[i].sa);
		if (ODP_PACKET_INVALID == pkto[i]) {
			CU_FAIL("ODP_PACKET_INVALID received");
		} else {
			ipsec_test_part part_in = *part;
			ipsec_test_packet pkt_in;

			CU_ASSERT_FATAL(odp_packet_len(pkto[i]) <=
					sizeof(pkt_in.data));

			pkt_in.len = odp_packet_len(pkto[i]);
			pkt_in.l2_offset = odp_packet_l2_offset(pkto[i]);
			pkt_in.l3_offset = odp_packet_l3_offset(pkto[i]);
			pkt_in.l4_offset = odp_packet_l4_offset(pkto[i]);
			odp_packet_copy_to_mem(pkto[i], 0,
					       pkt_in.len,
					       pkt_in.data);
			part_in.pkt_in = &pkt_in;
			ipsec_check_in_one(&part_in, sa_in);
			odp_packet_free(pkto[i]);
		}
	}
}

static
void ipsec_test_capability(void)
{
	odp_ipsec_capability_t capa;

	CU_ASSERT(odp_ipsec_capability(&capa) == 0);
}

odp_testinfo_t ipsec_suite[] = {
	ODP_TEST_INFO(ipsec_test_capability),
	ODP_TEST_INFO_NULL
};

static
int ODP_UNUSED ipsec_sync_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	suite_context.pref_mode = ODP_IPSEC_OP_MODE_SYNC;
	return 0;
}

static
int ODP_UNUSED ipsec_async_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;
	suite_context.queue = odp_queue_lookup("ipsec-out");
	if (suite_context.queue == ODP_QUEUE_INVALID)
		return -1;

	suite_context.pref_mode = ODP_IPSEC_OP_MODE_ASYNC;
	return 0;
}

static
int ipsec_suite_term(odp_testinfo_t *suite)
{
	int i;
	int first = 1;

	for (i = 0; suite[i].pName; i++) {
		if (suite[i].check_active &&
		    suite[i].check_active() == ODP_TEST_INACTIVE) {
			if (first) {
				first = 0;
				printf("\n\n  Inactive tests:\n");
			}
			printf("    %s\n", suite[i].pName);
		}
	}

	return 0;
}

static
int ipsec_in_term(void)
{
	return ipsec_suite_term(ipsec_in_suite);
}

static
int ipsec_out_term(void)
{
	return ipsec_suite_term(ipsec_out_suite);
}

odp_suiteinfo_t ipsec_suites[] = {
	{"IPsec", NULL, NULL, ipsec_suite},
	{"IPsec-sync-in", ipsec_sync_init, ipsec_in_term, ipsec_in_suite},
	{"IPsec-async-in", ipsec_async_init, ipsec_in_term, ipsec_in_suite},
	{"IPsec-sync-out", ipsec_sync_init, ipsec_out_term, ipsec_out_suite},
	{"IPsec-async-out", ipsec_async_init, ipsec_out_term, ipsec_out_suite},
	ODP_SUITE_INFO_NULL,
};

static
int ipsec_outit(odp_instance_t *inst)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_queue_t out_queue;
	odp_pool_capability_t pool_capa;

	if (0 != odp_init_global(inst, NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		fprintf(stderr, "error: odp_pool_capability() failed.\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_LEN;
	params.pkt.len     = PKT_POOL_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	if (pool_capa.pkt.max_seg_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_seg_len) {
		fprintf(stderr, "Warning: small packet segment length\n");
		params.pkt.seg_len = pool_capa.pkt.max_seg_len;
	}

	if (pool_capa.pkt.max_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_len) {
		fprintf(stderr, "Pool max packet length too small\n");
		return -1;
	}

	pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}
	out_queue = odp_queue_create("ipsec-out", NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}

	return 0;
}

static
int ipsec_term(odp_instance_t inst)
{
	odp_pool_t pool;
	odp_queue_t out_queue;

	out_queue = odp_queue_lookup("ipsec-out");
	if (ODP_QUEUE_INVALID != out_queue) {
		if (odp_queue_destroy(out_queue))
			fprintf(stderr, "Crypto outq destroy failed.\n");
	} else {
		fprintf(stderr, "Crypto outq not found.\n");
	}

	pool = odp_pool_lookup("packet_pool");
	if (ODP_POOL_INVALID != pool) {
		if (odp_pool_destroy(pool))
			fprintf(stderr, "Packet pool destroy failed.\n");
	} else {
		fprintf(stderr, "Packet pool not found.\n");
	}

	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

int ipsec_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(ipsec_outit);
	odp_cunit_register_global_term(ipsec_term);

	ret = odp_cunit_register(ipsec_suites);
	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
