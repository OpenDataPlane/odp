/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

#include <string.h>
#include <stdlib.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp_cunit_common.h>
#include "test_vectors.h"
#include "test_vector_defs.h"
#include "crypto_op_test.h"
#include "util.h"

/*
 * If nonzero, run time consuming tests too.
 * Set through FULL_TEST environment variable.
 */
static int full_test;

#define MAX_FAILURE_PRINTS 20

#define PKT_POOL_NUM  64
#define PKT_POOL_LEN  1200 /* enough for a test packet and some headroom */
#define UAREA_SIZE 8

static void test_defaults(uint8_t fill)
{
	odp_crypto_session_param_t param;

	memset(&param, fill, sizeof(param));
	odp_crypto_session_param_init(&param);

	CU_ASSERT(param.op == ODP_CRYPTO_OP_ENCODE);
	CU_ASSERT(param.op_type == ODP_CRYPTO_OP_TYPE_LEGACY);
	CU_ASSERT(param.cipher_range_in_bits == false);
	CU_ASSERT(param.auth_range_in_bits == false);
	CU_ASSERT(param.auth_cipher_text == false);
	CU_ASSERT(param.null_crypto_enable == false);
	CU_ASSERT(param.op_mode == ODP_CRYPTO_SYNC);
	CU_ASSERT(param.cipher_alg == ODP_CIPHER_ALG_NULL);
	CU_ASSERT(param.cipher_iv_len == 0);
	CU_ASSERT(param.auth_alg == ODP_AUTH_ALG_NULL);
	CU_ASSERT(param.auth_iv_len == 0);
	CU_ASSERT(param.auth_aad_len == 0);
}

static void test_default_values(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

static void print_alg_test_param(const crypto_op_test_param_t *p)
{
	const char *cipher_mode = p->session.cipher_range_in_bits ? "bit" : "byte";
	const char *auth_mode   = p->session.auth_range_in_bits   ? "bit" : "byte";

	switch (p->session.op_type) {
	case ODP_CRYPTO_OP_TYPE_LEGACY:
		printf("legacy ");
		break;
	case ODP_CRYPTO_OP_TYPE_BASIC:
		printf("basic ");
		break;
	case ODP_CRYPTO_OP_TYPE_OOP:
		printf("out-of-place ");
		break;
	case ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP:
		printf("basic-and-out-of-place (%s)",
		       p->op_type == ODP_CRYPTO_OP_TYPE_BASIC ? "basic" : "oop");
		break;
	default:
		printf("unknown (internal error) ");
		break;
	}
	printf("%s\n", p->session.op == ODP_CRYPTO_OP_ENCODE ? "encode" : "decode");

	printf("cipher: %s, %s mode\n", cipher_alg_name(p->ref->cipher), cipher_mode);
	printf("  key length: %d, iv length: %d\n",
	       p->ref->cipher_key_length, p->ref->cipher_iv_length);
	printf("  range: offset %d, length %d\n",
	       p->cipher_range.offset, p->cipher_range.length);

	printf("auth: %s, %s mode\n", auth_alg_name(p->ref->auth), auth_mode);
	printf("  key length: %d, iv length: %d\n",
	       p->ref->auth_key_length, p->ref->auth_iv_length);
	printf("  range: offset %d, length %d; aad length: %d\n",
	       p->auth_range.offset, p->auth_range.length, p->ref->aad_length);
	printf("  digest offset: %d, digest length %d\n",
	       p->digest_offset, p->ref->digest_length);

	if (p->wrong_digest)
		printf("wrong digest test\n");
	printf("header length: %d, trailer length: %d\n", p->header_len, p->trailer_len);
	if (p->adjust_segmentation)
		printf("segmentation adjusted, first_seg_len: %d\n", p->first_seg_len);
	if (p->op_type == ODP_CRYPTO_OP_TYPE_OOP)
		printf("oop_shift: %d\n", p->oop_shift);
	if (p->session.null_crypto_enable)
		printf("null crypto enabled in session\n");
	if (p->null_crypto)
		printf("null crypto requested\n");
}

static void alg_test_execute_and_print(crypto_op_test_param_t *param)
{
	static int print_limit = MAX_FAILURE_PRINTS;
	unsigned int num = CU_get_number_of_failures();

	test_crypto_op(param);

	if (CU_get_number_of_failures() > num) {
		if (print_limit > 0) {
			printf("\nTest failed:\n");
			print_alg_test_param(param);
			printf("\n");
			print_limit--;
			if (print_limit == 0)
				printf("Suppressing further failure output\n");
		}
	}
}

static void alg_test_op2(crypto_op_test_param_t *param)
{
	int32_t oop_shifts[] = {0, 3, 130, -10};

	for (uint32_t n = 0; n < ODPH_ARRAY_SIZE(oop_shifts); n++) {
		if (oop_shifts[n] != 0 &&
		    param->op_type != ODP_CRYPTO_OP_TYPE_OOP)
			continue;
		if ((int32_t)param->header_len + oop_shifts[n] < 0)
			continue;
		param->oop_shift = oop_shifts[n];

		param->wrong_digest = false;
		alg_test_execute_and_print(param);

		param->null_crypto = true;
		alg_test_execute_and_print(param);
		param->null_crypto = false;

		if (full_test)
			alg_test_execute_and_print(param); /* rerun with the same parameters */

		if (!full_test && param->session.null_crypto_enable)
			break;
		if (!full_test && param->session.op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP)
			break;

		param->wrong_digest = true;
		alg_test_execute_and_print(param);
	}
}

static void alg_test_op(crypto_op_test_param_t *param)
{
	param->op_type = param->session.op_type;
	if (param->op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP) {
		param->op_type = ODP_CRYPTO_OP_TYPE_BASIC;
		alg_test_op2(param);
		param->op_type = ODP_CRYPTO_OP_TYPE_OOP;
	}
	alg_test_op2(param);
}

static int combo_warning_shown;
static int oop_warning_shown;

typedef enum {
	HASH_NO_OVERLAP,
	HASH_OVERLAP,
} hash_test_mode_t;

typedef enum {
	AUTH_CIPHERTEXT,
	AUTH_PLAINTEXT
} alg_order_t;

static int session_create(crypto_session_t *session,
			  alg_order_t order,
			  crypto_test_reference_t *ref,
			  hash_test_mode_t hash_mode,
			  odp_bool_t must_fail)
{
	int rc;
	odp_crypto_ses_create_err_t status;
	odp_crypto_session_param_t ses_params;
	uint8_t cipher_key_data[MAX_KEY_LEN];
	uint8_t auth_key_data[MAX_KEY_LEN];
	odp_crypto_key_t cipher_key = {
		.data = cipher_key_data,
		.length = ref->cipher_key_length
	};
	odp_crypto_key_t auth_key = {
		.data = auth_key_data,
		.length = ref->auth_key_length
	};

	memcpy(cipher_key_data, ref->cipher_key, ref->cipher_key_length);
	memcpy(auth_key_data, ref->auth_key, ref->auth_key_length);

	/* Create a crypto session */
	odp_crypto_session_param_init(&ses_params);
	ses_params.op = session->op;
	ses_params.op_type = session->op_type;
	ses_params.cipher_range_in_bits = session->cipher_range_in_bits;
	ses_params.auth_range_in_bits = session->auth_range_in_bits;
	ses_params.auth_cipher_text = (order == AUTH_CIPHERTEXT);
	ses_params.null_crypto_enable = session->null_crypto_enable;
	ses_params.op_mode = suite_context.op_mode;
	ses_params.cipher_alg = ref->cipher;
	ses_params.auth_alg = ref->auth;
	ses_params.compl_queue = suite_context.queue;
	ses_params.output_pool = suite_context.pool;
	ses_params.cipher_key = cipher_key;
	ses_params.cipher_iv_len = ref->cipher_iv_length;
	ses_params.auth_iv_len = ref->auth_iv_length;
	ses_params.auth_key = auth_key;
	ses_params.auth_digest_len = ref->digest_length;
	ses_params.auth_aad_len = ref->aad_length;
	ses_params.hash_result_in_auth_range = (hash_mode == HASH_OVERLAP);
	rc = odp_crypto_session_create(&ses_params, &session->session, &status);

	if (must_fail) {
		CU_ASSERT(rc < 0);
		if (rc == 0) {
			rc = odp_crypto_session_destroy(session->session);
			CU_ASSERT(rc == 0);
		}
		return -1;
	}

	if (rc < 0 && status == ODP_CRYPTO_SES_ERR_ALG_COMBO) {
		if (!combo_warning_shown) {
			combo_warning_shown = 1;
			printf("\n    Unsupported algorithm combination: %s, %s\n",
			       cipher_alg_name(ref->cipher),
			       auth_alg_name(ref->auth));
		}
		return -1;
	}

	/*
	 * Allow ODP_CRYPTO_SES_ERR_ALG_ORDER only in async op mode.
	 * In sync mode an implementation should be able to support both
	 * orders without much difficulty.
	 */
	if (rc < 0 && status == ODP_CRYPTO_SES_ERR_ALG_ORDER &&
	    ses_params.op_mode == ODP_CRYPTO_ASYNC) {
		printf("\n    Unsupported algorithm order: %s, %s, auth_cipher_text: %d\n",
		       cipher_alg_name(ref->cipher),
		       auth_alg_name(ref->auth),
		       ses_params.auth_cipher_text);
		return -1;
	}

	/* For now, allow out-of-place sessions not to be supported. */
	if (rc < 0 && status == ODP_CRYPTO_SES_ERR_PARAMS &&
	    (ses_params.op_type == ODP_CRYPTO_OP_TYPE_OOP ||
	     ses_params.op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP)) {
		if (!oop_warning_shown)
			printf("\n    Skipping out-of-place tests\n");
		oop_warning_shown = 1;
		return -1;
	}

	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_ERR_NONE);
	CU_ASSERT(odp_crypto_session_to_u64(session->session) !=
		  odp_crypto_session_to_u64(ODP_CRYPTO_SESSION_INVALID));

	/*
	 * Clear session creation parameters so that we might notice if
	 * the implementation still tried to use them.
	 */
	memset(cipher_key_data, 0, sizeof(cipher_key_data));
	memset(auth_key_data, 0, sizeof(auth_key_data));
	memset(&ses_params, 0, sizeof(ses_params));

	return 0;
}

static void alg_test_ses(odp_crypto_op_t op,
			 odp_crypto_op_type_t op_type,
			 alg_order_t order,
			 crypto_test_reference_t *ref,
			 odp_packet_data_range_t cipher_range,
			 odp_packet_data_range_t auth_range,
			 uint32_t digest_offset,
			 odp_bool_t cipher_range_in_bits,
			 odp_bool_t auth_range_in_bits,
			 odp_bool_t null_crypto_enable,
			 odp_bool_t session_creation_must_fail)
{
	unsigned int initial_num_failures = CU_get_number_of_failures();
	const uint32_t reflength = ref_length_in_bytes(ref);
	const uint32_t auth_scale = auth_range_in_bits ? 8 : 1;
	hash_test_mode_t hash_mode = HASH_NO_OVERLAP;
	int rc;
	uint32_t seg_len;
	uint32_t max_shift;
	crypto_op_test_param_t test_param;

	if (null_crypto_enable && suite_context.op_mode == ODP_CRYPTO_SYNC)
		return;

	if (digest_offset * auth_scale >= auth_range.offset &&
	    digest_offset * auth_scale < auth_range.offset + auth_range.length)
		hash_mode = HASH_OVERLAP;

	memset(&test_param, 0, sizeof(test_param));
	test_param.session.op = op;
	test_param.session.op_type = op_type;
	test_param.session.cipher_range_in_bits = cipher_range_in_bits;
	test_param.session.auth_range_in_bits = auth_range_in_bits;
	test_param.session.null_crypto_enable = null_crypto_enable;
	if (session_create(&test_param.session, order, ref, hash_mode, session_creation_must_fail))
		return;
	test_param.ref = ref;
	test_param.cipher_range = cipher_range;
	test_param.auth_range = auth_range;
	test_param.digest_offset = digest_offset;

	alg_test_op(&test_param);

	max_shift = reflength + ref->digest_length;
	seg_len = 0;

	if (!full_test)
		if ((ref->cipher != ODP_CIPHER_ALG_NULL &&
		     ref->auth != ODP_AUTH_ALG_NULL) ||
		    test_param.session.null_crypto_enable ||
		    test_param.session.op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP) {
			/* run the loop body just once */
			seg_len = max_shift / 2;
			max_shift = seg_len;
		}

	/*
	 * Test with segmented packets with all possible segment boundaries
	 * within the packet data
	 */
	for (; seg_len <= max_shift; seg_len++) {
		/*
		 * CUnit chokes on too many assertion failures, so bail
		 * out if this test has already failed.
		 */
		if (CU_get_number_of_failures() > initial_num_failures)
			break;

		test_param.adjust_segmentation = true;
		test_param.first_seg_len = seg_len;
		test_param.header_len = 0;
		test_param.trailer_len = 0;
		test_param.digest_offset = digest_offset;
		alg_test_op(&test_param);

		/* Test partial packet crypto with odd alignment. */
		test_param.header_len = 13;
		test_param.trailer_len = 32;
		test_param.digest_offset = test_param.header_len + digest_offset;
		alg_test_op(&test_param);
	}

	rc = odp_crypto_session_destroy(test_param.session.session);
	CU_ASSERT(!rc);
}

static void alg_test_op_types(odp_crypto_op_t op,
			      alg_order_t order,
			      crypto_test_reference_t *ref,
			      odp_packet_data_range_t cipher_range,
			      odp_packet_data_range_t auth_range,
			      uint32_t digest_offset,
			      odp_bool_t cipher_range_in_bits,
			      odp_bool_t auth_range_in_bits,
			      odp_bool_t session_creation_must_fail)
{
	odp_crypto_op_type_t op_types[] = {
		ODP_CRYPTO_OP_TYPE_LEGACY,
		ODP_CRYPTO_OP_TYPE_BASIC,
		ODP_CRYPTO_OP_TYPE_OOP,
		ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP,
	};

	for (unsigned int n = 0; n < ODPH_ARRAY_SIZE(op_types); n++) {
		for (unsigned int null_crypto = 0 ; null_crypto <= 1; null_crypto++)
			alg_test_ses(op,
				     op_types[n],
				     order,
				     ref,
				     cipher_range,
				     auth_range,
				     digest_offset,
				     cipher_range_in_bits,
				     auth_range_in_bits,
				     null_crypto,
				     session_creation_must_fail);
	}
}

static void alg_test(odp_crypto_op_t op,
		     alg_order_t order,
		     crypto_test_reference_t *ref,
		     odp_packet_data_range_t cipher_bit_range,
		     odp_packet_data_range_t auth_bit_range,
		     uint32_t digest_offset,
		     odp_bool_t is_bit_mode_cipher,
		     odp_bool_t is_bit_mode_auth)
{
	odp_packet_data_range_t cipher_range;
	odp_packet_data_range_t auth_range;

	for (int cr_in_bits = 0; cr_in_bits <= 1; cr_in_bits++) {
		if (!cr_in_bits && cipher_bit_range.length % 8 != 0)
			continue;
		for (int ar_in_bits = 0; ar_in_bits <= 1; ar_in_bits++) {
			odp_bool_t session_creation_must_fail;

			if (!ar_in_bits && auth_bit_range.length % 8 != 0)
				continue;

			cipher_range = cipher_bit_range;
			auth_range = auth_bit_range;
			if (!cr_in_bits) {
				cipher_range.offset /= 8;
				cipher_range.length /= 8;
			}
			if (!ar_in_bits) {
				auth_range.offset /= 8;
				auth_range.length /= 8;
			}
			session_creation_must_fail = ((ar_in_bits && !is_bit_mode_auth) ||
						      (cr_in_bits && !is_bit_mode_cipher));
			alg_test_op_types(op, order, ref, cipher_range, auth_range,
					  digest_offset, cr_in_bits, ar_in_bits,
					  session_creation_must_fail);
		}
	}
}

static odp_bool_t aad_len_ok(const odp_crypto_auth_capability_t *capa, uint32_t len)
{
	if (len < capa->aad_len.min || len > capa->aad_len.max)
		return false;

	if (len == capa->aad_len.min)
		return true;
	if (capa->aad_len.inc == 0)
		return false;

	return ((len - capa->aad_len.min) % capa->aad_len.inc) == 0;
}

static void check_alg(odp_crypto_op_t op,
		      crypto_test_reference_t *ref,
		      size_t count)
{
	int rc, i;
	const odp_cipher_alg_t cipher_alg = ref->cipher;
	const odp_auth_alg_t auth_alg = ref->auth;
	int cipher_num = odp_crypto_cipher_capability(cipher_alg, NULL, 0);
	int auth_num = odp_crypto_auth_capability(auth_alg, NULL, 0);
	odp_bool_t cipher_ok = false;
	odp_bool_t auth_ok = false;
	size_t idx;

	CU_ASSERT_FATAL(cipher_num > 0);
	CU_ASSERT_FATAL(auth_num > 0);

	init_reference(ref, count);

	odp_crypto_cipher_capability_t cipher_capa[cipher_num];
	odp_crypto_auth_capability_t auth_capa[auth_num];
	odp_bool_t cipher_tested[cipher_num];
	odp_bool_t auth_tested[auth_num];

	rc = odp_crypto_cipher_capability(cipher_alg, cipher_capa, cipher_num);
	CU_ASSERT_FATAL(rc == cipher_num);

	rc = odp_crypto_auth_capability(auth_alg, auth_capa, auth_num);
	CU_ASSERT_FATAL(rc == auth_num);

	memset(cipher_tested, 0, sizeof(cipher_tested));
	memset(auth_tested, 0, sizeof(auth_tested));

	oop_warning_shown = 0; /* allow OOP-unsupported warning again */

	for (idx = 0; idx < count; idx++) {
		int cipher_idx = -1, auth_idx = -1;
		odp_bool_t is_bit_mode_cipher = false;
		odp_bool_t is_bit_mode_auth = false;
		uint32_t digest_offs = ref_length_in_bytes(&ref[idx]);
		odp_packet_data_range_t cipher_bit_range = {.offset = 0};
		odp_packet_data_range_t auth_bit_range = {.offset = 0};

		for (i = 0; i < cipher_num; i++) {
			if (cipher_capa[i].key_len ==
			    ref[idx].cipher_key_length &&
			    cipher_capa[i].iv_len ==
			    ref[idx].cipher_iv_length) {
				cipher_idx = i;
				is_bit_mode_cipher = cipher_capa[i].bit_mode;
				break;
			}
		}

		if (cipher_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 "\n",
			       cipher_alg_name(cipher_alg),
			       ref[idx].cipher_key_length,
			       ref[idx].cipher_iv_length);
			continue;
		}

		for (i = 0; i < auth_num; i++) {
			if (auth_capa[i].digest_len ==
			    ref[idx].digest_length &&
			    auth_capa[i].iv_len ==
			    ref[idx].auth_iv_length &&
			    auth_capa[i].key_len ==
			    ref[idx].auth_key_length &&
			    aad_len_ok(&auth_capa[i], ref[idx].aad_length)) {
				auth_idx = i;
				is_bit_mode_auth = auth_capa[i].bit_mode;
				break;
			}
		}

		if (auth_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 ", digest_len=%" PRIu32
			       "\n",
			       auth_alg_name(auth_alg),
			       ref[idx].auth_key_length,
			       ref[idx].auth_iv_length,
			       ref[idx].digest_length);
			continue;
		}

		cipher_bit_range.length = ref_length_in_bits(&ref[idx]);
		auth_bit_range.length = ref_length_in_bits(&ref[idx]);

		alg_test(op, AUTH_PLAINTEXT, &ref[idx],
			 cipher_bit_range, auth_bit_range, digest_offs,
			 is_bit_mode_cipher, is_bit_mode_auth);
		alg_test(op, AUTH_CIPHERTEXT, &ref[idx],
			 cipher_bit_range, auth_bit_range, digest_offs,
			 is_bit_mode_cipher, is_bit_mode_auth);

		cipher_tested[cipher_idx] = true;
		auth_tested[auth_idx] = true;
	}

	for (i = 0; i < cipher_num; i++) {
		cipher_ok |= cipher_tested[i];
		if (!cipher_tested[i] && cipher_alg != ODP_CIPHER_ALG_NULL)
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "iv_len=%" PRIu32 "%s\n",
			       cipher_alg_name(cipher_alg),
			       cipher_capa[i].key_len,
			       cipher_capa[i].iv_len,
			       cipher_capa[i].bit_mode ? ", bit mode" : "");
	}

	for (i = 0; i < auth_num; i++) {
		auth_ok |= auth_tested[i];
		if (!auth_tested[i] && auth_alg != ODP_AUTH_ALG_NULL)
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "digest_len=%" PRIu32 "%s\n",
			       auth_alg_name(auth_alg),
			       auth_capa[i].key_len,
			       auth_capa[i].digest_len,
			       auth_capa[i].bit_mode ? ", bit mode" : "");
	}

	/* Verify that we were able to run at least one test */
	CU_ASSERT(cipher_ok);
	CU_ASSERT(auth_ok);
}

static void test_capability(void)
{
	odp_crypto_capability_t capa = {.max_sessions = 1};
	int rc;

	rc = odp_crypto_capability(&capa);
	CU_ASSERT(!rc);
	if (capa.max_sessions > 0)
		CU_ASSERT(capa.sync_mode || capa.async_mode);
	CU_ASSERT((~capa.ciphers.all_bits & capa.hw_ciphers.all_bits) == 0);
	CU_ASSERT((~capa.auths.all_bits & capa.hw_auths.all_bits) == 0);
}

/*
 * Create a test reference, which can be used in tests where the hash
 * result is within auth_range.
 *
 * The ciphertext packet and the hash are calculated using an encode
 * operation with hash_result_offset outside the auth_range and by
 * copying the hash in the ciphertext packet.
 */
static int create_hash_test_reference(odp_auth_alg_t auth,
				      const odp_crypto_auth_capability_t *capa,
				      crypto_test_reference_t *ref,
				      uint32_t digest_offset,
				      uint8_t digest_fill)
{
	crypto_session_t session;
	int rc;
	odp_packet_t pkt;
	odp_bool_t ok;
	const uint32_t auth_bytes = 100;
	uint32_t enc_digest_offset = auth_bytes;

	ref->cipher = ODP_CIPHER_ALG_NULL;
	ref->auth = auth;
	ref->auth_key_length = capa->key_len;
	ref->auth_iv_length = capa->iv_len;
	ref->digest_length = capa->digest_len;
	ref->is_length_in_bits = false;
	ref->length = auth_bytes;

	if (ref->auth_key_length > MAX_KEY_LEN ||
	    ref->auth_iv_length > MAX_IV_LEN ||
	    auth_bytes > MAX_DATA_LEN ||
	    digest_offset + ref->digest_length > MAX_DATA_LEN)
		CU_FAIL_FATAL("Internal error\n");

	fill_with_pattern(ref->auth_key, ref->auth_key_length);
	fill_with_pattern(ref->auth_iv, ref->auth_iv_length);
	fill_with_pattern(ref->plaintext, auth_bytes);

	memset(ref->plaintext + digest_offset, digest_fill, ref->digest_length);

	pkt = odp_packet_alloc(suite_context.pool, auth_bytes + ref->digest_length);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	rc = odp_packet_copy_from_mem(pkt, 0, auth_bytes, ref->plaintext);
	CU_ASSERT(rc == 0);

	session.op = ODP_CRYPTO_OP_ENCODE;
	session.op_type = ODP_CRYPTO_OP_TYPE_BASIC;
	session.cipher_range_in_bits = false;
	session.auth_range_in_bits = false;
	session.null_crypto_enable = false;
	if (session_create(&session, AUTH_PLAINTEXT, ref, HASH_NO_OVERLAP, false))
		return -1;

	odp_crypto_packet_op_param_t op_params = {
		.session = session.session,
		.cipher_iv_ptr = ref->cipher_iv,
		.auth_iv_ptr = ref->auth_iv,
		.hash_result_offset = enc_digest_offset,
		.aad_ptr = ref->aad,
		.cipher_range = {.offset = 0, .length = 0},
		.auth_range = { .offset = 0, .length = auth_bytes },
		.dst_offset_shift = 0,
	};
	rc = crypto_op(pkt, &pkt, &ok, &op_params,
		       ODP_CRYPTO_OP_TYPE_BASIC, ODP_CRYPTO_OP_TYPE_BASIC);

	CU_ASSERT(rc == 0);
	if (rc) {
		(void)odp_crypto_session_destroy(session.session);
		return -1;
	}
	CU_ASSERT(ok);

	rc = odp_crypto_session_destroy(session.session);
	CU_ASSERT(rc == 0);

	/* copy the processed packet to the ciphertext packet in ref */
	rc = odp_packet_copy_to_mem(pkt, 0, auth_bytes, ref->ciphertext);
	CU_ASSERT(rc == 0);

	/* copy the calculated digest in the ciphertext packet in ref */
	rc = odp_packet_copy_to_mem(pkt, enc_digest_offset, ref->digest_length,
				    &ref->ciphertext[digest_offset]);
	CU_ASSERT(rc == 0);

	/* copy the calculated digest the digest field in ref */
	rc = odp_packet_copy_to_mem(pkt, enc_digest_offset, ref->digest_length,
				    &ref->digest);
	CU_ASSERT(rc == 0);

	odp_packet_free(pkt);

	return 0;
}

static void test_auth_hash_in_auth_range(odp_auth_alg_t auth,
					 const odp_crypto_auth_capability_t *capa,
					 odp_bool_t is_bit_mode_cipher,
					 alg_order_t order)
{
	static crypto_test_reference_t ref = {.length = 0};
	uint32_t digest_offset = 13;
	const odp_packet_data_range_t cipher_bit_range = {.offset = 0, .length = 0};
	odp_packet_data_range_t auth_bit_range;

	if (!full_test && capa->digest_len % 4 != 0)
		return;

	/*
	 * Create test packets with auth hash in the authenticated range and
	 * zeroes in the hash location in the plaintext packet.
	 */
	if (create_hash_test_reference(auth, capa, &ref, digest_offset, 0))
		return;

	auth_bit_range.offset = 0;
	auth_bit_range.length = ref_length_in_bits(&ref);

	/*
	 * Decode the ciphertext packet.
	 *
	 * Check that auth hash verification works even if hash_result_offset
	 * is within the auth range. The ODP implementation must clear the
	 * hash bytes in the ciphertext packet before calculating the hash.
	 */
	alg_test(ODP_CRYPTO_OP_DECODE,
		 order,
		 &ref,
		 cipher_bit_range, auth_bit_range,
		 digest_offset,
		 is_bit_mode_cipher,
		 capa->bit_mode);

	/*
	 * Create test packets with auth hash in the authenticated range and
	 * ones in the hash location in the plaintext packet.
	 */
	if (create_hash_test_reference(auth, capa, &ref, digest_offset, 1))
		return;

	auth_bit_range.offset = 0;
	auth_bit_range.length = ref_length_in_bits(&ref);

	/*
	 * Encode the plaintext packet.
	 *
	 * Check that auth hash generation works even if hash_result_offset
	 * is within the auth range. The ODP implementation must not clear
	 * the hash bytes in the plaintext packet before calculating the hash.
	 */
	alg_test(ODP_CRYPTO_OP_ENCODE,
		 order,
		 &ref,
		 cipher_bit_range, auth_bit_range,
		 digest_offset,
		 is_bit_mode_cipher,
		 capa->bit_mode);
}

/*
 * Cipher algorithms that are not AEAD algorithms
 */
static odp_cipher_alg_t cipher_algs[] = {
	ODP_CIPHER_ALG_NULL,
	ODP_CIPHER_ALG_DES,
	ODP_CIPHER_ALG_3DES_CBC,
	ODP_CIPHER_ALG_3DES_ECB,
	ODP_CIPHER_ALG_AES_CBC,
	ODP_CIPHER_ALG_AES_CTR,
	ODP_CIPHER_ALG_AES_ECB,
	ODP_CIPHER_ALG_AES_CFB128,
	ODP_CIPHER_ALG_AES_XTS,
	ODP_CIPHER_ALG_KASUMI_F8,
	ODP_CIPHER_ALG_SNOW3G_UEA2,
	ODP_CIPHER_ALG_AES_EEA2,
	ODP_CIPHER_ALG_ZUC_EEA3,
};

/*
 * Authentication algorithms and hashes that may use auth_range
 * parameter. AEAD algorithms are excluded.
 */
static odp_auth_alg_t auth_algs[] = {
	ODP_AUTH_ALG_NULL,
	ODP_AUTH_ALG_MD5_HMAC,
	ODP_AUTH_ALG_SHA1_HMAC,
	ODP_AUTH_ALG_SHA224_HMAC,
	ODP_AUTH_ALG_SHA256_HMAC,
	ODP_AUTH_ALG_SHA384_HMAC,
	ODP_AUTH_ALG_SHA512_HMAC,
	ODP_AUTH_ALG_AES_GMAC,
	ODP_AUTH_ALG_AES_CMAC,
	ODP_AUTH_ALG_AES_XCBC_MAC,
	ODP_AUTH_ALG_KASUMI_F9,
	ODP_AUTH_ALG_SNOW3G_UIA2,
	ODP_AUTH_ALG_AES_EIA2,
	ODP_AUTH_ALG_ZUC_EIA3,
	ODP_AUTH_ALG_MD5,
	ODP_AUTH_ALG_SHA1,
	ODP_AUTH_ALG_SHA224,
	ODP_AUTH_ALG_SHA256,
	ODP_AUTH_ALG_SHA384,
	ODP_AUTH_ALG_SHA512,
};

static void test_auth_hashes_in_auth_range(void)
{
	for (size_t n = 0; n < ODPH_ARRAY_SIZE(auth_algs); n++) {
		odp_auth_alg_t auth = auth_algs[n];
		odp_crypto_cipher_capability_t c_capa;
		int num;

		if (check_alg_support(ODP_CIPHER_ALG_NULL, auth) == ODP_TEST_INACTIVE)
			continue;

		num = odp_crypto_cipher_capability(ODP_CIPHER_ALG_NULL, &c_capa, 1);
		CU_ASSERT_FATAL(num == 1);

		num = odp_crypto_auth_capability(auth, NULL, 0);
		CU_ASSERT_FATAL(num > 0);

		odp_crypto_auth_capability_t capa[num];

		num = odp_crypto_auth_capability(auth, capa, num);

		for (int i = 0; i < num; i++) {
			test_auth_hash_in_auth_range(auth, &capa[i], c_capa.bit_mode,
						     AUTH_PLAINTEXT);
			test_auth_hash_in_auth_range(auth, &capa[i], c_capa.bit_mode,
						     AUTH_CIPHERTEXT);
		}
	}
}

/*
 * Encode ref->plaintext and save result in ref->ciphertext.
 */
static int crypto_encode_ref(crypto_test_reference_t *ref,
			     odp_packet_data_range_t cipher_range,
			     odp_packet_data_range_t auth_range,
			     uint32_t hash_result_offset)
{
	odp_packet_data_range_t zero_range = {.offset = 0, .length = 0};
	odp_packet_t pkt;
	int rc;
	crypto_session_t session;
	odp_bool_t ok;

	pkt = odp_packet_alloc(suite_context.pool, ref->length);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	rc = odp_packet_copy_from_mem(pkt, 0, ref->length, ref->plaintext);
	CU_ASSERT(rc == 0);

	session.op = ODP_CRYPTO_OP_ENCODE;
	session.op_type = ODP_CRYPTO_OP_TYPE_BASIC;
	session.cipher_range_in_bits = false;
	session.auth_range_in_bits = false;
	session.null_crypto_enable = false;
	if (session_create(&session, AUTH_PLAINTEXT, ref, HASH_OVERLAP, false)) {
		odp_packet_free(pkt);
		return 1;
	}

	if (ref->cipher == ODP_CIPHER_ALG_NULL)
		cipher_range = zero_range;
	if (ref->auth == ODP_AUTH_ALG_NULL) {
		auth_range = zero_range;
		hash_result_offset = 0;
	}

	CU_ASSERT_FATAL(hash_result_offset + ref->digest_length <= ref->length);

	odp_crypto_packet_op_param_t op_params = {
		.session = session.session,
		.cipher_iv_ptr = ref->cipher_iv,
		.auth_iv_ptr = ref->auth_iv,
		.hash_result_offset = hash_result_offset,
		.aad_ptr = ref->aad,
		.cipher_range = cipher_range,
		.auth_range = auth_range,
		.dst_offset_shift = 0,
	};
	rc = crypto_op(pkt, &pkt, &ok, &op_params,
		       ODP_CRYPTO_OP_TYPE_BASIC, ODP_CRYPTO_OP_TYPE_BASIC);
	CU_ASSERT(rc == 0);
	if (rc) {
		(void)odp_crypto_session_destroy(session.session);
		return -1;
	}
	CU_ASSERT(ok);

	rc = odp_crypto_session_destroy(session.session);
	CU_ASSERT(rc == 0);

	rc = odp_packet_copy_to_mem(pkt, 0, ref->length, ref->ciphertext);
	CU_ASSERT(rc == 0);

	odp_packet_free(pkt);
	return 0;
}

typedef struct crypto_suite_t {
	odp_cipher_alg_t cipher;
	odp_auth_alg_t auth;
	alg_order_t order;
	const odp_crypto_cipher_capability_t *cipher_capa;
	const odp_crypto_auth_capability_t *auth_capa;
} crypto_suite_t;

/*
 * Create test reference for combined auth & cipher by doing authentication
 * and ciphering through separate ODP crypto operations.
 */
static int create_combined_ref(const crypto_suite_t *suite,
			       crypto_test_reference_t *ref,
			       const odp_packet_data_range_t *cipher_range,
			       const odp_packet_data_range_t *auth_range,
			       uint32_t digest_offset)
{
	uint32_t total_len;
	int rc;
	crypto_test_reference_t ref_cipher_only;
	crypto_test_reference_t ref_auth_only;
	crypto_test_reference_t *first_ref, *second_ref;

	total_len = cipher_range->offset + cipher_range->length;
	if (auth_range->offset + auth_range->length > total_len)
		total_len = auth_range->offset + auth_range->length;
	if (digest_offset + suite->auth_capa->digest_len > total_len)
		total_len = digest_offset + suite->auth_capa->digest_len;

	ref->cipher = suite->cipher;
	ref->auth = suite->auth;
	ref->cipher_key_length = suite->cipher_capa->key_len;
	ref->cipher_iv_length = suite->cipher_capa->iv_len;
	ref->auth_key_length = suite->auth_capa->key_len;
	ref->auth_iv_length = suite->auth_capa->iv_len;
	ref->digest_length = suite->auth_capa->digest_len;
	ref->aad_length = 0;
	ref->is_length_in_bits = false;
	ref->length = total_len;

	if (ref->auth_key_length > MAX_KEY_LEN ||
	    ref->auth_iv_length > MAX_IV_LEN ||
	    total_len > MAX_DATA_LEN ||
	    digest_offset + ref->digest_length > MAX_DATA_LEN)
		CU_FAIL_FATAL("Internal error\n");

	fill_with_pattern(ref->cipher_key, ref->cipher_key_length);
	fill_with_pattern(ref->cipher_iv, ref->cipher_iv_length);
	fill_with_pattern(ref->auth_key, ref->auth_key_length);
	fill_with_pattern(ref->auth_iv, ref->auth_iv_length);
	fill_with_pattern(ref->plaintext, ref->length);
	memset(ref->plaintext + digest_offset, 0, ref->digest_length);

	ref_cipher_only = *ref;
	ref_cipher_only.auth = ODP_AUTH_ALG_NULL;
	ref_cipher_only.auth_key_length = 0;
	ref_cipher_only.auth_iv_length = 0;
	ref_cipher_only.aad_length = 0;
	ref_cipher_only.digest_length = 0;

	ref_auth_only = *ref;
	ref_auth_only.cipher = ODP_CIPHER_ALG_NULL;
	ref_auth_only.cipher_key_length = 0;
	ref_auth_only.cipher_iv_length = 0;

	if (suite->order == AUTH_CIPHERTEXT) {
		first_ref = &ref_cipher_only;
		second_ref = &ref_auth_only;
	} else {
		first_ref = &ref_auth_only;
		second_ref = &ref_cipher_only;
	}
	rc = crypto_encode_ref(first_ref,
			       *cipher_range, *auth_range,
			       digest_offset);
	if (rc)
		return 1;
	memcpy(second_ref->plaintext, first_ref->ciphertext, ref->length);
	rc = crypto_encode_ref(second_ref,
			       *cipher_range, *auth_range,
			       digest_offset);
	if (rc)
		return 1;
	memcpy(ref->ciphertext, second_ref->ciphertext, ref->length);
	/*
	 * These may be encrypted bytes, but that is what alg_test wants if
	 * the digest is encrypted in the input packet.
	 */
	memcpy(ref->digest, second_ref->ciphertext + digest_offset, ref->digest_length);

	return 0;
}

/*
 * Return cipher range that is at least min_len bytes long, multiple of the
 * block size and at least 3 blocks.
 */
static uint32_t get_cipher_range_len(uint32_t min_len)
{
#define MAX_BLOCK_SIZE 16
	uint32_t bs = MAX_BLOCK_SIZE;
	uint32_t len = 3 * bs;

	if (min_len > len)
		len = ((min_len + bs - 1) / bs) * bs;
	return len;
}

typedef enum range_overlap_t {
	SEPARATE_AUTH_AND_CIPHER_RANGES,
	SAME_AUTH_AND_CIPHER_RANGE,
	RANGES_PARTIALLY_OVERLAP,
	AUTH_RANGE_IN_CIPHER_RANGE,
	CIPHER_RANGE_IN_AUTH_RANGE,
} range_overlap_t;
#define NUM_RANGE_OVERLAPS 5

typedef enum hash_location_t {
	HASH_SEPARATE,
	HASH_IN_AUTH_RANGE_ONLY,
	HASH_IN_CIPHER_RANGE_ONLY,
	HASH_IN_AUTH_AND_CIPHER_RANGE,
} hash_location_t;
#define NUM_HASH_LOCATIONS 4

static int make_byte_ranges(range_overlap_t overlap,
			    hash_location_t hash_location,
			    uint32_t hash_len,
			    odp_packet_data_range_t *cipher_range,
			    odp_packet_data_range_t *auth_range,
			    uint32_t *digest_offset)
{
	const uint32_t padding = 5; /* padding between parts, could also be zero */
	const uint32_t nonzero_len = 3;
	uint32_t c_offs = 0, c_len = 0, a_offs = 0, a_len = 0, digest_offs = 0;

	switch (overlap) {
	case SEPARATE_AUTH_AND_CIPHER_RANGES:
		switch (hash_location) {
		case HASH_SEPARATE:
			/* |cccc_aaaa_dd| */
			c_offs = 0;
			c_len = get_cipher_range_len(nonzero_len);
			a_offs = c_offs + c_len + padding;
			a_len = nonzero_len;
			digest_offs = a_offs + a_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/*
			 * |cccc_aaaa|
			 * |     _dd_|
			 */
			c_offs = 0;
			c_len = get_cipher_range_len(nonzero_len);
			a_offs = c_offs + c_len + padding;
			a_len = hash_len + 2 * padding;
			digest_offs = a_offs + padding;
			break;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/*
			 * |cccc_aaaa|
			 * |_dd_     |
			 */
			c_offs = 0;
			c_len = get_cipher_range_len(hash_len + 2 * padding);
			a_offs = c_offs + c_len + padding;
			a_len = nonzero_len;
			digest_offs = c_offs + padding;
			break;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/* not possible when ranges are separate */
			return 1;
		}
		break;
	case SAME_AUTH_AND_CIPHER_RANGE:
		c_offs = 0;
		a_offs = 0;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |cccc_dd|
			 * |aaaa   |
			 */
			c_len = get_cipher_range_len(nonzero_len);
			a_len = c_len;
			digest_offs = c_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
		case HASH_IN_CIPHER_RANGE_ONLY:
			/* not possible when ranges are the same */
			return 1;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |cccc|
			 * |aaaa|
			 * |_dd_|
			 */
			c_len = get_cipher_range_len(hash_len + 2 * padding);
			a_len = c_len;
			digest_offs = padding;
			break;
		}
		break;
	case RANGES_PARTIALLY_OVERLAP:
		a_offs = 0;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |aaaa    |
			 * | cccc_dd|
			 */
			a_len = 2 * nonzero_len;
			c_offs = nonzero_len;
			c_len = get_cipher_range_len(a_len);
			digest_offs = c_offs + c_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/*
			 * |aaaaa  |
			 * |_dd_ccc|
			 */
			digest_offs = padding;
			a_len = hash_len + 2 * padding + nonzero_len;
			c_offs = hash_len + 2 * padding;
			c_len = get_cipher_range_len(2 * nonzero_len);
			break;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/* PDCP case when AUTH_PLAINTEXT */
			/*
			 * |aaaadd|
			 * | ccccc|
			 */
			c_offs = nonzero_len;
			c_len = get_cipher_range_len(nonzero_len + hash_len);
			a_len = nonzero_len + c_len - hash_len;
			digest_offs = c_offs + c_len - hash_len;
			break;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |aaaaaa |
			 * | cccccc|
			 * |¨_dd_  |
			 */
			c_offs = nonzero_len;
			c_len = get_cipher_range_len(hash_len + 2 * padding + nonzero_len);
			a_len = c_offs + hash_len + 2 * padding;
			digest_offs = c_offs + padding;
			break;
		}
		break;
	case AUTH_RANGE_IN_CIPHER_RANGE:
		c_offs = 0;
		a_offs = nonzero_len;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |cccc_dd|
			 * | aa_   |
			 */
			a_len = nonzero_len;
			c_len = get_cipher_range_len(a_offs + a_len + padding);
			digest_offs = c_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/* not possible since auth range is in cipher range */
			return 1;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/*
			 * |ccccccc|
			 * | aa_dd_|
			 */
			a_len = nonzero_len;
			digest_offs = a_offs + a_len + padding;
			c_len = get_cipher_range_len(digest_offs + hash_len + padding);
			break;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |cccccc|
			 * | aaaa_|
			 * | _dd_ |
			 */
			a_len = /**/ hash_len + 2 * padding;
			c_len = get_cipher_range_len(a_offs + a_len + padding);
			digest_offs = a_offs + /**/ padding;
			break;
		}
		break;
	case CIPHER_RANGE_IN_AUTH_RANGE:
		a_offs = 0;
		c_offs = nonzero_len;
		switch (hash_location) {
		case HASH_SEPARATE:
			/*
			 * |aaaa_dd|
			 * | cc_   |
			 */
			c_len = get_cipher_range_len(nonzero_len);
			a_len = c_offs + c_len + padding;
			digest_offs = a_len + padding;
			break;
		case HASH_IN_AUTH_RANGE_ONLY:
			/*
			 * |aaaaaaa|
			 * | cc_dd_|
			 */
			c_len = get_cipher_range_len(nonzero_len);
			digest_offs = c_offs + c_len + padding;
			a_len = digest_offs + hash_len + padding;
			break;
		case HASH_IN_CIPHER_RANGE_ONLY:
			/* not possible since cipher range is in auth range */
			return 1;
		case HASH_IN_AUTH_AND_CIPHER_RANGE:
			/*
			 * |aaaaaa|
			 * | cccc_|
			 * | _dd_ |
			 */
			c_len = get_cipher_range_len(hash_len + 2 * padding);
			a_len = c_offs + c_len + padding;
			digest_offs = c_offs + padding;
			break;
		}
		break;
	}
	cipher_range->offset = c_offs;
	cipher_range->length = c_len;
	auth_range->offset = a_offs;
	auth_range->length = a_len;
	*digest_offset = digest_offs;
	return 0;
}

static void test_combo(const crypto_suite_t *suite,
		       range_overlap_t overlap,
		       hash_location_t location)
{
	int rc;

	odp_packet_data_range_t cipher_range = {0, 0};
	odp_packet_data_range_t auth_range = {0, 0};
	uint32_t digest_offset = 0;
	crypto_test_reference_t ref;

	rc = make_byte_ranges(overlap,
			      location,
			      suite->auth_capa->digest_len,
			      &cipher_range,
			      &auth_range,
			      &digest_offset);
	if (rc)
		return;

	rc = create_combined_ref(suite, &ref,
				 &cipher_range, &auth_range,
				 digest_offset);
	if (rc)
		return;

	cipher_range.offset *= 8;
	cipher_range.length *= 8;
	auth_range.offset *= 8;
	auth_range.length *= 8;

	alg_test(ODP_CRYPTO_OP_ENCODE,
		 suite->order,
		 &ref,
		 cipher_range, auth_range,
		 digest_offset,
		 suite->cipher_capa->bit_mode,
		 suite->auth_capa->bit_mode);

	alg_test(ODP_CRYPTO_OP_DECODE,
		 suite->order,
		 &ref,
		 cipher_range, auth_range,
		 digest_offset,
		 suite->cipher_capa->bit_mode,
		 suite->auth_capa->bit_mode);
}

/* Iterate and test different cipher/auth range and hash locations */
static void test_combo_ranges(const crypto_suite_t *suite)
{
	if (!full_test && suite->auth_capa->digest_len % 4 != 0)
		return;

	for (int overlap = 0; overlap < NUM_RANGE_OVERLAPS; overlap++)
		for (int location = 0; location < NUM_HASH_LOCATIONS; location++) {
			if (suite->order == AUTH_CIPHERTEXT &&
			    (location == HASH_IN_CIPHER_RANGE_ONLY ||
			     location == HASH_IN_AUTH_AND_CIPHER_RANGE)) {
				/*
				 * This combination ís not valid since
				 * the generated hash would overwrite some
				 * ciphertext, preventing decryption.
				 */
				continue;
			}
			test_combo(suite, overlap, location);
		}
}

/* Iterate and test all variants (key sizes etc) of an alg combo */
static void test_combo_variants(odp_cipher_alg_t cipher, odp_auth_alg_t auth)
{
	int num, num_ciphers, num_auths;

	/* ODP API says AES-GMAC can be combined with the null cipher only */
	if (auth == ODP_AUTH_ALG_AES_GMAC &&
	    cipher != ODP_CIPHER_ALG_NULL)
		return;

	if (check_alg_support(cipher, auth) == ODP_TEST_INACTIVE)
		return;

	printf("    %s, %s\n",
	       cipher_alg_name(cipher),
	       auth_alg_name(auth));

	num_ciphers = odp_crypto_cipher_capability(cipher, NULL, 0);
	num_auths = odp_crypto_auth_capability(auth, NULL, 0);
	CU_ASSERT_FATAL(num_ciphers > 0);
	CU_ASSERT_FATAL(num_auths > 0);

	odp_crypto_cipher_capability_t cipher_capa[num_ciphers];
	odp_crypto_auth_capability_t auth_capa[num_auths];

	num = odp_crypto_cipher_capability(cipher, cipher_capa, num_ciphers);
	CU_ASSERT(num == num_ciphers);
	num = odp_crypto_auth_capability(auth, auth_capa, num_auths);
	CU_ASSERT(num == num_auths);

	combo_warning_shown = 0;

	for (int n = 0; n < num_ciphers; n++)
		for (int i = 0; i < num_auths; i++) {
			crypto_suite_t suite = {.cipher = cipher,
						.auth = auth,
						.cipher_capa = &cipher_capa[n],
						.auth_capa = &auth_capa[i]};
			suite.order = AUTH_PLAINTEXT;
			test_combo_ranges(&suite);
			suite.order = AUTH_CIPHERTEXT;
			test_combo_ranges(&suite);
		}
}

static void test_all_combinations(void)
{
	if (suite_context.partial_test) {
		printf("skipped ");
		return;
	}

	printf("\n");
	for (size_t n = 0; n < ODPH_ARRAY_SIZE(cipher_algs); n++)
		for (size_t i = 0; i < ODPH_ARRAY_SIZE(auth_algs); i++)
			test_combo_variants(cipher_algs[n], auth_algs[i]);
}

static int check_alg_null(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_null(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  null_reference,
		  ODPH_ARRAY_SIZE(null_reference));
}

static void crypto_test_dec_alg_null(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  null_reference,
		  ODPH_ARRAY_SIZE(null_reference));
}

static int check_alg_3des_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_CBC, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  tdes_cbc_reference,
		  ODPH_ARRAY_SIZE(tdes_cbc_reference));
}

static void crypto_test_dec_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  tdes_cbc_reference,
		  ODPH_ARRAY_SIZE(tdes_cbc_reference));
}

static int check_alg_3des_ecb(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_ECB, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_3des_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  tdes_ecb_reference,
		  ODPH_ARRAY_SIZE(tdes_ecb_reference));
}

static void crypto_test_dec_alg_3des_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  tdes_ecb_reference,
		  ODPH_ARRAY_SIZE(tdes_ecb_reference));
}

static int check_alg_chacha20_poly1305(void)
{
	return check_alg_support(ODP_CIPHER_ALG_CHACHA20_POLY1305,
				 ODP_AUTH_ALG_CHACHA20_POLY1305);
}

static void crypto_test_enc_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  chacha20_poly1305_reference,
		  ODPH_ARRAY_SIZE(chacha20_poly1305_reference));
}

static void crypto_test_dec_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  chacha20_poly1305_reference,
		  ODPH_ARRAY_SIZE(chacha20_poly1305_reference));
}

static int check_alg_aes_gcm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_GCM, ODP_AUTH_ALG_AES_GCM);
}

static void crypto_test_enc_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_gcm_reference,
		  ODPH_ARRAY_SIZE(aes_gcm_reference));
}

static void crypto_test_dec_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_gcm_reference,
		  ODPH_ARRAY_SIZE(aes_gcm_reference));
}

static int check_alg_aes_ccm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CCM, ODP_AUTH_ALG_AES_CCM);
}

static void crypto_test_enc_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_ccm_reference,
		  ODPH_ARRAY_SIZE(aes_ccm_reference));
}

static void crypto_test_dec_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_ccm_reference,
		  ODPH_ARRAY_SIZE(aes_ccm_reference));
}

static int check_alg_aes_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CBC, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_cbc_reference,
		  ODPH_ARRAY_SIZE(aes_cbc_reference));
}

static void crypto_test_dec_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_cbc_reference,
		  ODPH_ARRAY_SIZE(aes_cbc_reference));
}

static int check_alg_aes_ctr(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CTR, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_ctr_reference,
		  ODPH_ARRAY_SIZE(aes_ctr_reference));
}

static void crypto_test_dec_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_ctr_reference,
		  ODPH_ARRAY_SIZE(aes_ctr_reference));
}

static int check_alg_aes_ecb(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_ECB, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_ecb_reference,
		  ODPH_ARRAY_SIZE(aes_ecb_reference));
}

static void crypto_test_dec_alg_aes_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_ecb_reference,
		  ODPH_ARRAY_SIZE(aes_ecb_reference));
}

static int check_alg_aes_cfb128(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CFB128, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_cfb128(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_cfb128_reference,
		  ODPH_ARRAY_SIZE(aes_cfb128_reference));
}

static void crypto_test_dec_alg_aes_cfb128(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_cfb128_reference,
		  ODPH_ARRAY_SIZE(aes_cfb128_reference));
}

static int check_alg_aes_xts(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_XTS, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_xts(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_xts_reference,
		  ODPH_ARRAY_SIZE(aes_xts_reference));
}

static void crypto_test_dec_alg_aes_xts(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_xts_reference,
		  ODPH_ARRAY_SIZE(aes_xts_reference));
}

static int check_alg_kasumi_f8(void)
{
	return check_alg_support(ODP_CIPHER_ALG_KASUMI_F8, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_kasumi_f8(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  kasumi_f8_reference,
		  ODPH_ARRAY_SIZE(kasumi_f8_reference));
}

static void crypto_test_dec_alg_kasumi_f8(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  kasumi_f8_reference,
		  ODPH_ARRAY_SIZE(kasumi_f8_reference));
}

static int check_alg_snow3g_uea2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_SNOW3G_UEA2, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_snow3g_uea2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  snow3g_uea2_reference,
		  ODPH_ARRAY_SIZE(snow3g_uea2_reference));
}

static void crypto_test_dec_alg_snow3g_uea2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  snow3g_uea2_reference,
		  ODPH_ARRAY_SIZE(snow3g_uea2_reference));
}

static int check_alg_aes_eea2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_EEA2,
				 ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_eea2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_eea2_reference,
		  ODPH_ARRAY_SIZE(aes_eea2_reference));
}

static void crypto_test_dec_alg_aes_eea2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_eea2_reference,
		  ODPH_ARRAY_SIZE(aes_eea2_reference));
}

static int check_alg_zuc_eea3(void)
{
	return check_alg_support(ODP_CIPHER_ALG_ZUC_EEA3, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_zuc_eea3(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  zuc_eea3_reference,
		  ODPH_ARRAY_SIZE(zuc_eea3_reference));
}

static void crypto_test_dec_alg_zuc_eea3(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  zuc_eea3_reference,
		  ODPH_ARRAY_SIZE(zuc_eea3_reference));
}

static int check_alg_hmac_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5_HMAC);
}

static void crypto_test_gen_alg_hmac_md5(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_md5_reference,
		  ODPH_ARRAY_SIZE(hmac_md5_reference));
}

static void crypto_test_check_alg_hmac_md5(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_md5_reference,
		  ODPH_ARRAY_SIZE(hmac_md5_reference));
}

static int check_alg_hmac_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1_HMAC);
}

static void crypto_test_gen_alg_hmac_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha1_reference,
		  ODPH_ARRAY_SIZE(hmac_sha1_reference));
}

static void crypto_test_check_alg_hmac_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha1_reference,
		  ODPH_ARRAY_SIZE(hmac_sha1_reference));
}

static int check_alg_hmac_sha224(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA224_HMAC);
}

static void crypto_test_gen_alg_hmac_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha224_reference,
		  ODPH_ARRAY_SIZE(hmac_sha224_reference));
}

static void crypto_test_check_alg_hmac_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha224_reference,
		  ODPH_ARRAY_SIZE(hmac_sha224_reference));
}

static int check_alg_hmac_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256_HMAC);
}

static void crypto_test_gen_alg_hmac_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha256_reference,
		  ODPH_ARRAY_SIZE(hmac_sha256_reference));
}

static void crypto_test_check_alg_hmac_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha256_reference,
		  ODPH_ARRAY_SIZE(hmac_sha256_reference));
}

static int check_alg_hmac_sha384(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA384_HMAC);
}

static void crypto_test_gen_alg_hmac_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha384_reference,
		  ODPH_ARRAY_SIZE(hmac_sha384_reference));
}

static void crypto_test_check_alg_hmac_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha384_reference,
		  ODPH_ARRAY_SIZE(hmac_sha384_reference));
}

static int check_alg_hmac_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512_HMAC);
}

static void crypto_test_gen_alg_hmac_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  hmac_sha512_reference,
		  ODPH_ARRAY_SIZE(hmac_sha512_reference));
}

static void crypto_test_check_alg_hmac_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  hmac_sha512_reference,
		  ODPH_ARRAY_SIZE(hmac_sha512_reference));
}

static int check_alg_aes_xcbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL,
						ODP_AUTH_ALG_AES_XCBC_MAC);
}

static void crypto_test_gen_alg_aes_xcbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_xcbc_reference,
		  ODPH_ARRAY_SIZE(aes_xcbc_reference));
}

static void crypto_test_check_alg_aes_xcbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_xcbc_reference,
		  ODPH_ARRAY_SIZE(aes_xcbc_reference));
}

static int check_alg_aes_gmac(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_GMAC);
}

static void crypto_test_gen_alg_aes_gmac(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_gmac_reference,
		  ODPH_ARRAY_SIZE(aes_gmac_reference));
}

static void crypto_test_check_alg_aes_gmac(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_gmac_reference,
		  ODPH_ARRAY_SIZE(aes_gmac_reference));
}

static int check_alg_aes_cmac(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_CMAC);
}

static void crypto_test_gen_alg_aes_cmac(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_cmac_reference,
		  ODPH_ARRAY_SIZE(aes_cmac_reference));
}

static void crypto_test_check_alg_aes_cmac(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_cmac_reference,
		  ODPH_ARRAY_SIZE(aes_cmac_reference));
}

static int check_alg_kasumi_f9(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_KASUMI_F9);
}

static void crypto_test_gen_alg_kasumi_f9(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  kasumi_f9_reference,
		  ODPH_ARRAY_SIZE(kasumi_f9_reference));
}

static void crypto_test_check_alg_kasumi_f9(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  kasumi_f9_reference,
		  ODPH_ARRAY_SIZE(kasumi_f9_reference));
}

static int check_alg_snow3g_uia2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SNOW3G_UIA2);
}

static void crypto_test_gen_alg_snow3g_uia2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  snow3g_uia2_reference,
		  ODPH_ARRAY_SIZE(snow3g_uia2_reference));
}

static void crypto_test_check_alg_snow3g_uia2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  snow3g_uia2_reference,
		  ODPH_ARRAY_SIZE(snow3g_uia2_reference));
}

static int check_alg_aes_eia2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL,
				 ODP_AUTH_ALG_AES_EIA2);
}

static void crypto_test_gen_alg_aes_eia2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  aes_eia2_reference,
		  ODPH_ARRAY_SIZE(aes_eia2_reference));
}

static void crypto_test_check_alg_aes_eia2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  aes_eia2_reference,
		  ODPH_ARRAY_SIZE(aes_eia2_reference));
}

static int check_alg_zuc_eia3(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_ZUC_EIA3);
}

static void crypto_test_gen_alg_zuc_eia3(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  zuc_eia3_reference,
		  ODPH_ARRAY_SIZE(zuc_eia3_reference));
}

static void crypto_test_check_alg_zuc_eia3(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  zuc_eia3_reference,
		  ODPH_ARRAY_SIZE(zuc_eia3_reference));
}

static int check_alg_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5);
}

static void crypto_test_gen_alg_md5(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  md5_reference,
		  ODPH_ARRAY_SIZE(md5_reference));
}

static void crypto_test_check_alg_md5(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  md5_reference,
		  ODPH_ARRAY_SIZE(md5_reference));
}

static int check_alg_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1);
}

static void crypto_test_gen_alg_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha1_reference,
		  ODPH_ARRAY_SIZE(sha1_reference));
}

static void crypto_test_check_alg_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha1_reference,
		  ODPH_ARRAY_SIZE(sha1_reference));
}

static int check_alg_sha224(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA224);
}

static void crypto_test_gen_alg_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha224_reference,
		  ODPH_ARRAY_SIZE(sha224_reference));
}

static void crypto_test_check_alg_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha224_reference,
		  ODPH_ARRAY_SIZE(sha224_reference));
}

static int check_alg_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256);
}

static void crypto_test_gen_alg_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha256_reference,
		  ODPH_ARRAY_SIZE(sha256_reference));
}

static void crypto_test_check_alg_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha256_reference,
		  ODPH_ARRAY_SIZE(sha256_reference));
}

static int check_alg_sha384(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA384);
}

static void crypto_test_gen_alg_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha384_reference,
		  ODPH_ARRAY_SIZE(sha384_reference));
}

static void crypto_test_check_alg_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha384_reference,
		  ODPH_ARRAY_SIZE(sha384_reference));
}

static int check_alg_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512);
}

static void crypto_test_gen_alg_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  sha512_reference,
		  ODPH_ARRAY_SIZE(sha512_reference));
}

static void crypto_test_check_alg_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  sha512_reference,
		  ODPH_ARRAY_SIZE(sha512_reference));
}

static odp_queue_t sched_compl_queue_create(void)
{
	odp_queue_param_t qparam;

	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = odp_schedule_default_prio();
	qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	return odp_queue_create("crypto-out", &qparam);
}

static odp_queue_t plain_compl_queue_create(void)
{
	return odp_queue_create("crypto-out", NULL);
}

static odp_event_t sched_compl_queue_deq(void)
{
	return odp_schedule(NULL, ODP_SCHED_NO_WAIT);
}

static odp_event_t plain_compl_queue_deq(void)
{
	return odp_queue_deq(suite_context.queue);
}

static int partial_test_only(odp_crypto_op_mode_t op_mode, odp_queue_type_t q_type)
{
	odp_crypto_capability_t capa;

	if (full_test || odp_crypto_capability(&capa))
		return 0;

	if (!capa.async_mode)
		return 0;

	if (op_mode == ODP_CRYPTO_SYNC)
		return 1;
	else if (q_type == ODP_QUEUE_TYPE_PLAIN && capa.queue_type_sched)
		return 1;

	return 0;
}

static int crypto_suite_packet_sync_init(void)
{
	suite_context.op_mode = ODP_CRYPTO_SYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	suite_context.partial_test = partial_test_only(suite_context.op_mode,
						       ODP_QUEUE_TYPE_PLAIN);
	return 0;
}

static int crypto_suite_packet_async_plain_init(void)
{
	odp_queue_t out_queue;

	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = plain_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		ODPH_ERR("Crypto outq creation failed\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_PLAIN;
	suite_context.compl_queue_deq = plain_compl_queue_deq;
	suite_context.partial_test = partial_test_only(suite_context.op_mode,
						       suite_context.q_type);

	return 0;
}

static int crypto_suite_packet_async_sched_init(void)
{
	odp_queue_t out_queue;

	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = sched_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		ODPH_ERR("Crypto outq creation failed\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_SCHED;
	suite_context.compl_queue_deq = sched_compl_queue_deq;
	suite_context.partial_test = partial_test_only(suite_context.op_mode,
						       suite_context.q_type);

	return 0;
}

static int crypto_suite_term(void)
{
	if (ODP_QUEUE_INVALID != suite_context.queue) {
		if (odp_queue_destroy(suite_context.queue))
			ODPH_ERR("Crypto outq destroy failed\n");
	} else {
		ODPH_ERR("Crypto outq not found\n");
	}

	return odp_cunit_print_inactive();
}

odp_testinfo_t crypto_suite[] = {
	ODP_TEST_INFO(test_capability),
	ODP_TEST_INFO(test_default_values),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_null,
				  check_alg_null),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_null,
				  check_alg_null),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_3des_cbc,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_3des_cbc,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_3des_ecb,
				  check_alg_3des_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_3des_ecb,
				  check_alg_3des_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ctr,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ctr,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ecb,
				  check_alg_aes_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ecb,
				  check_alg_aes_ecb),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_cfb128,
				  check_alg_aes_cfb128),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_cfb128,
				  check_alg_aes_cfb128),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_xts,
				  check_alg_aes_xts),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_xts,
				  check_alg_aes_xts),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_kasumi_f8,
				  check_alg_kasumi_f8),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_kasumi_f8,
				  check_alg_kasumi_f8),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_snow3g_uea2,
				  check_alg_snow3g_uea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_snow3g_uea2,
				  check_alg_snow3g_uea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_eea2,
				  check_alg_aes_eea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_eea2,
				  check_alg_aes_eea2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_zuc_eea3,
				  check_alg_zuc_eea3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_zuc_eea3,
				  check_alg_zuc_eea3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ccm,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ccm,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_chacha20_poly1305,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_chacha20_poly1305,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha1,
				  check_alg_hmac_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha1,
				  check_alg_hmac_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha224,
				  check_alg_hmac_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha224,
				  check_alg_hmac_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha256,
				  check_alg_hmac_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha256,
				  check_alg_hmac_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha384,
				  check_alg_hmac_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha384,
				  check_alg_hmac_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha512,
				  check_alg_hmac_sha512),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha512,
				  check_alg_hmac_sha512),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_xcbc,
				  check_alg_aes_xcbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_xcbc,
				  check_alg_aes_xcbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_gmac,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_gmac,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_cmac,
				  check_alg_aes_cmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_cmac,
				  check_alg_aes_cmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_kasumi_f9,
				  check_alg_kasumi_f9),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_kasumi_f9,
				  check_alg_kasumi_f9),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_snow3g_uia2,
				  check_alg_snow3g_uia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_snow3g_uia2,
				  check_alg_snow3g_uia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_eia2,
				  check_alg_aes_eia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_eia2,
				  check_alg_aes_eia2),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_zuc_eia3,
				  check_alg_zuc_eia3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_zuc_eia3,
				  check_alg_zuc_eia3),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_md5,
				  check_alg_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_md5,
				  check_alg_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha1,
				  check_alg_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha1,
				  check_alg_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha224,
				  check_alg_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha224,
				  check_alg_sha224),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha256,
				  check_alg_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha256,
				  check_alg_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha384,
				  check_alg_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha384,
				  check_alg_sha384),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_sha512,
				  check_alg_sha512),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_sha512,
				  check_alg_sha512),
	ODP_TEST_INFO(test_auth_hashes_in_auth_range),
	ODP_TEST_INFO(test_all_combinations),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t crypto_suites[] = {
	{"odp_crypto_packet_sync_inp", crypto_suite_packet_sync_init,
	 NULL, crypto_suite},
	{"odp_crypto_packet_async_plain_inp",
	 crypto_suite_packet_async_plain_init,
	 crypto_suite_term, crypto_suite},
	{"odp_crypto_packet_async_sched_inp",
	 crypto_suite_packet_async_sched_init,
	 crypto_suite_term, crypto_suite},
	ODP_SUITE_INFO_NULL,
};

static int crypto_init(odp_instance_t *inst)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_pool_capability_t pool_capa;
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		ODPH_ERR("odph_options() failed\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		ODPH_ERR("odp_init_global() failed\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("odp_init_local() failed\n");
		return -1;
	}

	/* Configure the scheduler. */
	if (odp_schedule_config(NULL)) {
		ODPH_ERR("odp_schedule_config() failed\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("odp_pool_capability() failed\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_LEN;
	params.pkt.len     = PKT_POOL_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	/*
	 * Let's have a user area so that we can check that its
	 * content gets copied along with other metadata when needed.
	 */
	if (pool_capa.pkt.max_uarea_size >= UAREA_SIZE)
		params.pkt.uarea_size = UAREA_SIZE;
	else
		printf("Warning: could not request packet user area\n");

	if (pool_capa.pkt.max_seg_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_seg_len) {
		ODPH_ERR("Warning: small packet segment length\n");
		params.pkt.seg_len = pool_capa.pkt.max_seg_len;
	}

	if (pool_capa.pkt.max_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_len) {
		ODPH_ERR("Pool max packet length too small\n");
		return -1;
	}

	pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		ODPH_ERR("Packet pool creation failed\n");
		return -1;
	}

	return 0;
}

static int crypto_term(odp_instance_t inst)
{
	odp_pool_t pool;

	pool = odp_pool_lookup("packet_pool");
	if (ODP_POOL_INVALID != pool) {
		if (odp_pool_destroy(pool))
			ODPH_ERR("Packet pool destroy failed\n");
	} else {
		ODPH_ERR("Packet pool not found\n");
	}

	if (0 != odp_term_local()) {
		ODPH_ERR("odp_term_local() failed\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		ODPH_ERR("odp_term_global() failed\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	char *env = getenv("FULL_TEST");

	if (env && strcmp(env, "0"))
		full_test = 1;
	printf("Test mode: %s\n", full_test ? "full" : "partial");

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	odp_cunit_register_global_init(crypto_init);
	odp_cunit_register_global_term(crypto_term);

	ret = odp_cunit_register(crypto_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
