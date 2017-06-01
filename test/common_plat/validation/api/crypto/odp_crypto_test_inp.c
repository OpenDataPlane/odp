/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_api.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include "test_vectors.h"
#include "odp_crypto_test_inp.h"
#include "crypto.h"

#define MAX_ALG_CAPA 32

struct suite_context_s {
	odp_crypto_op_mode_t pref_mode;
	odp_pool_t pool;
	odp_queue_t queue;
};

static struct suite_context_s suite_context;

static const char *auth_alg_name(odp_auth_alg_t auth)
{
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		return "ODP_AUTH_ALG_NULL";
	case ODP_AUTH_ALG_MD5_HMAC:
		return "ODP_AUTH_ALG_MD5_HMAC";
	case ODP_AUTH_ALG_SHA256_HMAC:
		return "ODP_AUTH_ALG_SHA256_HMAC";
	case ODP_AUTH_ALG_AES_GCM:
		return "ODP_AUTH_ALG_AES_GCM";
	default:
		return "Unknown";
	}
}

static const char *cipher_alg_name(odp_cipher_alg_t cipher)
{
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		return "ODP_CIPHER_ALG_NULL";
	case ODP_CIPHER_ALG_DES:
		return "ODP_CIPHER_ALG_DES";
	case ODP_CIPHER_ALG_3DES_CBC:
		return "ODP_CIPHER_ALG_3DES_CBC";
	case ODP_CIPHER_ALG_AES_CBC:
		return "ODP_CIPHER_ALG_AES_CBC";
	case ODP_CIPHER_ALG_AES_GCM:
		return "ODP_CIPHER_ALG_AES_GCM";
	default:
		return "Unknown";
	}
}

/* Basic algorithm run function for async inplace mode.
 * Creates a session from input parameters and runs one operation
 * on input_vec. Checks the output of the crypto operation against
 * output_vec. Operation completion event is dequeued polling the
 * session output queue. Completion context pointer is retrieved
 * and checked against the one set before the operation.
 * Completion event can be a separate buffer or the input packet
 * buffer can be used.
 * */
static void alg_test(odp_crypto_op_t op,
		     odp_bool_t should_fail,
		     odp_cipher_alg_t cipher_alg,
		     odp_crypto_iv_t ses_iv,
		     uint8_t *op_iv_ptr,
		     odp_crypto_key_t cipher_key,
		     odp_auth_alg_t auth_alg,
		     odp_crypto_key_t auth_key,
		     odp_packet_data_range_t *cipher_range,
		     odp_packet_data_range_t *auth_range,
		     uint8_t *aad,
		     uint32_t aad_len,
		     const uint8_t *plaintext,
		     unsigned int plaintext_len,
		     const uint8_t *ciphertext,
		     unsigned int ciphertext_len,
		     const uint8_t *digest,
		     uint32_t digest_len)
{
	odp_crypto_session_t session;
	odp_crypto_capability_t capa;
	int rc;
	odp_crypto_ses_create_err_t status;
	odp_bool_t posted;
	odp_event_t event;
	odp_crypto_compl_t compl_event;
	odp_crypto_op_result_t result;
	odp_crypto_session_param_t ses_params;
	odp_crypto_op_param_t op_params;
	uint8_t *data_addr;
	int data_off;
	odp_crypto_cipher_capability_t cipher_capa[MAX_ALG_CAPA];
	odp_crypto_auth_capability_t   auth_capa[MAX_ALG_CAPA];
	int num, i;
	int found;

	rc = odp_crypto_capability(&capa);
	CU_ASSERT(!rc);

	if (cipher_alg == ODP_CIPHER_ALG_3DES_CBC &&
	    !(capa.ciphers.bit.trides_cbc))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_AES_CBC &&
	    !(capa.ciphers.bit.aes_cbc))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_AES_GCM &&
	    !(capa.ciphers.bit.aes_gcm))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_DES &&
	    !(capa.ciphers.bit.des))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_NULL &&
	    !(capa.ciphers.bit.null))
		rc = -1;

	CU_ASSERT(!rc);
	CU_ASSERT((~capa.ciphers.all_bits & capa.hw_ciphers.all_bits) == 0);

	if (auth_alg == ODP_AUTH_ALG_AES_GCM &&
	    !(capa.auths.bit.aes_gcm))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_MD5_HMAC &&
	    !(capa.auths.bit.md5_hmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_NULL &&
	    !(capa.auths.bit.null))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_SHA256_HMAC &&
	    !(capa.auths.bit.sha256_hmac))
		rc = -1;

	CU_ASSERT(!rc);
	CU_ASSERT((~capa.auths.all_bits & capa.hw_auths.all_bits) == 0);

	num = odp_crypto_cipher_capability(cipher_alg, cipher_capa,
					   MAX_ALG_CAPA);

	CU_ASSERT(num > 0);
	found = 0;

	CU_ASSERT(num <= MAX_ALG_CAPA);

	if (num > MAX_ALG_CAPA)
		num = MAX_ALG_CAPA;

	/* Search for the test case */
	for (i = 0; i < num; i++) {
		if (cipher_capa[i].key_len == cipher_key.length &&
		    cipher_capa[i].iv_len  == ses_iv.length) {
			found = 1;
			break;
		}
	}

	CU_ASSERT(found);

	num = odp_crypto_auth_capability(auth_alg, auth_capa, MAX_ALG_CAPA);

	CU_ASSERT(num > 0);
	found = 0;

	CU_ASSERT(num <= MAX_ALG_CAPA);

	if (num > MAX_ALG_CAPA)
		num = MAX_ALG_CAPA;

	/* Search for the test case */
	for (i = 0; i < num; i++) {
		if (auth_capa[i].digest_len == digest_len &&
		    auth_capa[i].key_len    == auth_key.length) {
			found = 1;
			break;
		}
	}

	CU_ASSERT(found);

	/* Create a crypto session */
	odp_crypto_session_param_init(&ses_params);
	ses_params.op = op;
	ses_params.auth_cipher_text = false;
	ses_params.pref_mode = suite_context.pref_mode;
	ses_params.cipher_alg = cipher_alg;
	ses_params.auth_alg = auth_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.output_pool = suite_context.pool;
	ses_params.cipher_key = cipher_key;
	ses_params.iv = ses_iv;
	ses_params.auth_key = auth_key;
	ses_params.auth_digest_len = digest_len;

	rc = odp_crypto_session_create(&ses_params, &session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_crypto_session_to_u64(session) !=
		  odp_crypto_session_to_u64(ODP_CRYPTO_SESSION_INVALID));

	/* Prepare input data */
	odp_packet_t pkt = odp_packet_alloc(suite_context.pool,
					    plaintext_len + digest_len);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	data_addr = odp_packet_data(pkt);
	memcpy(data_addr, plaintext, plaintext_len);
	data_off = 0;

	/* Prepare input/output params */
	memset(&op_params, 0, sizeof(op_params));
	op_params.session = session;
	op_params.pkt = pkt;
	op_params.out_pkt = pkt;
	op_params.ctx = (void *)0xdeadbeef;

	if (cipher_range) {
		op_params.cipher_range = *cipher_range;
		data_off = cipher_range->offset;
	} else {
		op_params.cipher_range.offset = data_off;
		op_params.cipher_range.length = plaintext_len;
	}
	if (auth_range) {
		op_params.auth_range = *auth_range;
	} else {
		op_params.auth_range.offset = data_off;
		op_params.auth_range.length = plaintext_len;
	}
	if (op_iv_ptr)
		op_params.override_iv_ptr = op_iv_ptr;

	op_params.aad.ptr = aad;
	op_params.aad.length = aad_len;

	op_params.hash_result_offset = plaintext_len;
	if (0 != digest_len) {
		memcpy(data_addr + op_params.hash_result_offset,
		       digest, digest_len);
	}

	rc = odp_crypto_operation(&op_params, &posted, &result);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_operation()");
		goto cleanup;
	}

	if (posted) {
		/* Poll completion queue for results */
		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		compl_event = odp_crypto_compl_from_event(event);
		CU_ASSERT(odp_crypto_compl_to_u64(compl_event) ==
			  odp_crypto_compl_to_u64(odp_crypto_compl_from_event(event)));
		odp_crypto_compl_result(compl_event, &result);
		odp_crypto_compl_free(compl_event);
	}

	CU_ASSERT(result.pkt == pkt);
	CU_ASSERT(result.ctx == (void *)0xdeadbeef);

	if (should_fail) {
		CU_ASSERT(!result.ok);
		goto cleanup;
	}

	CU_ASSERT(result.ok);

	if (cipher_alg != ODP_CIPHER_ALG_NULL)
		CU_ASSERT(!memcmp(data_addr, ciphertext, ciphertext_len));

	if (op == ODP_CRYPTO_OP_ENCODE && auth_alg != ODP_AUTH_ALG_NULL)
		CU_ASSERT(!memcmp(data_addr + op_params.hash_result_offset,
				  digest, digest_len));
cleanup:
	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(!rc);

	odp_packet_free(pkt);
}

/**
 * Check if given cipher and authentication algorithms are supported
 *
 * @param cipher      Cipher algorithm
 * @param auth        Authentication algorithm
 *
 * @retval ODP_TEST_ACTIVE when both algorithms are supported
 * @retval ODP_TEST_INACTIVE when either algorithm is not supported
 */
static int check_alg_support(odp_cipher_alg_t cipher, odp_auth_alg_t auth)
{
	odp_crypto_capability_t capability;

	if (odp_crypto_capability(&capability))
		return ODP_TEST_INACTIVE;

	/* Cipher algorithms */
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		if (!capability.ciphers.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_DES:
		if (!capability.ciphers.bit.des)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		if (!capability.ciphers.bit.trides_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (!capability.ciphers.bit.aes_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (!capability.ciphers.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported cipher algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	/* Authentication algorithms */
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		if (!capability.auths.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		if (!capability.auths.bit.md5_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		if (!capability.auths.bit.sha1_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		if (!capability.auths.bit.sha256_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (!capability.auths.bit.sha512_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (!capability.auths.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

/**
 * Check if given cipher options are supported
 *
 * @param cipher      Cipher algorithm
 * @param key_len     Key length
 * @param iv_len      IV length
 *
 * @retval non-zero if both cipher options are supported
 * @retval 0 if both options are not supported
 */
static int check_cipher_options(odp_cipher_alg_t cipher, uint32_t key_len,
				uint32_t iv_len)
{
	int i;
	int num;
	odp_crypto_cipher_capability_t cipher_capa[MAX_ALG_CAPA];

	num = odp_crypto_cipher_capability(cipher, cipher_capa, MAX_ALG_CAPA);
	CU_ASSERT_FATAL(num >= 1);

	for (i = 0; i < num; i++) {
		if (key_len == cipher_capa[i].key_len &&
		    iv_len == cipher_capa[i].iv_len)
			break;
	}

	if (i == num) {
		printf("\n    Unsupported: alg=%s, key_len=%" PRIu32 ", "
		       "iv_len=%" PRIu32 "\n", cipher_alg_name(cipher), key_len,
		       iv_len);
		return 0;
	}
	return 1;
}

/**
 * Check if given authentication options are supported
 *
 * @param auth        Authentication algorithm
 * @param key_len     Key length
 * @param digest_len  Digest length
 *
 * @retval non-zero if both authentication options are supported
 * @retval 0 if both options are not supported
 */
static int check_auth_options(odp_auth_alg_t auth, uint32_t key_len,
			      uint32_t digest_len)
{
	int i;
	int num;
	odp_crypto_auth_capability_t capa[MAX_ALG_CAPA];

	num = odp_crypto_auth_capability(auth, capa, MAX_ALG_CAPA);
	CU_ASSERT_FATAL(num >= 1);

	for (i = 0; i < num; i++) {
		if (key_len == capa[i].key_len &&
		    digest_len == capa[i].digest_len)
			break;
	}

	if (i == num) {
		printf("\n    Unsupported: alg=%s, key_len=%" PRIu32 ", "
		       "digest_len=%" PRIu32 "\n", auth_alg_name(auth), key_len,
		       digest_len);
		return 0;
	}
	return 1;
}

static int check_alg_null(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_NULL);
}

void crypto_test_enc_alg_null(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0};
	unsigned int test_vec_num = (sizeof(null_reference_length) /
				     sizeof(null_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		if (!check_cipher_options(ODP_CIPHER_ALG_NULL,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 null_reference_plaintext[i],
			 null_reference_length[i],
			 null_reference_plaintext[i],
			 null_reference_length[i], NULL, 0);
	}
}

void crypto_test_dec_alg_null(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };
	unsigned int test_vec_num = (sizeof(null_reference_length) /
				     sizeof(null_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		if (!check_cipher_options(ODP_CIPHER_ALG_NULL,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 null_reference_plaintext[i],
			 null_reference_length[i],
			 null_reference_plaintext[i],
			 null_reference_length[i], NULL, 0);
	}
}

static int check_alg_3des_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_CBC, ODP_AUTH_ALG_NULL);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
void crypto_test_enc_alg_3des_cbc(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length) /
				     sizeof(tdes_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);
		iv.data = tdes_cbc_reference_iv[i];
		iv.length = sizeof(tdes_cbc_reference_iv[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_3DES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i], NULL, 0);
	}
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the operation IV.
 * */
void crypto_test_enc_alg_3des_cbc_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = TDES_CBC_IV_LEN };
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length) /
				     sizeof(tdes_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_3DES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 tdes_cbc_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i], NULL, 0);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_dec_alg_3des_cbc(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length) /
				     sizeof(tdes_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);
		iv.data = tdes_cbc_reference_iv[i];
		iv.length = sizeof(tdes_cbc_reference_iv[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_3DES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i], NULL, 0);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_dec_alg_3des_cbc_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = TDES_CBC_IV_LEN };
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length) /
				     sizeof(tdes_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_3DES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 tdes_cbc_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i], NULL, 0);
	}
}

static int check_alg_aes_gcm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_GCM, ODP_AUTH_ALG_AES_GCM);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_GCM algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
void crypto_test_enc_alg_aes128_gcm(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = AES128_GCM_IV_LEN };
	unsigned int test_vec_num = (sizeof(aes128_gcm_reference_length) /
				     sizeof(aes128_gcm_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_gcm_reference_key[i];
		cipher_key.length = sizeof(aes128_gcm_reference_key[i]);
		iv.data = aes128_gcm_reference_iv[i];
		iv.length = sizeof(aes128_gcm_reference_iv[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_GCM,
					  cipher_key.length, iv.length))
			continue;
		if (!check_auth_options(ODP_AUTH_ALG_AES_GCM,
					auth_key.length,
					aes128_gcm_reference_tag_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_AES_GCM,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_AES_GCM,
			 auth_key,
			 &aes128_gcm_cipher_range[i],
			 &aes128_gcm_cipher_range[i],
			 aes128_gcm_reference_aad[i],
			 aes128_gcm_reference_aad_length[i],
			 aes128_gcm_reference_plaintext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_ciphertext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_ciphertext[i] +
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_tag_length[i]);
	}
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_GCM algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
void crypto_test_enc_alg_aes128_gcm_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = AES128_GCM_IV_LEN };
	unsigned int test_vec_num = (sizeof(aes128_gcm_reference_length) /
				     sizeof(aes128_gcm_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_gcm_reference_key[i];
		cipher_key.length = sizeof(aes128_gcm_reference_key[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_GCM,
					  cipher_key.length, iv.length))
			continue;
		if (!check_auth_options(ODP_AUTH_ALG_AES_GCM,
					auth_key.length,
					aes128_gcm_reference_tag_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_AES_GCM,
			 iv,
			 aes128_gcm_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_AES_GCM,
			 auth_key,
			 &aes128_gcm_cipher_range[i],
			 &aes128_gcm_cipher_range[i],
			 aes128_gcm_reference_aad[i],
			 aes128_gcm_reference_aad_length[i],
			 aes128_gcm_reference_plaintext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_ciphertext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_ciphertext[i] +
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_tag_length[i]);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_dec_alg_aes128_gcm(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = AES128_GCM_IV_LEN };
	uint8_t wrong_digest[AES128_GCM_DIGEST_LEN];
	unsigned int test_vec_num = (sizeof(aes128_gcm_reference_length) /
				     sizeof(aes128_gcm_reference_length[0]));
	unsigned int i;

	memset(wrong_digest, 0xa5, sizeof(wrong_digest));

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_gcm_reference_key[i];
		cipher_key.length = sizeof(aes128_gcm_reference_key[i]);
		iv.data = aes128_gcm_reference_iv[i];
		iv.length = sizeof(aes128_gcm_reference_iv[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_GCM,
					  cipher_key.length, iv.length))
			continue;
		if (!check_auth_options(ODP_AUTH_ALG_AES_GCM,
					auth_key.length,
					aes128_gcm_reference_tag_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_AES_GCM,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_AES_GCM,
			 auth_key,
			 &aes128_gcm_cipher_range[i],
			 &aes128_gcm_cipher_range[i],
			 aes128_gcm_reference_aad[i],
			 aes128_gcm_reference_aad_length[i],
			 aes128_gcm_reference_ciphertext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_plaintext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_ciphertext[i] +
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_tag_length[i]);

		alg_test(ODP_CRYPTO_OP_DECODE,
			 1,
			 ODP_CIPHER_ALG_AES_GCM,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_AES_GCM,
			 auth_key,
			 &aes128_gcm_cipher_range[i],
			 &aes128_gcm_cipher_range[i],
			 aes128_gcm_reference_aad[i],
			 aes128_gcm_reference_aad_length[i],
			 aes128_gcm_reference_ciphertext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_plaintext[i],
			 aes128_gcm_reference_length[i],
			 wrong_digest,
			 aes128_gcm_reference_tag_length[i]);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_dec_alg_aes128_gcm_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = AES128_GCM_IV_LEN };
	uint8_t wrong_digest[AES128_GCM_DIGEST_LEN];
	unsigned int test_vec_num = (sizeof(aes128_gcm_reference_length) /
				     sizeof(aes128_gcm_reference_length[0]));
	unsigned int i;

	memset(wrong_digest, 0xa5, sizeof(wrong_digest));

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_gcm_reference_key[i];
		cipher_key.length = sizeof(aes128_gcm_reference_key[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_GCM,
					  cipher_key.length, iv.length))
			continue;
		if (!check_auth_options(ODP_AUTH_ALG_AES_GCM,
					auth_key.length,
					aes128_gcm_reference_tag_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_AES_GCM,
			 iv,
			 aes128_gcm_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_AES_GCM,
			 auth_key,
			 &aes128_gcm_cipher_range[i],
			 &aes128_gcm_cipher_range[i],
			 aes128_gcm_reference_aad[i],
			 aes128_gcm_reference_aad_length[i],
			 aes128_gcm_reference_ciphertext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_plaintext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_ciphertext[i] +
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_tag_length[i]);

		alg_test(ODP_CRYPTO_OP_DECODE,
			 1,
			 ODP_CIPHER_ALG_AES_GCM,
			 iv,
			 aes128_gcm_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_AES_GCM,
			 auth_key,
			 &aes128_gcm_cipher_range[i],
			 &aes128_gcm_cipher_range[i],
			 aes128_gcm_reference_aad[i],
			 aes128_gcm_reference_aad_length[i],
			 aes128_gcm_reference_ciphertext[i],
			 aes128_gcm_reference_length[i],
			 aes128_gcm_reference_plaintext[i],
			 aes128_gcm_reference_length[i],
			 wrong_digest,
			 aes128_gcm_reference_tag_length[i]);
	}
}

static int check_alg_aes_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CBC, ODP_AUTH_ALG_NULL);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_CBC algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
void crypto_test_enc_alg_aes128_cbc(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	unsigned int test_vec_num = (sizeof(aes128_cbc_reference_length) /
				     sizeof(aes128_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_cbc_reference_key[i];
		cipher_key.length = sizeof(aes128_cbc_reference_key[i]);
		iv.data = aes128_cbc_reference_iv[i];
		iv.length = sizeof(aes128_cbc_reference_iv[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_AES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 aes128_cbc_reference_plaintext[i],
			 aes128_cbc_reference_length[i],
			 aes128_cbc_reference_ciphertext[i],
			 aes128_cbc_reference_length[i], NULL, 0);
	}
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_CBC algorithm. IV for the operation is the operation IV.
 * */
void crypto_test_enc_alg_aes128_cbc_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = AES128_CBC_IV_LEN };
	unsigned int test_vec_num = (sizeof(aes128_cbc_reference_length) /
				     sizeof(aes128_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_cbc_reference_key[i];
		cipher_key.length = sizeof(aes128_cbc_reference_key[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_AES_CBC,
			 iv,
			 aes128_cbc_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 aes128_cbc_reference_plaintext[i],
			 aes128_cbc_reference_length[i],
			 aes128_cbc_reference_ciphertext[i],
			 aes128_cbc_reference_length[i], NULL, 0);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for AES128_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_dec_alg_aes128_cbc(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };
	unsigned int test_vec_num = (sizeof(aes128_cbc_reference_length) /
				     sizeof(aes128_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_cbc_reference_key[i];
		cipher_key.length = sizeof(aes128_cbc_reference_key[i]);
		iv.data = aes128_cbc_reference_iv[i];
		iv.length = sizeof(aes128_cbc_reference_iv[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_AES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 aes128_cbc_reference_ciphertext[i],
			 aes128_cbc_reference_length[i],
			 aes128_cbc_reference_plaintext[i],
			 aes128_cbc_reference_length[i], NULL, 0);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for AES128_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_dec_alg_aes128_cbc_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = AES128_CBC_IV_LEN };
	unsigned int test_vec_num = (sizeof(aes128_cbc_reference_length) /
				     sizeof(aes128_cbc_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = aes128_cbc_reference_key[i];
		cipher_key.length = sizeof(aes128_cbc_reference_key[i]);

		if (!check_cipher_options(ODP_CIPHER_ALG_AES_CBC,
					  cipher_key.length, iv.length))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_AES_CBC,
			 iv,
			 aes128_cbc_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 aes128_cbc_reference_ciphertext[i],
			 aes128_cbc_reference_length[i],
			 aes128_cbc_reference_plaintext[i],
			 aes128_cbc_reference_length[i], NULL, 0);
	}
}

static int check_alg_hmac_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5_HMAC);
}

/* This test verifies the correctness of HMAC_MD5 digest operation.
 * The output check length is truncated to 12 bytes (96 bits) as
 * returned by the crypto operation API call.
 * Note that hash digest is a one-way operation.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_gen_alg_hmac_md5(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };

	unsigned int test_vec_num = (sizeof(hmac_md5_reference_length) /
				     sizeof(hmac_md5_reference_length[0]));
	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		auth_key.data = hmac_md5_reference_key[i];
		auth_key.length = sizeof(hmac_md5_reference_key[i]);

		if (!check_auth_options(ODP_AUTH_ALG_MD5_HMAC, auth_key.length,
					hmac_md5_reference_digest_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_MD5_HMAC,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 hmac_md5_reference_plaintext[i],
			 hmac_md5_reference_length[i],
			 NULL, 0,
			 hmac_md5_reference_digest[i],
			 hmac_md5_reference_digest_length[i]);
	}
}

void crypto_test_check_alg_hmac_md5(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };
	uint8_t wrong_digest[HMAC_MD5_DIGEST_LEN];

	unsigned int test_vec_num = (sizeof(hmac_md5_reference_length) /
				     sizeof(hmac_md5_reference_length[0]));
	unsigned int i;

	memset(wrong_digest, 0xa5, sizeof(wrong_digest));

	for (i = 0; i < test_vec_num; i++) {
		auth_key.data = hmac_md5_reference_key[i];
		auth_key.length = sizeof(hmac_md5_reference_key[i]);

		if (!check_auth_options(ODP_AUTH_ALG_MD5_HMAC, auth_key.length,
					hmac_md5_reference_digest_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_MD5_HMAC,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 hmac_md5_reference_plaintext[i],
			 hmac_md5_reference_length[i],
			 NULL, 0,
			 hmac_md5_reference_digest[i],
			 hmac_md5_reference_digest_length[i]);

		alg_test(ODP_CRYPTO_OP_DECODE,
			 1,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_MD5_HMAC,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 hmac_md5_reference_plaintext[i],
			 hmac_md5_reference_length[i],
			 NULL, 0,
			 wrong_digest,
			 hmac_md5_reference_digest_length[i]);
	}
}

static int check_alg_hmac_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256_HMAC);
}

/* This test verifies the correctness of HMAC_SHA256 digest operation.
 * The output check length is truncated to 16 bytes (128 bits) as
 * returned by the crypto operation API call.
 * Note that hash digest is a one-way operation.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
void crypto_test_gen_alg_hmac_sha256(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };

	unsigned int test_vec_num = (sizeof(hmac_sha256_reference_length) /
				     sizeof(hmac_sha256_reference_length[0]));

	unsigned int i;

	for (i = 0; i < test_vec_num; i++) {
		auth_key.data = hmac_sha256_reference_key[i];
		auth_key.length = sizeof(hmac_sha256_reference_key[i]);

		if (!check_auth_options(ODP_AUTH_ALG_SHA256_HMAC,
					auth_key.length,
					hmac_sha256_reference_digest_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 0,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_SHA256_HMAC,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 hmac_sha256_reference_plaintext[i],
			 hmac_sha256_reference_length[i],
			 NULL, 0,
			 hmac_sha256_reference_digest[i],
			 hmac_sha256_reference_digest_length[i]);
	}
}

void crypto_test_check_alg_hmac_sha256(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };
	uint8_t wrong_digest[HMAC_SHA256_DIGEST_LEN];

	unsigned int test_vec_num = (sizeof(hmac_sha256_reference_length) /
				     sizeof(hmac_sha256_reference_length[0]));

	unsigned int i;

	memset(wrong_digest, 0xa5, sizeof(wrong_digest));

	for (i = 0; i < test_vec_num; i++) {
		auth_key.data = hmac_sha256_reference_key[i];
		auth_key.length = sizeof(hmac_sha256_reference_key[i]);

		if (!check_auth_options(ODP_AUTH_ALG_SHA256_HMAC,
					auth_key.length,
					hmac_sha256_reference_digest_length[i]))
			continue;

		alg_test(ODP_CRYPTO_OP_DECODE,
			 0,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_SHA256_HMAC,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 hmac_sha256_reference_plaintext[i],
			 hmac_sha256_reference_length[i],
			 NULL, 0,
			 hmac_sha256_reference_digest[i],
			 hmac_sha256_reference_digest_length[i]);

		alg_test(ODP_CRYPTO_OP_DECODE,
			 1,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_SHA256_HMAC,
			 auth_key,
			 NULL, NULL,
			 NULL, 0,
			 hmac_sha256_reference_plaintext[i],
			 hmac_sha256_reference_length[i],
			 NULL, 0,
			 wrong_digest,
			 hmac_sha256_reference_digest_length[i]);
	}
}

static int check_alg_hmac_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1_HMAC);
}

void crypto_test_alg_hmac_sha1(void)
{
	printf(" TEST NOT IMPLEMENTED YET ");
}

static int check_alg_hmac_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512_HMAC);
}

void crypto_test_alg_hmac_sha512(void)
{
	printf(" TEST NOT IMPLEMENTED YET ");
}

int crypto_suite_sync_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	suite_context.pref_mode = ODP_CRYPTO_SYNC;
	return 0;
}

int crypto_suite_async_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;
	suite_context.queue = odp_queue_lookup("crypto-out");
	if (suite_context.queue == ODP_QUEUE_INVALID)
		return -1;

	suite_context.pref_mode = ODP_CRYPTO_ASYNC;
	return 0;
}

odp_testinfo_t crypto_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_null,
				  check_alg_null),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_null,
				  check_alg_null),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_3des_cbc,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_3des_cbc,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_3des_cbc_ovr_iv,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_3des_cbc_ovr_iv,
				  check_alg_3des_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes128_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes128_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes128_cbc_ovr_iv,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes128_cbc_ovr_iv,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes128_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes128_gcm_ovr_iv,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes128_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes128_gcm_ovr_iv,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_alg_hmac_sha1,
				  check_alg_hmac_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha256,
				  check_alg_hmac_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha256,
				  check_alg_hmac_sha256),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_alg_hmac_sha512,
				  check_alg_hmac_sha512),
	ODP_TEST_INFO_NULL,
};

int crypto_suite_term(void)
{
	int i;
	int first = 1;

	for (i = 0; crypto_suite[i].pName; i++) {
		if (crypto_suite[i].check_active &&
		    crypto_suite[i].check_active() == ODP_TEST_INACTIVE) {
			if (first) {
				first = 0;
				printf("\n\n  Inactive tests:\n");
			}
			printf("    %s\n", crypto_suite[i].pName);
		}
	}
	return 0;
}
