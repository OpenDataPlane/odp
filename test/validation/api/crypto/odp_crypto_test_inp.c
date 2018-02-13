/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include "test_vectors.h"
#include "odp_crypto_test_inp.h"
#include "crypto.h"

#define MAX_ALG_CAPA 32

struct suite_context_s {
	odp_bool_t packet;
	odp_crypto_op_mode_t op_mode;
	odp_crypto_op_mode_t pref_mode;
	odp_pool_t pool;
	odp_queue_t queue;
};

static struct suite_context_s suite_context;

static int packet_cmp_mem(odp_packet_t pkt, uint32_t offset,
			  void *s, uint32_t len)
{
	uint8_t buf[len];

	odp_packet_copy_to_mem(pkt, offset, len, buf);

	return memcmp(buf, s, len);
}

static const char *auth_alg_name(odp_auth_alg_t auth)
{
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		return "ODP_AUTH_ALG_NULL";
	case ODP_AUTH_ALG_MD5_HMAC:
		return "ODP_AUTH_ALG_MD5_HMAC";
	case ODP_AUTH_ALG_SHA1_HMAC:
		return "ODP_AUTH_ALG_SHA1_HMAC";
	case ODP_AUTH_ALG_SHA256_HMAC:
		return "ODP_AUTH_ALG_SHA256_HMAC";
	case ODP_AUTH_ALG_SHA384_HMAC:
		return "ODP_AUTH_ALG_SHA384_HMAC";
	case ODP_AUTH_ALG_SHA512_HMAC:
		return "ODP_AUTH_ALG_SHA512_HMAC";
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		return "ODP_AUTH_ALG_AES_XCBC_MAC";
	case ODP_AUTH_ALG_AES_GCM:
		return "ODP_AUTH_ALG_AES_GCM";
	case ODP_AUTH_ALG_AES_GMAC:
		return "ODP_AUTH_ALG_AES_GMAC";
	case ODP_AUTH_ALG_AES_CCM:
		return "ODP_AUTH_ALG_AES_CCM";
	case ODP_AUTH_ALG_AES_CMAC:
		return "ODP_AUTH_ALG_AES_CMAC";
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		return "ODP_AUTH_ALG_CHACHA20_POLY1305";
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
	case ODP_CIPHER_ALG_AES_CCM:
		return "ODP_CIPHER_ALG_AES_CCM";
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		return "ODP_CIPHER_ALG_CHACHA20_POLY1305";
	default:
		return "Unknown";
	}
}

static int alg_op(odp_packet_t pkt,
		  odp_bool_t *ok,
		  odp_crypto_session_t session,
		  uint8_t *cipher_iv_ptr,
		  uint8_t *auth_iv_ptr,
		  odp_packet_data_range_t *cipher_range,
		  odp_packet_data_range_t *auth_range,
		  uint8_t *aad,
		  unsigned int plaintext_len)
{
	int rc;
	odp_crypto_op_result_t result;
	odp_crypto_op_param_t op_params;
	odp_bool_t posted;
	odp_event_subtype_t subtype;

	/* Prepare input/output params */
	memset(&op_params, 0, sizeof(op_params));
	op_params.session = session;
	op_params.pkt = pkt;
	op_params.out_pkt = pkt;
	op_params.ctx = (void *)0xdeadbeef;

	op_params.cipher_range = *cipher_range;
	op_params.auth_range = *auth_range;
	if (cipher_iv_ptr)
		op_params.cipher_iv_ptr = cipher_iv_ptr;
	if (auth_iv_ptr)
		op_params.auth_iv_ptr = auth_iv_ptr;

	op_params.aad_ptr = aad;

	op_params.hash_result_offset = plaintext_len;

	rc = odp_crypto_operation(&op_params, &posted, &result);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_operation()");
		return rc;
	}

	if (posted) {
		odp_event_t event;
		odp_crypto_compl_t compl_event;

		/* Poll completion queue for results */
		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT(ODP_EVENT_CRYPTO_COMPL == odp_event_type(event));
		CU_ASSERT(ODP_EVENT_NO_SUBTYPE == odp_event_subtype(event));
		CU_ASSERT(ODP_EVENT_CRYPTO_COMPL ==
			  odp_event_types(event, &subtype));
		CU_ASSERT(ODP_EVENT_NO_SUBTYPE == subtype);

		compl_event = odp_crypto_compl_from_event(event);
		CU_ASSERT(odp_crypto_compl_to_u64(compl_event) ==
			  odp_crypto_compl_to_u64(
				  odp_crypto_compl_from_event(event)));
		odp_crypto_compl_result(compl_event, &result);
		odp_crypto_compl_free(compl_event);
	}

	CU_ASSERT(result.pkt == pkt);
	CU_ASSERT(result.ctx == (void *)0xdeadbeef);
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_type(odp_packet_to_event(result.pkt)));
	CU_ASSERT(ODP_EVENT_PACKET_BASIC ==
		  odp_event_subtype(odp_packet_to_event(result.pkt)));
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_types(odp_packet_to_event(result.pkt), &subtype));
	CU_ASSERT(ODP_EVENT_PACKET_BASIC == subtype);

	*ok = result.ok;

	return 0;
}

static int alg_packet_op(odp_packet_t pkt,
			 odp_bool_t *ok,
			 odp_crypto_session_t session,
			 uint8_t *cipher_iv_ptr,
			 uint8_t *auth_iv_ptr,
			 odp_packet_data_range_t *cipher_range,
			 odp_packet_data_range_t *auth_range,
			 uint8_t *aad,
			 unsigned int plaintext_len)
{
	int rc;
	odp_crypto_packet_result_t result;
	odp_crypto_packet_op_param_t op_params;
	odp_event_subtype_t subtype;
	odp_packet_t out_pkt = pkt;

	/* Prepare input/output params */
	memset(&op_params, 0, sizeof(op_params));
	op_params.session = session;

	op_params.cipher_range = *cipher_range;
	op_params.auth_range = *auth_range;
	if (cipher_iv_ptr)
		op_params.cipher_iv_ptr = cipher_iv_ptr;
	if (auth_iv_ptr)
		op_params.auth_iv_ptr = auth_iv_ptr;

	op_params.aad_ptr = aad;

	op_params.hash_result_offset = plaintext_len;

	rc = odp_crypto_op(&pkt, &out_pkt, &op_params, 1);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_packet_op()");
		return rc;
	}

	CU_ASSERT(out_pkt == pkt);
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_type(odp_packet_to_event(pkt)));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO ==
		  odp_event_subtype(odp_packet_to_event(pkt)));
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_types(odp_packet_to_event(pkt), &subtype));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == subtype);

	rc = odp_crypto_result(&result, pkt);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_packet_result()");
		return rc;
	}

	if (!result.ok)
		CU_ASSERT(odp_packet_has_error(pkt));

	*ok = result.ok;

	return 0;
}

static int alg_packet_op_enq(odp_packet_t pkt,
			     odp_bool_t *ok,
			     odp_crypto_session_t session,
			     uint8_t *cipher_iv_ptr,
			     uint8_t *auth_iv_ptr,
			     odp_packet_data_range_t *cipher_range,
			     odp_packet_data_range_t *auth_range,
			     uint8_t *aad,
			     unsigned int plaintext_len)
{
	int rc;
	odp_event_t event;
	odp_crypto_packet_result_t result;
	odp_crypto_packet_op_param_t op_params;
	odp_event_subtype_t subtype;
	odp_packet_t out_pkt = pkt;

	/* Prepare input/output params */
	memset(&op_params, 0, sizeof(op_params));
	op_params.session = session;

	op_params.cipher_range = *cipher_range;
	op_params.auth_range = *auth_range;
	if (cipher_iv_ptr)
		op_params.cipher_iv_ptr = cipher_iv_ptr;
	if (auth_iv_ptr)
		op_params.auth_iv_ptr = auth_iv_ptr;

	op_params.aad_ptr = aad;

	op_params.hash_result_offset = plaintext_len;

	rc = odp_crypto_op_enq(&pkt, &pkt, &op_params, 1);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_op_enq()");
		return rc;
	}

	/* Poll completion queue for results */
	do {
		event = odp_queue_deq(suite_context.queue);
	} while (event == ODP_EVENT_INVALID);

	CU_ASSERT(ODP_EVENT_PACKET == odp_event_type(event));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == odp_event_subtype(event));
	CU_ASSERT(ODP_EVENT_PACKET == odp_event_types(event, &subtype));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == subtype);

	pkt = odp_crypto_packet_from_event(event);

	CU_ASSERT(out_pkt == pkt);
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_type(odp_packet_to_event(pkt)));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO ==
		  odp_event_subtype(odp_packet_to_event(pkt)));
	CU_ASSERT(ODP_EVENT_PACKET ==
		  odp_event_types(odp_packet_to_event(pkt), &subtype));
	CU_ASSERT(ODP_EVENT_PACKET_CRYPTO == subtype);

	rc = odp_crypto_result(&result, pkt);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_packet_result()");
		return rc;
	}

	CU_ASSERT((!odp_packet_has_error(pkt)) == result.ok);

	*ok = result.ok;

	return 0;
}

typedef enum crypto_test {
	NORMAL_TEST = 0,   /**< Plain execution */
	REPEAT_TEST,       /**< Rerun without reinitializing the session */
	WRONG_DIGEST_TEST, /**< Check against wrong digest */
	MAX_TEST,          /**< Final mark */
} crypto_test;

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
		     odp_cipher_alg_t cipher_alg,
		     odp_auth_alg_t auth_alg,
		     crypto_test_reference_t *ref,
		     odp_bool_t ovr_iv)
{
	odp_crypto_session_t session;
	int rc;
	odp_crypto_ses_create_err_t status;
	odp_bool_t ok = false;
	int iteration;
	odp_crypto_session_param_t ses_params;
	odp_packet_data_range_t cipher_range;
	odp_packet_data_range_t auth_range;
	odp_crypto_key_t cipher_key = {
		.data = ref->cipher_key,
		.length = ref->cipher_key_length
	};
	odp_crypto_key_t auth_key = {
		.data = ref->auth_key,
		.length = ref->auth_key_length
	};
	odp_crypto_iv_t cipher_iv = {
		.data = ovr_iv ? NULL : ref->cipher_iv,
		.length = ref->cipher_iv_length
	};
	odp_crypto_iv_t auth_iv = {
		.data = ovr_iv ? NULL : ref->auth_iv,
		.length = ref->auth_iv_length
	};

	/* Create a crypto session */
	odp_crypto_session_param_init(&ses_params);
	ses_params.op = op;
	ses_params.auth_cipher_text = false;
	ses_params.op_mode = suite_context.op_mode;
	ses_params.pref_mode = suite_context.pref_mode;
	ses_params.cipher_alg = cipher_alg;
	ses_params.auth_alg = auth_alg;
	ses_params.compl_queue = suite_context.queue;
	ses_params.output_pool = suite_context.pool;
	ses_params.cipher_key = cipher_key;
	ses_params.cipher_iv = cipher_iv;
	ses_params.auth_iv = auth_iv;
	ses_params.auth_key = auth_key;
	ses_params.auth_digest_len = ref->digest_length;
	ses_params.auth_aad_len = ref->aad_length;

	rc = odp_crypto_session_create(&ses_params, &session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_CREATE_ERR_NONE);
	CU_ASSERT(odp_crypto_session_to_u64(session) !=
		  odp_crypto_session_to_u64(ODP_CRYPTO_SESSION_INVALID));

	cipher_range.offset = 0;
	cipher_range.length = ref->length;
	auth_range.offset = 0;
	auth_range.length = ref->length;

	/* Prepare input data */
	odp_packet_t pkt = odp_packet_alloc(suite_context.pool,
					    ref->length + ref->digest_length);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	if (pkt == ODP_PACKET_INVALID)
		goto cleanup;

	for (iteration = NORMAL_TEST; iteration < MAX_TEST; iteration++) {
		/* checking against wrong digest is meaningless for NULL digest
		 * or when generating digest */
		if (iteration == WRONG_DIGEST_TEST &&
		    (auth_alg == ODP_AUTH_ALG_NULL ||
		     op == ODP_CRYPTO_OP_ENCODE))
			continue;

		if (op == ODP_CRYPTO_OP_ENCODE) {
			odp_packet_copy_from_mem(pkt, 0, ref->length,
						 ref->plaintext);
		} else {
			odp_packet_copy_from_mem(pkt, 0, ref->length,
						 ref->ciphertext);
			odp_packet_copy_from_mem(pkt, ref->length,
						 ref->digest_length,
						 ref->digest);
			if (iteration == WRONG_DIGEST_TEST) {
				uint8_t byte = ~ref->digest[0];

				odp_packet_copy_from_mem(pkt, ref->length,
							 1, &byte);
			}
		}

		if (!suite_context.packet)
			rc = alg_op(pkt, &ok, session,
				    ovr_iv ? ref->cipher_iv : NULL,
				    ovr_iv ? ref->auth_iv : NULL,
				    &cipher_range, &auth_range,
				    ref->aad, ref->length);
		else if (ODP_CRYPTO_ASYNC == suite_context.op_mode)
			rc = alg_packet_op_enq(pkt, &ok, session,
					       ovr_iv ? ref->cipher_iv : NULL,
					       ovr_iv ? ref->auth_iv : NULL,
					       &cipher_range, &auth_range,
					       ref->aad, ref->length);
		else
			rc = alg_packet_op(pkt, &ok, session,
					   ovr_iv ? ref->cipher_iv : NULL,
					   ovr_iv ? ref->auth_iv : NULL,
					   &cipher_range, &auth_range,
					   ref->aad, ref->length);
		if (rc < 0)
			break;

		if (iteration == WRONG_DIGEST_TEST) {
			CU_ASSERT(!ok);
			continue;
		}

		CU_ASSERT(ok);

		if (op == ODP_CRYPTO_OP_ENCODE) {
			CU_ASSERT(!packet_cmp_mem(pkt, 0,
						  ref->ciphertext,
						  ref->length));
			CU_ASSERT(!packet_cmp_mem(pkt, ref->length,
						  ref->digest,
						  ref->digest_length));
		} else {
			CU_ASSERT(!packet_cmp_mem(pkt, 0,
						  ref->plaintext,
						  ref->length));
		}
	}

	odp_packet_free(pkt);

cleanup:
	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(!rc);
}

static void check_alg(odp_crypto_op_t op,
		      odp_cipher_alg_t cipher_alg,
		      odp_auth_alg_t auth_alg,
		      crypto_test_reference_t *ref,
		      size_t count,
		      odp_bool_t ovr_iv)
{
	odp_crypto_capability_t capa;
	odp_crypto_cipher_capability_t cipher_capa[MAX_ALG_CAPA];
	odp_crypto_auth_capability_t   auth_capa[MAX_ALG_CAPA];
	int rc, cipher_num, auth_num, i;
	odp_bool_t cipher_tested[MAX_ALG_CAPA];
	odp_bool_t auth_tested[MAX_ALG_CAPA];
	odp_bool_t cipher_ok = false;
	odp_bool_t auth_ok = false;
	size_t idx;

	rc = odp_crypto_capability(&capa);
	CU_ASSERT(!rc);

	if (cipher_alg == ODP_CIPHER_ALG_3DES_CBC &&
	    !(capa.ciphers.bit.trides_cbc))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_AES_CBC &&
	    !(capa.ciphers.bit.aes_cbc))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_AES_CTR &&
	    !(capa.ciphers.bit.aes_ctr))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_AES_GCM &&
	    !(capa.ciphers.bit.aes_gcm))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_AES_CCM &&
	    !(capa.ciphers.bit.aes_ccm))
		rc = -1;
	if (cipher_alg == ODP_CIPHER_ALG_CHACHA20_POLY1305 &&
	    !(capa.ciphers.bit.chacha20_poly1305))
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
	if (auth_alg == ODP_AUTH_ALG_AES_GMAC &&
	    !(capa.auths.bit.aes_gmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_AES_CMAC &&
	    !(capa.auths.bit.aes_cmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_AES_CCM &&
	    !(capa.auths.bit.aes_ccm))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_CHACHA20_POLY1305 &&
	    !(capa.auths.bit.chacha20_poly1305))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_MD5_HMAC &&
	    !(capa.auths.bit.md5_hmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_NULL &&
	    !(capa.auths.bit.null))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_SHA1_HMAC &&
	    !(capa.auths.bit.sha1_hmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_SHA256_HMAC &&
	    !(capa.auths.bit.sha256_hmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_SHA384_HMAC &&
	    !(capa.auths.bit.sha384_hmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_SHA512_HMAC &&
	    !(capa.auths.bit.sha512_hmac))
		rc = -1;
	if (auth_alg == ODP_AUTH_ALG_AES_XCBC_MAC &&
	    !(capa.auths.bit.aes_xcbc_mac))
		rc = -1;

	CU_ASSERT(!rc);
	CU_ASSERT((~capa.auths.all_bits & capa.hw_auths.all_bits) == 0);

	cipher_num = odp_crypto_cipher_capability(cipher_alg, cipher_capa,
						  MAX_ALG_CAPA);

	CU_ASSERT(cipher_num > 0);
	CU_ASSERT(cipher_num <= MAX_ALG_CAPA);
	if (cipher_num > MAX_ALG_CAPA)
		cipher_num = MAX_ALG_CAPA;

	auth_num = odp_crypto_auth_capability(auth_alg, auth_capa,
					      MAX_ALG_CAPA);

	CU_ASSERT(auth_num > 0);
	CU_ASSERT(auth_num <= MAX_ALG_CAPA);
	if (auth_num > MAX_ALG_CAPA)
		auth_num = MAX_ALG_CAPA;

	memset(cipher_tested, 0, sizeof(cipher_tested));
	memset(auth_tested, 0, sizeof(auth_tested));

	for (idx = 0; idx < count; idx++) {
		int cipher_idx = -1, auth_idx = -1;

		for (i = 0; i < cipher_num; i++) {
			if (cipher_capa[i].key_len ==
			    ref[idx].cipher_key_length &&
			    cipher_capa[i].iv_len ==
			    ref[idx].cipher_iv_length) {
				cipher_idx = i;
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
			    ref[idx].auth_key_length) {
				auth_idx = i;
				break;
			}
		}

		if (auth_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 ", digest_len=%" PRIu32 "\n",
			       auth_alg_name(auth_alg),
			       ref[idx].auth_key_length,
			       ref[idx].auth_iv_length,
			       ref[idx].digest_length);
			continue;
		}

		alg_test(op, cipher_alg, auth_alg, &ref[idx], ovr_iv);

		cipher_tested[cipher_idx] = true;
		auth_tested[auth_idx] = true;
	}

	for (i = 0; i < cipher_num; i++) {
		cipher_ok |= cipher_tested[i];
		if (!cipher_tested[i]) {
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "iv_len=%" PRIu32 "\n",
			       cipher_alg_name(cipher_alg),
			       cipher_capa[i].key_len,
			       cipher_capa[i].iv_len);
		}
	}

	for (i = 0; i < auth_num; i++) {
		auth_ok |= auth_tested[i];
		if (!auth_tested[i])
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "digest_len=%" PRIu32 "\n",
			       auth_alg_name(auth_alg),
			       auth_capa[i].key_len,
			       auth_capa[i].digest_len);
	}

	/* Verify that we were able to run at least several tests */
	CU_ASSERT(cipher_ok);
	CU_ASSERT(auth_ok);
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

	if (suite_context.packet) {
		if (suite_context.op_mode == ODP_CRYPTO_SYNC &&
		    capability.sync_mode == ODP_SUPPORT_NO)
			return ODP_TEST_INACTIVE;
		if (suite_context.op_mode == ODP_CRYPTO_ASYNC &&
		    capability.async_mode == ODP_SUPPORT_NO)
			return ODP_TEST_INACTIVE;
	}

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
	case ODP_CIPHER_ALG_AES_CTR:
		if (!capability.ciphers.bit.aes_ctr)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (!capability.ciphers.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		if (!capability.ciphers.bit.aes_ccm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		if (!capability.ciphers.bit.chacha20_poly1305)
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
	case ODP_AUTH_ALG_SHA384_HMAC:
		if (!capability.auths.bit.sha384_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (!capability.auths.bit.sha512_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		if (!capability.auths.bit.aes_xcbc_mac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (!capability.auths.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (!capability.auths.bit.aes_gmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		if (!capability.auths.bit.aes_ccm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		if (!capability.auths.bit.aes_cmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		if (!capability.auths.bit.chacha20_poly1305)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static int check_alg_null(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_NULL);
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
static void crypto_test_enc_alg_null(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_NULL,
		  null_reference,
		  ARRAY_SIZE(null_reference),
		  false);
}

static void crypto_test_dec_alg_null(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_NULL,
		  null_reference,
		  ARRAY_SIZE(null_reference),
		  false);
}

static int check_alg_3des_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_CBC, ODP_AUTH_ALG_NULL);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
static void crypto_test_enc_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_3DES_CBC,
		  ODP_AUTH_ALG_NULL,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference),
		  false);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the operation IV.
 * */
static void crypto_test_enc_alg_3des_cbc_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_3DES_CBC,
		  ODP_AUTH_ALG_NULL,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference),
		  true);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_3DES_CBC,
		  ODP_AUTH_ALG_NULL,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference),
		  false);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_3des_cbc_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_3DES_CBC,
		  ODP_AUTH_ALG_NULL,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference),
		  true);
}

static int check_alg_chacha20_poly1305(void)
{
	return check_alg_support(ODP_CIPHER_ALG_CHACHA20_POLY1305,
				 ODP_AUTH_ALG_CHACHA20_POLY1305);
}

static void crypto_test_enc_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_CHACHA20_POLY1305,
		  ODP_AUTH_ALG_CHACHA20_POLY1305,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference),
		  false);
}

static void crypto_test_enc_alg_chacha20_poly1305_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_CHACHA20_POLY1305,
		  ODP_AUTH_ALG_CHACHA20_POLY1305,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference),
		  true);
}

static void crypto_test_dec_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_CHACHA20_POLY1305,
		  ODP_AUTH_ALG_CHACHA20_POLY1305,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference),
		  false);
}

static void crypto_test_dec_alg_chacha20_poly1305_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_CHACHA20_POLY1305,
		  ODP_AUTH_ALG_CHACHA20_POLY1305,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference),
		  true);
}

static int check_alg_aes_gcm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_GCM, ODP_AUTH_ALG_AES_GCM);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_GCM algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
static void crypto_test_enc_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_GCM,
		  ODP_AUTH_ALG_AES_GCM,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference),
		  false);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_GCM algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
static void crypto_test_enc_alg_aes_gcm_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_GCM,
		  ODP_AUTH_ALG_AES_GCM,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference),
		  true);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_GCM,
		  ODP_AUTH_ALG_AES_GCM,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference),
		  false);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_aes_gcm_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_GCM,
		  ODP_AUTH_ALG_AES_GCM,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference),
		  true);
}

static int check_alg_aes_ccm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CCM, ODP_AUTH_ALG_AES_CCM);
}

static void crypto_test_enc_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CCM,
		  ODP_AUTH_ALG_AES_CCM,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference),
		  false);
}

static void crypto_test_enc_alg_aes_ccm_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CCM,
		  ODP_AUTH_ALG_AES_CCM,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference),
		  true);
}

static void crypto_test_dec_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CCM,
		  ODP_AUTH_ALG_AES_CCM,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference),
		  false);
}

static void crypto_test_dec_alg_aes_ccm_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CCM,
		  ODP_AUTH_ALG_AES_CCM,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference),
		  true);
}

static int check_alg_aes_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CBC, ODP_AUTH_ALG_NULL);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_CBC algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
static void crypto_test_enc_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CBC,
		  ODP_AUTH_ALG_NULL,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference),
		  false);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_CBC algorithm. IV for the operation is the operation IV.
 * */
static void crypto_test_enc_alg_aes_cbc_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CBC,
		  ODP_AUTH_ALG_NULL,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference),
		  true);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for AES128_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CBC,
		  ODP_AUTH_ALG_NULL,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference),
		  false);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for AES128_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_aes_cbc_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CBC,
		  ODP_AUTH_ALG_NULL,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference),
		  true);
}

static int check_alg_aes_ctr(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CTR, ODP_AUTH_ALG_NULL);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_CTR algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
static void crypto_test_enc_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CTR,
		  ODP_AUTH_ALG_NULL,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference),
		  false);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for AES128_CTR algorithm. IV for the operation is the operation IV.
 * */
static void crypto_test_enc_alg_aes_ctr_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CTR,
		  ODP_AUTH_ALG_NULL,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference),
		  true);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for AES128_CTR algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CTR,
		  ODP_AUTH_ALG_NULL,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference),
		  false);
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for AES128_CTR algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_dec_alg_aes_ctr_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CTR,
		  ODP_AUTH_ALG_NULL,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference),
		  true);
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
static void crypto_test_gen_alg_hmac_md5(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_MD5_HMAC,
		  hmac_md5_reference,
		  ARRAY_SIZE(hmac_md5_reference),
		  false);
}

static void crypto_test_check_alg_hmac_md5(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_MD5_HMAC,
		  hmac_md5_reference,
		  ARRAY_SIZE(hmac_md5_reference),
		  false);
}

static int check_alg_hmac_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1_HMAC);
}

/* This test verifies the correctness of HMAC_SHA1 digest operation.
 * The output check length is truncated to 12 bytes (96 bits) as
 * returned by the crypto operation API call.
 * Note that hash digest is a one-way operation.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_gen_alg_hmac_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA1_HMAC,
		  hmac_sha1_reference,
		  ARRAY_SIZE(hmac_sha1_reference),
		  false);
}

static void crypto_test_check_alg_hmac_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA1_HMAC,
		  hmac_sha1_reference,
		  ARRAY_SIZE(hmac_sha1_reference),
		  false);
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
static void crypto_test_gen_alg_hmac_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA256_HMAC,
		  hmac_sha256_reference,
		  ARRAY_SIZE(hmac_sha256_reference),
		  false);
}

static void crypto_test_check_alg_hmac_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA256_HMAC,
		  hmac_sha256_reference,
		  ARRAY_SIZE(hmac_sha256_reference),
		  false);
}

static int check_alg_hmac_sha384(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA384_HMAC);
}

/* This test verifies the correctness of HMAC_SHA384 digest operation.
 * The output check length is truncated to 24 bytes (192 bits) as
 * returned by the crypto operation API call.
 * Note that hash digest is a one-way operation.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_gen_alg_hmac_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA384_HMAC,
		  hmac_sha384_reference,
		  ARRAY_SIZE(hmac_sha384_reference),
		  false);
}

static void crypto_test_check_alg_hmac_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA384_HMAC,
		  hmac_sha384_reference,
		  ARRAY_SIZE(hmac_sha384_reference),
		  false);
}

static int check_alg_hmac_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512_HMAC);
}

/* This test verifies the correctness of HMAC_SHA512 digest operation.
 * The output check length is truncated to 32 bytes (256 bits) as
 * returned by the crypto operation API call.
 * Note that hash digest is a one-way operation.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
static void crypto_test_gen_alg_hmac_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA512_HMAC,
		  hmac_sha512_reference,
		  ARRAY_SIZE(hmac_sha512_reference),
		  false);
}

static void crypto_test_check_alg_hmac_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA512_HMAC,
		  hmac_sha512_reference,
		  ARRAY_SIZE(hmac_sha512_reference),
		  false);
}

static int check_alg_aes_xcbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_XCBC_MAC);
}

static void crypto_test_gen_alg_aes_xcbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_XCBC_MAC,
		  aes_xcbc_reference,
		  ARRAY_SIZE(aes_xcbc_reference),
		  false);
}

static void crypto_test_check_alg_aes_xcbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_XCBC_MAC,
		  aes_xcbc_reference,
		  ARRAY_SIZE(aes_xcbc_reference),
		  false);
}

static int check_alg_aes_gmac(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_GMAC);
}

static void crypto_test_gen_alg_aes_gmac(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_GMAC,
		  aes_gmac_reference,
		  ARRAY_SIZE(aes_gmac_reference),
		  false);
}

static void crypto_test_gen_alg_aes_gmac_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_GMAC,
		  aes_gmac_reference,
		  ARRAY_SIZE(aes_gmac_reference),
		  true);
}

static void crypto_test_check_alg_aes_gmac(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_GMAC,
		  aes_gmac_reference,
		  ARRAY_SIZE(aes_gmac_reference),
		  false);
}

static void crypto_test_check_alg_aes_gmac_ovr_iv(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_GMAC,
		  aes_gmac_reference,
		  ARRAY_SIZE(aes_gmac_reference),
		  false);
}

static int check_alg_aes_cmac(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_AES_CMAC);
}

static void crypto_test_gen_alg_aes_cmac(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_CMAC,
		  aes_cmac_reference,
		  ARRAY_SIZE(aes_cmac_reference),
		  false);
}

static void crypto_test_check_alg_aes_cmac(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_CMAC,
		  aes_cmac_reference,
		  ARRAY_SIZE(aes_cmac_reference),
		  false);
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

int crypto_suite_packet_sync_init(void)
{
	suite_context.packet = true;
	suite_context.op_mode = ODP_CRYPTO_SYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	return 0;
}

int crypto_suite_packet_async_init(void)
{
	suite_context.packet = true;
	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = odp_queue_lookup("crypto-out");
	if (suite_context.queue == ODP_QUEUE_INVALID)
		return -1;
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
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_cbc,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_cbc_ovr_iv,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_cbc_ovr_iv,
				  check_alg_aes_cbc),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ctr,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ctr,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ctr_ovr_iv,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ctr_ovr_iv,
				  check_alg_aes_ctr),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_gcm_ovr_iv,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_gcm,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_gcm_ovr_iv,
				  check_alg_aes_gcm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ccm,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_aes_ccm_ovr_iv,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ccm,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_aes_ccm_ovr_iv,
				  check_alg_aes_ccm),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_chacha20_poly1305,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_enc_alg_chacha20_poly1305_ovr_iv,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_chacha20_poly1305,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_dec_alg_chacha20_poly1305_ovr_iv,
				  check_alg_chacha20_poly1305),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_md5,
				  check_alg_hmac_md5),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_hmac_sha1,
				  check_alg_hmac_sha1),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_hmac_sha1,
				  check_alg_hmac_sha1),
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
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_gmac_ovr_iv,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_gmac,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_gmac_ovr_iv,
				  check_alg_aes_gmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_gen_alg_aes_cmac,
				  check_alg_aes_cmac),
	ODP_TEST_INFO_CONDITIONAL(crypto_test_check_alg_aes_cmac,
				  check_alg_aes_cmac),
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
