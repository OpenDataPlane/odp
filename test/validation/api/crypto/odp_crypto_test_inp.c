/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include "test_vectors.h"

#define PKT_POOL_NUM  64
#define PKT_POOL_LEN  (1 * 1024)

struct suite_context_s {
	odp_bool_t packet;
	odp_crypto_op_mode_t op_mode;
	odp_crypto_op_mode_t pref_mode;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_queue_type_t q_type;
	odp_event_t (*compl_queue_deq)(void);
};

static struct suite_context_s suite_context;

static void test_default_values(void)
{
	odp_crypto_session_param_t param;

	memset(&param, 0x55, sizeof(param));
	odp_crypto_session_param_init(&param);

	CU_ASSERT_EQUAL(param.op, ODP_CRYPTO_OP_ENCODE);
	CU_ASSERT_EQUAL(param.auth_cipher_text, false);
	CU_ASSERT_EQUAL(param.pref_mode, ODP_CRYPTO_SYNC);
	CU_ASSERT_EQUAL(param.op_mode, ODP_CRYPTO_SYNC);
	CU_ASSERT_EQUAL(param.cipher_alg, ODP_CIPHER_ALG_NULL);
	CU_ASSERT_EQUAL(param.cipher_iv_len, 0);
	CU_ASSERT_EQUAL(param.auth_alg, ODP_AUTH_ALG_NULL);
	CU_ASSERT_EQUAL(param.auth_iv_len, 0);
	CU_ASSERT_EQUAL(param.auth_aad_len, 0);

#if ODP_DEPRECATED_API
	CU_ASSERT_EQUAL(param.cipher_iv.data, NULL);
	CU_ASSERT_EQUAL(param.cipher_iv.length, 0);
	CU_ASSERT_EQUAL(param.auth_iv.data, NULL);
	CU_ASSERT_EQUAL(param.auth_iv.length, 0);
#endif
}

static int packet_cmp_mem_bits(odp_packet_t pkt, uint32_t offset,
			       uint8_t *s, uint32_t len)
{
	int rc = -1;
	uint32_t len_bytes = ((len + 7) / 8);
	uint8_t leftover_bits = len % 8;
	uint8_t buf[len_bytes];

	odp_packet_copy_to_mem(pkt, offset, len_bytes, buf);

	/* Compare till the last full byte */
	rc = memcmp(buf, s, leftover_bits ? len_bytes - 1 : len_bytes);

	if (rc == 0 && leftover_bits) {
		/* Do masked comparison for the leftover bits */
		uint8_t mask = 0xff << (8 - leftover_bits);

		rc = !((mask & buf[len_bytes - 1]) ==
		       (mask & s[len_bytes - 1]));
	}

	return rc;
}

static int packet_cmp_mem_bytes(odp_packet_t pkt, uint32_t offset,
				uint8_t *s, uint32_t len)
{
	uint8_t buf[len];

	odp_packet_copy_to_mem(pkt, offset, len, buf);

	return memcmp(buf, s, len);
}

static int packet_cmp_mem(odp_packet_t pkt, uint32_t offset,
			  uint8_t *s, uint32_t len, odp_bool_t bit_mode)
{
	int rc = -1;

	if (bit_mode)
		rc = packet_cmp_mem_bits(pkt, offset, s, len);
	else
		rc = packet_cmp_mem_bytes(pkt, offset, s, len);

	return rc;
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
	case ODP_AUTH_ALG_SHA224_HMAC:
		return "ODP_AUTH_ALG_SHA224_HMAC";
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
	case ODP_AUTH_ALG_KASUMI_F9:
		return "ODP_AUTH_ALG_KASUMI_F9";
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		return "ODP_AUTH_ALG_SNOW3G_UIA2";
	case ODP_AUTH_ALG_AES_EIA2:
		return "ODP_AUTH_ALG_AES_EIA2";
	case ODP_AUTH_ALG_ZUC_EIA3:
		return "ODP_AUTH_ALG_ZUC_EIA3";
	case ODP_AUTH_ALG_MD5:
		return "ODP_AUTH_ALG_MD5";
	case ODP_AUTH_ALG_SHA1:
		return "ODP_AUTH_ALG_SHA1";
	case ODP_AUTH_ALG_SHA224:
		return "ODP_AUTH_ALG_SHA224";
	case ODP_AUTH_ALG_SHA256:
		return "ODP_AUTH_ALG_SHA256";
	case ODP_AUTH_ALG_SHA384:
		return "ODP_AUTH_ALG_SHA384";
	case ODP_AUTH_ALG_SHA512:
		return "ODP_AUTH_ALG_SHA512";
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
	case ODP_CIPHER_ALG_3DES_ECB:
		return "ODP_CIPHER_ALG_3DES_ECB";
	case ODP_CIPHER_ALG_AES_CBC:
		return "ODP_CIPHER_ALG_AES_CBC";
	case ODP_CIPHER_ALG_AES_CTR:
		return "ODP_CIPHER_ALG_AES_CTR";
	case ODP_CIPHER_ALG_AES_ECB:
		return "ODP_CIPHER_ALG_AES_ECB";
	case ODP_CIPHER_ALG_AES_CFB128:
		return "ODP_CIPHER_ALG_AES_CFB128";
	case ODP_CIPHER_ALG_AES_XTS:
		return "ODP_CIPHER_ALG_AES_XTS";
	case ODP_CIPHER_ALG_AES_GCM:
		return "ODP_CIPHER_ALG_AES_GCM";
	case ODP_CIPHER_ALG_AES_CCM:
		return "ODP_CIPHER_ALG_AES_CCM";
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		return "ODP_CIPHER_ALG_CHACHA20_POLY1305";
	case ODP_CIPHER_ALG_KASUMI_F8:
		return "ODP_CIPHER_ALG_KASUMI_F8";
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		return "ODP_CIPHER_ALG_SNOW3G_UEA2";
	case ODP_CIPHER_ALG_AES_EEA2:
		return "ODP_CIPHER_ALG_AES_EEA2";
	case ODP_CIPHER_ALG_ZUC_EEA3:
		return "ODP_CIPHER_ALG_ZUC_EEA3";
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
		  unsigned int hash_result_offset)
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

	op_params.hash_result_offset = hash_result_offset;

	rc = odp_crypto_operation(&op_params, &posted, &result);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_operation()");
		return rc;
	}

	if (posted) {
		odp_event_t event;
		odp_crypto_compl_t compl_event;

		/* Get crypto completion event from compl_queue. */
		CU_ASSERT_FATAL(NULL != suite_context.compl_queue_deq);
		do {
			event = suite_context.compl_queue_deq();
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT(odp_event_is_valid(event) == 1);
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
			 unsigned int hash_result_offset)
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

	op_params.hash_result_offset = hash_result_offset;

	rc = odp_crypto_op(&pkt, &out_pkt, &op_params, 1);
	if (rc <= 0) {
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
	CU_ASSERT(odp_packet_subtype(pkt) == ODP_EVENT_PACKET_CRYPTO);

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
			     unsigned int hash_result_offset)
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

	op_params.hash_result_offset = hash_result_offset;

	rc = odp_crypto_op_enq(&pkt, &pkt, &op_params, 1);
	if (rc <= 0) {
		CU_FAIL("Failed odp_crypto_op_enq()");
		return rc;
	}

	/* Get crypto completion event from compl_queue. */
	CU_ASSERT_FATAL(NULL != suite_context.compl_queue_deq);
	do {
		event = suite_context.compl_queue_deq();
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
	CU_ASSERT(odp_packet_subtype(pkt) == ODP_EVENT_PACKET_CRYPTO);

	rc = odp_crypto_result(&result, pkt);
	if (rc < 0) {
		CU_FAIL("Failed odp_crypto_packet_result()");
		return rc;
	}

	CU_ASSERT((!odp_packet_has_error(pkt)) == result.ok);

	*ok = result.ok;

	return 0;
}

/*
 * Try to adjust packet so that the first segment holds 'first_seg_len' bytes
 * of packet data (+ tailroom if first_seg_len is longer than the packet).
 *
 * If 'first_seg_len' is zero, do not try to add segments but make headroom
 * zero.
 *
 * Packet data bytes are not preserved.
 */
static void adjust_segments(odp_packet_t *pkt, uint32_t first_seg_len)
{
	uint32_t shift;

	shift = odp_packet_headroom(*pkt) + first_seg_len;

	if (odp_packet_extend_head(pkt, shift, NULL, NULL) < 0) {
		CU_FAIL("odp_packet_extend_head() failed\n");
		return;
	}
	if (odp_packet_trunc_tail(pkt, shift, NULL, NULL) < 0) {
		CU_FAIL("odp_packet_trunc_tail() failed\n");
		return;
	}
	/*
	 * ODP API does not seem to guarantee that we ever have a multi-segment
	 * packet at this point, but we can print a message about it.
	 */
	if (first_seg_len == 1 &&
	    first_seg_len != odp_packet_seg_len(*pkt))
		printf("Could not create a segmented packet for testing.\n");
}

/*
 * Generate or verify header and trailer bytes
 */
static void do_header_and_trailer(odp_packet_t pkt,
				  uint32_t header_len, uint32_t trailer_len,
				  odp_bool_t check)
{
	uint32_t trailer_offset = odp_packet_len(pkt) - trailer_len;
	uint32_t max_len = header_len > trailer_len ? header_len : trailer_len;
	uint8_t buffer[max_len];
	uint32_t n;
	int rc;

	for (n = 0; n < max_len; n++)
		buffer[n] = n;

	if (check) {
		CU_ASSERT(!packet_cmp_mem_bytes(pkt, 0,
						buffer, header_len));
		CU_ASSERT(!packet_cmp_mem_bytes(pkt, trailer_offset,
						buffer, trailer_len));
	} else {
		rc = odp_packet_copy_from_mem(pkt, 0,
					      header_len, buffer);
		CU_ASSERT(rc == 0);
		rc = odp_packet_copy_from_mem(pkt, trailer_offset,
					      trailer_len, buffer);
		CU_ASSERT(rc == 0);
	}
}

typedef enum crypto_test {
	NORMAL_TEST = 0,   /**< Plain execution */
	REPEAT_TEST,       /**< Rerun without reinitializing the session */
	WRONG_DIGEST_TEST, /**< Check against wrong digest */
	MAX_TEST,          /**< Final mark */
} crypto_test;

typedef struct alg_test_param_t {
	odp_crypto_session_t session;
	odp_crypto_op_t op;
	odp_auth_alg_t auth_alg;
	crypto_test_reference_t *ref;
	odp_bool_t override_iv;
	odp_bool_t bit_mode;
	odp_bool_t adjust_segmentation;
	uint32_t first_seg_len;
	uint32_t header_len;
	uint32_t trailer_len;
} alg_test_param_t;

static void alg_test_execute(const alg_test_param_t *param)
{
	int rc;
	odp_bool_t ok = false;
	int iteration;
	uint32_t reflength;
	odp_packet_data_range_t cipher_range;
	odp_packet_data_range_t auth_range;
	crypto_test_reference_t *ref = param->ref;
	uint8_t *cipher_iv = param->override_iv ? ref->cipher_iv : NULL;
	uint8_t *auth_iv   = param->override_iv ? ref->auth_iv : NULL;

	cipher_range.offset = param->header_len;
	cipher_range.length = ref->length;
	auth_range.offset = param->header_len;
	auth_range.length = ref->length;

	if (param->bit_mode) {
		reflength = (ref->length + 7) / 8;
		cipher_range.offset *= 8;
		auth_range.offset *= 8;
	} else {
		reflength = ref->length;
	}

	for (iteration = NORMAL_TEST; iteration < MAX_TEST; iteration++) {
		odp_packet_t pkt;
		uint32_t digest_offset = param->header_len + reflength;

		/*
		 * Test detection of wrong digest value in input packet
		 * only when decoding and using non-null auth algorithm.
		 */
		if (iteration == WRONG_DIGEST_TEST &&
		    (param->auth_alg == ODP_AUTH_ALG_NULL ||
		     param->op == ODP_CRYPTO_OP_ENCODE))
			continue;

		pkt = odp_packet_alloc(suite_context.pool,
				       param->header_len + reflength +
				       ref->digest_length + param->trailer_len);
		CU_ASSERT(pkt != ODP_PACKET_INVALID);
		if (pkt == ODP_PACKET_INVALID)
			continue;

		if (param->adjust_segmentation)
			adjust_segments(&pkt, param->first_seg_len);

		do_header_and_trailer(pkt, param->header_len, param->trailer_len, false);

		if (param->op == ODP_CRYPTO_OP_ENCODE) {
			odp_packet_copy_from_mem(pkt, param->header_len,
						 reflength, ref->plaintext);
		} else {
			odp_packet_copy_from_mem(pkt, param->header_len,
						 reflength, ref->ciphertext);
			odp_packet_copy_from_mem(pkt, digest_offset,
						 ref->digest_length,
						 ref->digest);
			if (iteration == WRONG_DIGEST_TEST) {
				uint8_t byte = ~ref->digest[0];

				odp_packet_copy_from_mem(pkt, digest_offset,
							 1, &byte);
			}
		}

		if (!suite_context.packet)
			rc = alg_op(pkt, &ok, param->session,
				    cipher_iv, auth_iv,
				    &cipher_range, &auth_range,
				    ref->aad, digest_offset);
		else if (ODP_CRYPTO_ASYNC == suite_context.op_mode)
			rc = alg_packet_op_enq(pkt, &ok, param->session,
					       cipher_iv, auth_iv,
					       &cipher_range, &auth_range,
					       ref->aad, digest_offset);
		else
			rc = alg_packet_op(pkt, &ok, param->session,
					   cipher_iv, auth_iv,
					   &cipher_range, &auth_range,
					   ref->aad, digest_offset);
		if (rc < 0) {
			odp_packet_free(pkt);
			break;
		}

		if (iteration == WRONG_DIGEST_TEST) {
			CU_ASSERT(!ok);
			odp_packet_free(pkt);
			continue;
		}

		CU_ASSERT(ok);

		do_header_and_trailer(pkt, param->header_len, param->trailer_len, true);

		if (param->op == ODP_CRYPTO_OP_ENCODE) {
			CU_ASSERT(!packet_cmp_mem(pkt, param->header_len,
						  ref->ciphertext,
						  ref->length,
						  param->bit_mode));
			CU_ASSERT(!packet_cmp_mem(pkt, digest_offset,
						  ref->digest,
						  ref->digest_length,
						  param->bit_mode));
		} else {
			CU_ASSERT(!packet_cmp_mem(pkt, param->header_len,
						  ref->plaintext,
						  ref->length,
						  param->bit_mode));
		}
		odp_packet_free(pkt);
	}
}

typedef enum {
	PACKET_IV,
	OLD_PACKET_IV,
	OLD_SESSION_IV,
} iv_test_mode_t;

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
		     iv_test_mode_t iv_mode,
		     odp_bool_t bit_mode)
{
	unsigned int initial_num_failures = CU_get_number_of_failures();
	odp_crypto_session_t session;
	int rc;
	uint32_t reflength;
	uint32_t seg_len;
	uint32_t max_shift;
	odp_crypto_ses_create_err_t status;
	odp_crypto_session_param_t ses_params;
	uint8_t cipher_key_data[ref->cipher_key_length];
	uint8_t auth_key_data[ref->auth_key_length];
	odp_crypto_key_t cipher_key = {
		.data = cipher_key_data,
		.length = ref->cipher_key_length
	};
	odp_crypto_key_t auth_key = {
		.data = auth_key_data,
		.length = ref->auth_key_length
	};
	alg_test_param_t test_param;
#if ODP_DEPRECATED_API
	uint8_t cipher_iv_data[ref->cipher_iv_length];
	uint8_t auth_iv_data[ref->auth_iv_length];
	odp_crypto_iv_t cipher_iv = {
		.length = ref->cipher_iv_length
	};
	odp_crypto_iv_t auth_iv = {
		.length = ref->auth_iv_length
	};

	if (iv_mode == OLD_SESSION_IV) {
		memcpy(cipher_iv_data, ref->cipher_iv, ref->cipher_iv_length);
		memcpy(auth_iv_data, ref->auth_iv, ref->auth_iv_length);
		cipher_iv.data = cipher_iv_data;
		auth_iv.data = auth_iv_data;
	}
#endif

	memcpy(cipher_key_data, ref->cipher_key, ref->cipher_key_length);
	memcpy(auth_key_data, ref->auth_key, ref->auth_key_length);

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
	if (iv_mode == PACKET_IV) {
		ses_params.cipher_iv_len = ref->cipher_iv_length;
		ses_params.auth_iv_len = ref->auth_iv_length;
	} else {
#if ODP_DEPRECATED_API
		ses_params.cipher_iv = cipher_iv;
		ses_params.auth_iv = auth_iv;
#endif
	}
	ses_params.auth_key = auth_key;
	ses_params.auth_digest_len = ref->digest_length;
	ses_params.auth_aad_len = ref->aad_length;

	rc = odp_crypto_session_create(&ses_params, &session, &status);
	CU_ASSERT_FATAL(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_ERR_NONE);
	CU_ASSERT(odp_crypto_session_to_u64(session) !=
		  odp_crypto_session_to_u64(ODP_CRYPTO_SESSION_INVALID));

	/*
	 * Clear session creation parameters so that we might notice if
	 * the implementation still tried to use them.
	 */
	memset(cipher_key_data, 0, sizeof(cipher_key_data));
	memset(auth_key_data, 0, sizeof(auth_key_data));
#if ODP_DEPRECATED_API
	memset(cipher_iv_data, 0, sizeof(cipher_iv_data));
	memset(auth_iv_data, 0, sizeof(auth_iv_data));
#endif
	memset(&ses_params, 0, sizeof(ses_params));

	memset(&test_param, 0, sizeof(test_param));
	test_param.session = session;
	test_param.op = op;
	test_param.auth_alg = auth_alg;
	test_param.ref = ref;
	test_param.override_iv = (iv_mode != OLD_SESSION_IV);
	test_param.bit_mode = bit_mode;

	alg_test_execute(&test_param);

	if (bit_mode)
		reflength = (ref->length + 7) / 8;
	else
		reflength = ref->length;
	max_shift = reflength + ref->digest_length;

	/*
	 * Test with segmented packets with all possible segment boundaries
	 * within the packet data (including boundary after the packet data
	 * in the location where the digest will be written).
	 */
	for (seg_len = 0; seg_len <= max_shift; seg_len++) {
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
		alg_test_execute(&test_param);

		/* Test partial packet crypto with odd alignment. */
		test_param.header_len = 3;
		test_param.trailer_len = 32;
		alg_test_execute(&test_param);
	}

	rc = odp_crypto_session_destroy(session);
	CU_ASSERT(!rc);
}

static void check_alg(odp_crypto_op_t op,
		      odp_cipher_alg_t cipher_alg,
		      odp_auth_alg_t auth_alg,
		      crypto_test_reference_t *ref,
		      size_t count,
		      odp_bool_t bit_mode)
{
	int rc, i;
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

	for (idx = 0; idx < count; idx++) {
		int cipher_idx = -1, auth_idx = -1;

		for (i = 0; i < cipher_num; i++) {
			if (cipher_capa[i].key_len ==
			    ref[idx].cipher_key_length &&
			    cipher_capa[i].iv_len ==
			    ref[idx].cipher_iv_length &&
			    cipher_capa[i].bit_mode ==
			    bit_mode) {
				cipher_idx = i;
				break;
			}
		}

		if (cipher_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 "%s\n",
			       cipher_alg_name(cipher_alg),
			       ref[idx].cipher_key_length,
			       ref[idx].cipher_iv_length,
			       bit_mode ? " using bits" : "");
			continue;
		}

		for (i = 0; i < auth_num; i++) {
			if (auth_capa[i].digest_len ==
			    ref[idx].digest_length &&
			    auth_capa[i].iv_len ==
			    ref[idx].auth_iv_length &&
			    auth_capa[i].key_len ==
			    ref[idx].auth_key_length &&
			    auth_capa[i].bit_mode ==
			    bit_mode) {
				auth_idx = i;
				break;
			}
		}

		if (auth_idx < 0) {
			printf("\n    Unsupported: alg=%s, key_len=%" PRIu32
			       ", iv_len=%" PRIu32 ", digest_len=%" PRIu32
			       "%s\n",
			       auth_alg_name(auth_alg),
			       ref[idx].auth_key_length,
			       ref[idx].auth_iv_length,
			       ref[idx].digest_length,
			       bit_mode ? " using bits" : "");
			continue;
		}

		/* test with per-packet IV */
		alg_test(op, cipher_alg, auth_alg, &ref[idx],
			 PACKET_IV, bit_mode);
#if ODP_DEPRECATED_API
		/* test with per-packet IV using the old API*/
		alg_test(op, cipher_alg, auth_alg, &ref[idx],
			 OLD_PACKET_IV, bit_mode);

		/* test with per-session IV */
		alg_test(op, cipher_alg, auth_alg, &ref[idx],
			 OLD_SESSION_IV, bit_mode);
#endif

		cipher_tested[cipher_idx] = true;
		auth_tested[auth_idx] = true;
	}

	for (i = 0; i < cipher_num; i++) {
		cipher_ok |= cipher_tested[i];
		if (!cipher_tested[i] && cipher_capa[i].bit_mode == bit_mode)
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "iv_len=%" PRIu32 "%s\n",
			       cipher_alg_name(cipher_alg),
			       cipher_capa[i].key_len,
			       cipher_capa[i].iv_len,
			       cipher_capa[i].bit_mode ? " using bits" : "");
	}

	for (i = 0; i < auth_num; i++) {
		auth_ok |= auth_tested[i];
		if (!auth_tested[i] && auth_capa[i].bit_mode == bit_mode)
			printf("\n    Untested: alg=%s, key_len=%" PRIu32 ", "
			       "digest_len=%" PRIu32 "%s\n",
			       auth_alg_name(auth_alg),
			       auth_capa[i].key_len,
			       auth_capa[i].digest_len,
			       auth_capa[i].bit_mode ? " using bits" : "");
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

	memset(&capability, 0, sizeof(odp_crypto_capability_t));
	if (odp_crypto_capability(&capability)) {
		fprintf(stderr, "odp_crypto_capability() failed\n");
		return ODP_TEST_INACTIVE;
	}

	if (suite_context.queue != ODP_QUEUE_INVALID) {
		if (suite_context.q_type == ODP_QUEUE_TYPE_PLAIN &&
		    capability.queue_type_plain == 0)
			return ODP_TEST_INACTIVE;
		if (suite_context.q_type == ODP_QUEUE_TYPE_SCHED &&
		    capability.queue_type_sched == 0)
			return ODP_TEST_INACTIVE;
	}

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
	case ODP_CIPHER_ALG_3DES_ECB:
		if (!capability.ciphers.bit.trides_ecb)
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
	case ODP_CIPHER_ALG_AES_ECB:
		if (!capability.ciphers.bit.aes_ecb)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CFB128:
		if (!capability.ciphers.bit.aes_cfb128)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_XTS:
		if (!capability.ciphers.bit.aes_xts)
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
	case ODP_CIPHER_ALG_KASUMI_F8:
		if (!capability.ciphers.bit.kasumi_f8)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		if (!capability.ciphers.bit.snow3g_uea2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_EEA2:
		if (!capability.ciphers.bit.aes_eea2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_ZUC_EEA3:
		if (!capability.ciphers.bit.zuc_eea3)
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
	case ODP_AUTH_ALG_SHA224_HMAC:
		if (!capability.auths.bit.sha224_hmac)
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
	case ODP_AUTH_ALG_KASUMI_F9:
		if (!capability.auths.bit.kasumi_f9)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		if (!capability.auths.bit.snow3g_uia2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_EIA2:
		if (!capability.auths.bit.aes_eia2)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_ZUC_EIA3:
		if (!capability.auths.bit.zuc_eia3)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_MD5:
		if (!capability.auths.bit.md5)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA1:
		if (!capability.auths.bit.sha1)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA224:
		if (!capability.auths.bit.sha224)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA256:
		if (!capability.auths.bit.sha256)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA384:
		if (!capability.auths.bit.sha384)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512:
		if (!capability.auths.bit.sha512)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
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

static void crypto_test_enc_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_3DES_CBC,
		  ODP_AUTH_ALG_NULL,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference),
		  false);
}

static void crypto_test_dec_alg_3des_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_3DES_CBC,
		  ODP_AUTH_ALG_NULL,
		  tdes_cbc_reference,
		  ARRAY_SIZE(tdes_cbc_reference),
		  false);
}

static int check_alg_3des_ecb(void)
{
	return check_alg_support(ODP_CIPHER_ALG_3DES_ECB, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_3des_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_3DES_ECB,
		  ODP_AUTH_ALG_NULL,
		  tdes_ecb_reference,
		  ARRAY_SIZE(tdes_ecb_reference),
		  false);
}

static void crypto_test_dec_alg_3des_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_3DES_ECB,
		  ODP_AUTH_ALG_NULL,
		  tdes_ecb_reference,
		  ARRAY_SIZE(tdes_ecb_reference),
		  false);
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

static void crypto_test_dec_alg_chacha20_poly1305(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_CHACHA20_POLY1305,
		  ODP_AUTH_ALG_CHACHA20_POLY1305,
		  chacha20_poly1305_reference,
		  ARRAY_SIZE(chacha20_poly1305_reference),
		  false);
}

static int check_alg_aes_gcm(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_GCM, ODP_AUTH_ALG_AES_GCM);
}

static void crypto_test_enc_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_GCM,
		  ODP_AUTH_ALG_AES_GCM,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference),
		  false);
}

static void crypto_test_dec_alg_aes_gcm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_GCM,
		  ODP_AUTH_ALG_AES_GCM,
		  aes_gcm_reference,
		  ARRAY_SIZE(aes_gcm_reference),
		  false);
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

static void crypto_test_dec_alg_aes_ccm(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CCM,
		  ODP_AUTH_ALG_AES_CCM,
		  aes_ccm_reference,
		  ARRAY_SIZE(aes_ccm_reference),
		  false);
}

static int check_alg_aes_cbc(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CBC, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CBC,
		  ODP_AUTH_ALG_NULL,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference),
		  false);
}

static void crypto_test_dec_alg_aes_cbc(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CBC,
		  ODP_AUTH_ALG_NULL,
		  aes_cbc_reference,
		  ARRAY_SIZE(aes_cbc_reference),
		  false);
}

static int check_alg_aes_ctr(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CTR, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CTR,
		  ODP_AUTH_ALG_NULL,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference),
		  false);
}

static void crypto_test_dec_alg_aes_ctr(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CTR,
		  ODP_AUTH_ALG_NULL,
		  aes_ctr_reference,
		  ARRAY_SIZE(aes_ctr_reference),
		  false);
}

static int check_alg_aes_ecb(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_ECB, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_ECB,
		  ODP_AUTH_ALG_NULL,
		  aes_ecb_reference,
		  ARRAY_SIZE(aes_ecb_reference),
		  false);
}

static void crypto_test_dec_alg_aes_ecb(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_ECB,
		  ODP_AUTH_ALG_NULL,
		  aes_ecb_reference,
		  ARRAY_SIZE(aes_ecb_reference),
		  false);
}

static int check_alg_aes_cfb128(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_CFB128, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_cfb128(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_CFB128,
		  ODP_AUTH_ALG_NULL,
		  aes_cfb128_reference,
		  ARRAY_SIZE(aes_cfb128_reference),
		  false);
}

static void crypto_test_dec_alg_aes_cfb128(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_CFB128,
		  ODP_AUTH_ALG_NULL,
		  aes_cfb128_reference,
		  ARRAY_SIZE(aes_cfb128_reference),
		  false);
}

static int check_alg_aes_xts(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_XTS, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_xts(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_XTS,
		  ODP_AUTH_ALG_NULL,
		  aes_xts_reference,
		  ARRAY_SIZE(aes_xts_reference),
		  false);
}

static void crypto_test_dec_alg_aes_xts(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_XTS,
		  ODP_AUTH_ALG_NULL,
		  aes_xts_reference,
		  ARRAY_SIZE(aes_xts_reference),
		  false);
}

static int check_alg_kasumi_f8(void)
{
	return check_alg_support(ODP_CIPHER_ALG_KASUMI_F8, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_kasumi_f8(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_KASUMI_F8,
		  ODP_AUTH_ALG_NULL,
		  kasumi_f8_reference,
		  ARRAY_SIZE(kasumi_f8_reference),
		  true);
}

static void crypto_test_dec_alg_kasumi_f8(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_KASUMI_F8,
		  ODP_AUTH_ALG_NULL,
		  kasumi_f8_reference,
		  ARRAY_SIZE(kasumi_f8_reference),
		  true);
}

static int check_alg_snow3g_uea2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_SNOW3G_UEA2, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_snow3g_uea2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_SNOW3G_UEA2,
		  ODP_AUTH_ALG_NULL,
		  snow3g_uea2_reference,
		  ARRAY_SIZE(snow3g_uea2_reference),
		  true);
}

static void crypto_test_dec_alg_snow3g_uea2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_SNOW3G_UEA2,
		  ODP_AUTH_ALG_NULL,
		  snow3g_uea2_reference,
		  ARRAY_SIZE(snow3g_uea2_reference),
		  true);
}

static int check_alg_aes_eea2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_AES_EEA2,
				 ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_aes_eea2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_AES_EEA2,
		  ODP_AUTH_ALG_NULL,
		  aes_eea2_reference,
		  ARRAY_SIZE(aes_eea2_reference),
		  true);
}

static void crypto_test_dec_alg_aes_eea2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_AES_EEA2,
		  ODP_AUTH_ALG_NULL,
		  aes_eea2_reference,
		  ARRAY_SIZE(aes_eea2_reference),
		  true);
}

static int check_alg_zuc_eea3(void)
{
	return check_alg_support(ODP_CIPHER_ALG_ZUC_EEA3, ODP_AUTH_ALG_NULL);
}

static void crypto_test_enc_alg_zuc_eea3(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_ZUC_EEA3,
		  ODP_AUTH_ALG_NULL,
		  zuc_eea3_reference,
		  ARRAY_SIZE(zuc_eea3_reference),
		  true);
}

static void crypto_test_dec_alg_zuc_eea3(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_ZUC_EEA3,
		  ODP_AUTH_ALG_NULL,
		  zuc_eea3_reference,
		  ARRAY_SIZE(zuc_eea3_reference),
		  true);
}

static int check_alg_hmac_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5_HMAC);
}

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

static int check_alg_hmac_sha224(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA224_HMAC);
}

static void crypto_test_gen_alg_hmac_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA224_HMAC,
		  hmac_sha224_reference,
		  ARRAY_SIZE(hmac_sha224_reference),
		  false);
}

static void crypto_test_check_alg_hmac_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA224_HMAC,
		  hmac_sha224_reference,
		  ARRAY_SIZE(hmac_sha224_reference),
		  false);
}

static int check_alg_hmac_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256_HMAC);
}

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
	return check_alg_support(ODP_CIPHER_ALG_NULL,
						ODP_AUTH_ALG_AES_XCBC_MAC);
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

static void crypto_test_check_alg_aes_gmac(void)
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

static int check_alg_kasumi_f9(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_KASUMI_F9);
}

static void crypto_test_gen_alg_kasumi_f9(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_KASUMI_F9,
		  kasumi_f9_reference,
		  ARRAY_SIZE(kasumi_f9_reference),
		  true);
}

static void crypto_test_check_alg_kasumi_f9(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_KASUMI_F9,
		  kasumi_f9_reference,
		  ARRAY_SIZE(kasumi_f9_reference),
		  true);
}

static int check_alg_snow3g_uia2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SNOW3G_UIA2);
}

static void crypto_test_gen_alg_snow3g_uia2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SNOW3G_UIA2,
		  snow3g_uia2_reference,
		  ARRAY_SIZE(snow3g_uia2_reference),
		  true);
}

static void crypto_test_check_alg_snow3g_uia2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SNOW3G_UIA2,
		  snow3g_uia2_reference,
		  ARRAY_SIZE(snow3g_uia2_reference),
		  true);
}

static int check_alg_aes_eia2(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL,
				 ODP_AUTH_ALG_AES_EIA2);
}

static void crypto_test_gen_alg_aes_eia2(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_EIA2,
		  aes_eia2_reference,
		  ARRAY_SIZE(aes_eia2_reference),
		  true);
}

static void crypto_test_check_alg_aes_eia2(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_AES_EIA2,
		  aes_eia2_reference,
		  ARRAY_SIZE(aes_eia2_reference),
		  true);
}

static int check_alg_zuc_eia3(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_ZUC_EIA3);
}

static void crypto_test_gen_alg_zuc_eia3(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_ZUC_EIA3,
		  zuc_eia3_reference,
		  ARRAY_SIZE(zuc_eia3_reference),
		  true);
}

static void crypto_test_check_alg_zuc_eia3(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_ZUC_EIA3,
		  zuc_eia3_reference,
		  ARRAY_SIZE(zuc_eia3_reference),
		  true);
}

static int check_alg_md5(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_MD5);
}

static void crypto_test_gen_alg_md5(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_MD5,
		  md5_reference,
		  ARRAY_SIZE(md5_reference),
		  false);
}

static void crypto_test_check_alg_md5(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_MD5,
		  md5_reference,
		  ARRAY_SIZE(md5_reference),
		  false);
}

static int check_alg_sha1(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA1);
}

static void crypto_test_gen_alg_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA1,
		  sha1_reference,
		  ARRAY_SIZE(sha1_reference),
		  false);
}

static void crypto_test_check_alg_sha1(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA1,
		  sha1_reference,
		  ARRAY_SIZE(sha1_reference),
		  false);
}

static int check_alg_sha224(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA224);
}

static void crypto_test_gen_alg_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA224,
		  sha224_reference,
		  ARRAY_SIZE(sha224_reference),
		  false);
}

static void crypto_test_check_alg_sha224(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA224,
		  sha224_reference,
		  ARRAY_SIZE(sha224_reference),
		  false);
}

static int check_alg_sha256(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA256);
}

static void crypto_test_gen_alg_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA256,
		  sha256_reference,
		  ARRAY_SIZE(sha256_reference),
		  false);
}

static void crypto_test_check_alg_sha256(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA256,
		  sha256_reference,
		  ARRAY_SIZE(sha256_reference),
		  false);
}

static int check_alg_sha384(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA384);
}

static void crypto_test_gen_alg_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA384,
		  sha384_reference,
		  ARRAY_SIZE(sha384_reference),
		  false);
}

static void crypto_test_check_alg_sha384(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA384,
		  sha384_reference,
		  ARRAY_SIZE(sha384_reference),
		  false);
}

static int check_alg_sha512(void)
{
	return check_alg_support(ODP_CIPHER_ALG_NULL, ODP_AUTH_ALG_SHA512);
}

static void crypto_test_gen_alg_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_ENCODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA512,
		  sha512_reference,
		  ARRAY_SIZE(sha512_reference),
		  false);
}

static void crypto_test_check_alg_sha512(void)
{
	check_alg(ODP_CRYPTO_OP_DECODE,
		  ODP_CIPHER_ALG_NULL,
		  ODP_AUTH_ALG_SHA512,
		  sha512_reference,
		  ARRAY_SIZE(sha512_reference),
		  false);
}

static odp_queue_t sched_compl_queue_create(void)
{
	odp_queue_param_t qparam;

	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
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

static int crypto_suite_sync_init(void)
{
	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	suite_context.pref_mode = ODP_CRYPTO_SYNC;
	return 0;
}

static int crypto_suite_async_plain_init(void)
{
	odp_queue_t out_queue;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = plain_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_PLAIN;
	suite_context.compl_queue_deq = plain_compl_queue_deq;
	suite_context.pref_mode = ODP_CRYPTO_ASYNC;

	return 0;
}

static int crypto_suite_async_sched_init(void)
{
	odp_queue_t out_queue;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = sched_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_SCHED;
	suite_context.compl_queue_deq = sched_compl_queue_deq;
	suite_context.pref_mode = ODP_CRYPTO_ASYNC;

	return 0;
}

static int crypto_suite_packet_sync_init(void)
{
	suite_context.packet = true;
	suite_context.op_mode = ODP_CRYPTO_SYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	suite_context.queue = ODP_QUEUE_INVALID;
	return 0;
}

static int crypto_suite_packet_async_plain_init(void)
{
	odp_queue_t out_queue;

	suite_context.packet = true;
	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = plain_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_PLAIN;
	suite_context.compl_queue_deq = plain_compl_queue_deq;

	return 0;
}

static int crypto_suite_packet_async_sched_init(void)
{
	odp_queue_t out_queue;

	suite_context.packet = true;
	suite_context.op_mode = ODP_CRYPTO_ASYNC;

	suite_context.pool = odp_pool_lookup("packet_pool");
	if (suite_context.pool == ODP_POOL_INVALID)
		return -1;

	out_queue = sched_compl_queue_create();
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "Crypto outq creation failed.\n");
		return -1;
	}
	suite_context.queue = out_queue;
	suite_context.q_type = ODP_QUEUE_TYPE_SCHED;
	suite_context.compl_queue_deq = sched_compl_queue_deq;

	return 0;
}

static int crypto_suite_term(void)
{
	if (ODP_QUEUE_INVALID != suite_context.queue) {
		if (odp_queue_destroy(suite_context.queue))
			fprintf(stderr, "Crypto outq destroy failed.\n");
	} else {
		fprintf(stderr, "Crypto outq not found.\n");
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
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t crypto_suites[] = {
	{"odp_crypto_sync_inp", crypto_suite_sync_init,
	 NULL, crypto_suite},
	{"odp_crypto_async_plain_inp", crypto_suite_async_plain_init,
	 crypto_suite_term, crypto_suite},
	{"odp_crypto_async_sched_inp", crypto_suite_async_sched_init,
	 crypto_suite_term, crypto_suite},
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
		fprintf(stderr, "error: odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	/* Configure the scheduler. */
	if (odp_schedule_config(NULL)) {
		fprintf(stderr, "odp_schedule_config() failed.\n");
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

	return 0;
}

static int crypto_term(odp_instance_t inst)
{
	odp_pool_t pool;

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

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(crypto_init);
	odp_cunit_register_global_term(crypto_term);

	ret = odp_cunit_register(crypto_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
