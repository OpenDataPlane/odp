/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>
#include "test_vectors.h"

/* Basic algorithm run function for async inplace mode.
 * Creates a session from input parameters and runs one operation
 * on input_vec. Checks the output of the crypto operation against
 * output_vec. Operation completion event is dequeued polling the
 * session output queue. Completion context pointer is retrieved
 * and checked against the one set before the operation.
 * Completion event can be a separate buffer or the input packet
 * buffer can be used.
 * */
static void alg_test(enum odp_crypto_op op,
		     enum odp_cipher_alg cipher_alg,
		     odp_crypto_iv_t ses_iv,
		     uint8_t *op_iv_ptr,
		     odp_crypto_key_t cipher_key,
		     enum odp_auth_alg auth_alg,
		     odp_crypto_key_t auth_key,
		     odp_event_t compl_new,
		     uint8_t *input_vec,
		     unsigned int input_vec_len,
		     uint8_t *output_vec,
		     unsigned int output_vec_len)
{
	odp_crypto_session_t session;
	int rc;
	enum odp_crypto_ses_create_err status;
	bool posted;
	odp_event_t compl_event;

	odp_queue_t compl_queue = odp_queue_lookup("crypto-out");
	CU_ASSERT(compl_queue != ODP_QUEUE_INVALID);
	odp_buffer_pool_t pool = odp_buffer_pool_lookup("packet_pool");
	CU_ASSERT(pool != ODP_BUFFER_POOL_INVALID);

	/* Create a crypto session */
	odp_crypto_session_params_t ses_params;
	memset(&ses_params, 0, sizeof(ses_params));
	ses_params.op = op;
	ses_params.auth_cipher_text = false;
	ses_params.pref_mode = ODP_CRYPTO_ASYNC;
	ses_params.cipher_alg = cipher_alg;
	ses_params.auth_alg = auth_alg;
	ses_params.compl_queue = compl_queue;
	ses_params.output_pool = pool;
	ses_params.cipher_key = cipher_key;
	ses_params.iv = ses_iv;
	ses_params.auth_key = auth_key;

	rc = odp_crypto_session_create(&ses_params, &session, &status);
	CU_ASSERT(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_CREATE_ERR_NONE);

	/* Prepare input data */
	odp_packet_t pkt = odp_packet_alloc(pool, input_vec_len);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	uint8_t *data_addr = odp_packet_data(pkt);
	memcpy(data_addr, input_vec, input_vec_len);
	const int data_off = 0;

	/* Prepare input/output params */
	odp_crypto_op_params_t op_params;
	memset(&op_params, 0, sizeof(op_params));
	op_params.session = session;
	op_params.pkt = pkt;
	op_params.out_pkt = pkt;
	if (cipher_alg != ODP_CIPHER_ALG_NULL &&
	    auth_alg == ODP_AUTH_ALG_NULL) {
		op_params.cipher_range.offset = data_off;
		op_params.cipher_range.length = input_vec_len;
		if (op_iv_ptr)
			op_params.override_iv_ptr = op_iv_ptr;
	} else if (cipher_alg == ODP_CIPHER_ALG_NULL &&
		 auth_alg != ODP_AUTH_ALG_NULL) {
		op_params.auth_range.offset = data_off;
		op_params.auth_range.length = input_vec_len;
		op_params.hash_result_offset = data_off;
	} else {
		CU_FAIL("%s : not implemented for combined alg mode\n");
	}

	if (compl_new == ODP_EVENT_INVALID) {
		odp_event_t ev = odp_packet_to_event(pkt);
		odp_crypto_set_operation_compl_ctx(ev, (void *)0xdeadbeef);
		rc = odp_crypto_operation(&op_params, &posted, ev);
	} else {
		odp_crypto_set_operation_compl_ctx(compl_new,
						   (void *)0xdeadbeef);
		rc = odp_crypto_operation(&op_params, &posted, compl_new);
	}
	CU_ASSERT(posted);

	/* Poll completion queue for results */
	do {
		compl_event = odp_queue_deq(compl_queue);
	} while (compl_event == ODP_EVENT_INVALID);

	if (compl_new == ODP_EVENT_INVALID)
		CU_ASSERT(compl_event == odp_packet_to_event(pkt))
	else
		CU_ASSERT(compl_event == compl_new)

	struct odp_crypto_compl_status auth_status, cipher_status;
	odp_crypto_get_operation_compl_status(compl_event,
					      &auth_status, &cipher_status);
	CU_ASSERT(auth_status.alg_err == ODP_CRYPTO_ALG_ERR_NONE);
	CU_ASSERT(auth_status.hw_err == ODP_CRYPTO_HW_ERR_NONE);
	CU_ASSERT(cipher_status.alg_err == ODP_CRYPTO_ALG_ERR_NONE);
	CU_ASSERT(cipher_status.hw_err == ODP_CRYPTO_HW_ERR_NONE);

	odp_packet_t out_pkt;
	out_pkt = odp_crypto_get_operation_compl_packet(compl_event);
	CU_ASSERT(out_pkt == pkt);

	CU_ASSERT(!memcmp(data_addr, output_vec, output_vec_len));

	void *ctx = odp_crypto_get_operation_compl_ctx(compl_event);
	CU_ASSERT(ctx == (void *)0xdeadbeef);

	odp_packet_free(pkt);
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.*/
#define ASYNC_INP_ENC_ALG_3DES_CBC	"ENC_ALG_3DES_CBC"
static void enc_alg_3des_cbc(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length)/
				     sizeof(tdes_cbc_reference_length[0]));

	unsigned int i;
	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);
		iv.data = tdes_cbc_reference_iv[i];
		iv.length = sizeof(tdes_cbc_reference_iv[i]);

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 ODP_EVENT_INVALID,
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i]);
	}
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the operation IV.
 * */
#define ASYNC_INP_ENC_ALG_3DES_CBC_OVR_IV	"ENC_ALG_3DES_CBC_OVR_IV"
static void enc_alg_3des_cbc_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = TDES_CBC_IV_LEN };
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length)/
				     sizeof(tdes_cbc_reference_length[0]));

	unsigned int i;
	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 tdes_cbc_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 ODP_EVENT_INVALID,
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i]);
	}
}


/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
#define ASYNC_INP_DEC_ALG_3DES_CBC	"DEC_ALG_3DES_CBC"
static void dec_alg_3des_cbc(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length)/
				     sizeof(tdes_cbc_reference_length[0]));

	unsigned int i;
	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);
		iv.data = tdes_cbc_reference_iv[i];
		iv.length = sizeof(tdes_cbc_reference_iv[i]);

		alg_test(ODP_CRYPTO_OP_DECODE,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 ODP_EVENT_INVALID,
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i]);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
#define ASYNC_INP_DEC_ALG_3DES_CBC_OVR_IV	"DEC_ALG_3DES_CBC_OVR_IV"
static void dec_alg_3des_cbc_ovr_iv(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = TDES_CBC_IV_LEN };
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length)/
				     sizeof(tdes_cbc_reference_length[0]));

	unsigned int i;
	for (i = 0; i < test_vec_num; i++) {
		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);

		alg_test(ODP_CRYPTO_OP_DECODE,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 tdes_cbc_reference_iv[i],
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 ODP_EVENT_INVALID,
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i]);
	}
}


/* This test verifies the correctness of HMAC_MD5 digest operation.
 * The output check length is truncated to 12 bytes (96 bits) as
 * returned by the crypto operation API call.
 * Note that hash digest is a one-way operation.
 * In addition the test verifies if the implementation can use the
 * packet buffer as completion event buffer.
 * */
#define ASYNC_INP_ALG_HMAC_MD5	"ALG_HMAC_MD5"
static void alg_hmac_md5(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv = { .data = NULL, .length = 0 };

	unsigned int test_vec_num = (sizeof(hmac_md5_reference_length)/
				     sizeof(hmac_md5_reference_length[0]));

	unsigned int i;
	for (i = 0; i < test_vec_num; i++) {
		auth_key.data = hmac_md5_reference_key[i];
		auth_key.length = sizeof(hmac_md5_reference_key[i]);

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 ODP_CIPHER_ALG_NULL,
			 iv,
			 iv.data,
			 cipher_key,
			 ODP_AUTH_ALG_MD5_96,
			 auth_key,
			 ODP_EVENT_INVALID,
			 hmac_md5_reference_plaintext[i],
			 hmac_md5_reference_length[i],
			 hmac_md5_reference_digest[i],
			 HMAC_MD5_96_CHECK_LEN);
	}
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV.
 * Uses a separate buffer for completion event
 * */
#define ASYNC_INP_ENC_ALG_3DES_CBC_COMPL_NEW	"ENC_ALG_3DES_CBC_COMPL_NEW"
static void enc_alg_3des_cbc_compl_new(void)
{
	odp_crypto_key_t cipher_key = { .data = NULL, .length = 0 },
			 auth_key   = { .data = NULL, .length = 0 };
	odp_crypto_iv_t iv;
	unsigned int test_vec_num = (sizeof(tdes_cbc_reference_length)/
				     sizeof(tdes_cbc_reference_length[0]));

	odp_buffer_pool_t pool = odp_buffer_pool_lookup("compl_pool");
	CU_ASSERT(pool != ODP_BUFFER_POOL_INVALID);

	unsigned int i;
	odp_buffer_t compl_new;
	for (i = 0; i < test_vec_num; i++) {
		compl_new = odp_buffer_alloc(pool);
		CU_ASSERT(compl_new != ODP_BUFFER_INVALID);

		cipher_key.data = tdes_cbc_reference_key[i];
		cipher_key.length = sizeof(tdes_cbc_reference_key[i]);
		iv.data = tdes_cbc_reference_iv[i];
		iv.length = sizeof(tdes_cbc_reference_iv[i]);

		alg_test(ODP_CRYPTO_OP_ENCODE,
			 ODP_CIPHER_ALG_3DES_CBC,
			 iv,
			 NULL,
			 cipher_key,
			 ODP_AUTH_ALG_NULL,
			 auth_key,
			 odp_buffer_to_event(compl_new),
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i]);
		odp_buffer_free(compl_new);
	}
}

CU_TestInfo test_array_async[] = {
	{ASYNC_INP_ENC_ALG_3DES_CBC, enc_alg_3des_cbc },
	{ASYNC_INP_DEC_ALG_3DES_CBC, dec_alg_3des_cbc },
	{ASYNC_INP_ENC_ALG_3DES_CBC_OVR_IV, enc_alg_3des_cbc_ovr_iv },
	{ASYNC_INP_DEC_ALG_3DES_CBC_OVR_IV, dec_alg_3des_cbc_ovr_iv },
	{ASYNC_INP_ALG_HMAC_MD5, alg_hmac_md5 },
	{ASYNC_INP_ENC_ALG_3DES_CBC_COMPL_NEW, enc_alg_3des_cbc_compl_new },
	CU_TEST_INFO_NULL,
};
