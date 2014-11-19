#include <odp.h>
#include <odp_crypto.h>
#include "CUnit/Basic.h"
#include "CUnit/TestDB.h"
#include "test_vectors.h"

/* Basic algorithm run function for sync inplace.
 * Creates a session from input parameters and runs one operation
 * on input_vec. Checks the output of the crypto operation against
 * output_vec.
 */
static void alg_test(enum odp_crypto_op op,
		     enum odp_cipher_alg cipher_alg,
		     odp_crypto_iv_t ses_iv,
		     uint8_t *op_iv_ptr,
		     odp_crypto_key_t cipher_key,
		     enum odp_auth_alg auth_alg,
		     odp_crypto_key_t auth_key,
		     uint8_t *input_vec,
		     unsigned int input_vec_len,
		     uint8_t *output_vec,
		     unsigned int output_vec_len)
{
	odp_crypto_session_t session;
	int rc;
	enum odp_crypto_ses_create_err status;
	bool posted;

	odp_queue_t compl_queue = odp_queue_lookup("crypto-out");
	CU_ASSERT(compl_queue != ODP_QUEUE_INVALID);
	odp_buffer_pool_t pool = odp_buffer_pool_lookup("packet_pool");
	CU_ASSERT(pool != ODP_BUFFER_POOL_INVALID);

	/* Create a crypto session */
	odp_crypto_session_params_t ses_params;
	memset(&ses_params, 0, sizeof(ses_params));
	ses_params.op = op;
	ses_params.auth_cipher_text = false;
	ses_params.pref_mode = ODP_CRYPTO_SYNC;
	ses_params.cipher_alg = cipher_alg;
	ses_params.auth_alg = auth_alg;
	ses_params.compl_queue = ODP_QUEUE_INVALID;
	ses_params.output_pool = pool;
	ses_params.cipher_key = cipher_key;
	ses_params.iv = ses_iv;
	ses_params.auth_key = auth_key;

	/* TEST : odp_crypto_session_create */
	rc = odp_crypto_session_create(&ses_params, &session, &status);
	CU_ASSERT(!rc);
	CU_ASSERT(status == ODP_CRYPTO_SES_CREATE_ERR_NONE);

	/* Prepare input data */
	odp_buffer_t buf = odp_buffer_alloc(pool);
	CU_ASSERT(buf != ODP_BUFFER_INVALID);
	odp_packet_t pkt = odp_packet_from_buffer(buf);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	uint8_t *data_addr = odp_packet_data(pkt);
	memcpy(data_addr, input_vec, input_vec_len);
	/* offsets are relative to buffer address (not packet data)
	until https://bugs.linaro.org/show_bug.cgi?id=387 is fixed */
	int data_off = data_addr - (uint8_t *)odp_buffer_addr(buf);

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

	/* TEST : odp_crypto_operation */
	rc = odp_crypto_operation(&op_params, &posted, buf);
	CU_ASSERT(!rc);
	/* indication that the operation completed */
	CU_ASSERT(!posted);

	/* TEST : operation output was correct */
	CU_ASSERT(!memcmp(data_addr, output_vec, output_vec_len));
}

#define SYNC_INP_ENC_ALG_3DES_CBC	"ENC_ALG_3DES_CBC"
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
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i]);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV
 * */
#define SYNC_INP_DEC_ALG_3DES_CBC	"DEC_ALG_3DES_CBC"
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
 * */
#define SYNC_INP_ALG_HMAC_MD5	"ALG_HMAC_MD5"
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
			 hmac_md5_reference_plaintext[i],
			 hmac_md5_reference_length[i],
			 hmac_md5_reference_digest[i],
			 HMAC_MD5_96_CHECK_LEN);
	}
}

/* This test verifies the correctness of encode (plaintext -> ciphertext)
 * operation for 3DES_CBC algorithm. IV for the operation is the operation IV.
 * */
#define SYNC_INP_ENC_ALG_3DES_CBC_OVR_IV	"ENC_ALG_3DES_CBC_OVR_IV"
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
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i]);
	}
}

/* This test verifies the correctness of decode (ciphertext -> plaintext)
 * operation for 3DES_CBC algorithm. IV for the operation is the session IV.
 * */
#define SYNC_INP_DEC_ALG_3DES_CBC_OVR_IV	"DEC_ALG_3DES_CBC_OVR_IV"
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
			 tdes_cbc_reference_ciphertext[i],
			 tdes_cbc_reference_length[i],
			 tdes_cbc_reference_plaintext[i],
			 tdes_cbc_reference_length[i]);
	}
}

CU_TestInfo test_array_sync[] = {
	{SYNC_INP_ENC_ALG_3DES_CBC, enc_alg_3des_cbc },
	{SYNC_INP_DEC_ALG_3DES_CBC, dec_alg_3des_cbc },
	{SYNC_INP_ENC_ALG_3DES_CBC_OVR_IV, enc_alg_3des_cbc_ovr_iv },
	{SYNC_INP_DEC_ALG_3DES_CBC_OVR_IV, dec_alg_3des_cbc_ovr_iv },
	{SYNC_INP_ALG_HMAC_MD5, alg_hmac_md5 },
	CU_TEST_INFO_NULL,
};
