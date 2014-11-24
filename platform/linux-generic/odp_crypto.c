/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_crypto.h>
#include <odp_internal.h>
#include <odp_atomic.h>
#include <odp_spinlock.h>
#include <odp_sync.h>
#include <odp_debug.h>
#include <odp_align.h>
#include <odp_shared_memory.h>
#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>
#include <odp_hints.h>
#include <odph_packet.h>

#include <string.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define MAX_SESSIONS 32

typedef struct {
	odp_atomic_u32_t next;
	uint32_t         max;
	odp_crypto_generic_session_t sessions[0];
} odp_crypto_global_t;

static odp_crypto_global_t *global;

/*
 * @todo This is a serious hack to allow us to use packet buffer to convey
 *       crypto operation results by placing them at the very end of the
 *       packet buffer.  The issue should be resolved shortly once the issue
 *       of packets versus events on completion queues is closed.
 */
static
odp_crypto_generic_op_result_t *get_op_result_from_buffer(odp_buffer_t buf)
{
	uint8_t   *temp;
	odp_crypto_generic_op_result_t *result;

	temp  = odp_buffer_addr(buf);
	temp += odp_buffer_size(buf);
	temp -= sizeof(*result);
	result = (odp_crypto_generic_op_result_t *)(void *)temp;
	return result;
}

static
odp_crypto_generic_session_t *alloc_session(void)
{
	uint32_t idx;
	odp_crypto_generic_session_t *session = NULL;

	idx = odp_atomic_fetch_inc_u32(&global->next);
	if (idx < global->max) {
		session = &global->sessions[idx];
		session->index = idx;
	}
	return session;
}

static
enum crypto_alg_err null_crypto_routine(
	odp_crypto_op_params_t *params ODP_UNUSED,
	odp_crypto_generic_session_t *session ODP_UNUSED)
{
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
enum crypto_alg_err md5_gen(odp_crypto_op_params_t *params,
			    odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_addr(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Hash it */
	HMAC(EVP_md5(),
	     session->auth.data.md5.key,
	     16,
	     data,
	     len,
	     hash,
	     NULL);

	/* Copy to the output location */
	memcpy(icv, hash, session->auth.data.md5.bytes);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
enum crypto_alg_err md5_check(odp_crypto_op_params_t *params,
			      odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_addr(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint32_t bytes = session->auth.data.md5.bytes;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Copy current value out and clear it before authentication */
	memset(hash_in, 0, sizeof(hash_in));
	memcpy(hash_in, icv, bytes);
	memset(icv, 0, bytes);
	memset(hash_out, 0, sizeof(hash_out));

	/* Hash it */
	HMAC(EVP_md5(),
	     session->auth.data.md5.key,
	     16,
	     data,
	     len,
	     hash_out,
	     NULL);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
enum crypto_alg_err des_encrypt(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_addr(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock *iv = NULL;
	DES_cblock iv_temp;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	if (session->cipher.iv.data) {
		memcpy(iv_temp, session->cipher.iv.data, sizeof(iv_temp));
		iv = &iv_temp;
	}

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;

	/* Override IV if requested */
	if (params->override_iv_ptr)
		iv = (DES_cblock *)params->override_iv_ptr;

	/* No session or operation IV */
	if (!iv)
		return ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;

	/* Encrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     iv,
			     1);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
enum crypto_alg_err des_decrypt(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_addr(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock *iv = (DES_cblock *)session->cipher.iv.data;

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;

	/* Override IV if requested */
	if (params->override_iv_ptr)
		iv = (DES_cblock *)params->override_iv_ptr;

	/* Decrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     iv,
			     0);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_des_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params)
{
	/* Verify IV len is either 0 or 8 */
	if (!((0 == params->iv.length) || (8 == params->iv.length)))
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->cipher.func = des_encrypt;
	else
		session->cipher.func = des_decrypt;

	/* Convert keys */
	DES_set_key((DES_cblock *)&params->cipher_key.data[0],
		    &session->cipher.data.des.ks1);
	DES_set_key((DES_cblock *)&params->cipher_key.data[8],
		    &session->cipher.data.des.ks2);
	DES_set_key((DES_cblock *)&params->cipher_key.data[16],
		    &session->cipher.data.des.ks3);

	return 0;
}

static
int process_md5_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params,
		       uint32_t bits)
{
	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->auth.func = md5_gen;
	else
		session->auth.func = md5_check;

	/* Number of valid bytes */
	session->auth.data.md5.bytes = bits / 8;

	/* Convert keys */
	memcpy(session->auth.data.md5.key, params->auth_key.data, 16);

	return 0;
}

int
odp_crypto_session_create(odp_crypto_session_params_t *params,
			  odp_crypto_session_t *session_out,
			  enum odp_crypto_ses_create_err *status)
{
	int rc;
	odp_crypto_generic_session_t *session;

	/* Default to successful result */
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->do_cipher_first =  params->auth_cipher_text;
	else
		session->do_cipher_first = !params->auth_cipher_text;

	/* Copy stuff over */
	session->op = params->op;
	session->compl_queue = params->compl_queue;
	session->cipher.alg  = params->cipher_alg;
	session->cipher.iv.data = params->iv.data;
	session->cipher.iv.len  = params->iv.length;
	session->auth.alg  = params->auth_alg;
	session->output_pool = params->output_pool;

	/* Process based on cipher */
	switch (params->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		session->cipher.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		rc = process_des_params(session, params);
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;
		return -1;
	}

	/* Process based on auth */
	switch (params->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_AUTH_ALG_MD5_96:
		rc = process_md5_params(session, params, 96);
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH;
		return -1;
	}

	/* We're happy */
	*session_out = (intptr_t)session;
	return 0;
}


int
odp_crypto_operation(odp_crypto_op_params_t *params,
		     bool *posted,
		     odp_buffer_t completion_event)
{
	enum crypto_alg_err rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	enum crypto_alg_err rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_crypto_generic_op_result_t *result;

	*posted = 0;
	session = (odp_crypto_generic_session_t *)(intptr_t)params->session;

	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->out_pkt)
		if (ODP_BUFFER_POOL_INVALID != session->output_pool)
			params->out_pkt =
				odp_buffer_alloc(session->output_pool);
	if (params->pkt != params->out_pkt) {
		if (odp_unlikely(ODP_PACKET_INVALID == params->out_pkt))
			abort();
		odp_packet_copy(params->out_pkt, params->pkt);
		if (completion_event == odp_packet_to_buffer(params->pkt))
			completion_event =
				odp_packet_to_buffer(params->out_pkt);
		odph_packet_free(params->pkt);
		params->pkt = ODP_PACKET_INVALID;
	}

	/* Invoke the functions */
	if (session->do_cipher_first) {
		rc_cipher = session->cipher.func(params, session);
		rc_auth = session->auth.func(params, session);
	} else {
		rc_auth = session->auth.func(params, session);
		rc_cipher = session->cipher.func(params, session);
	}

	/* Build Result (no HW so no errors) */
	result = get_op_result_from_buffer(completion_event);
	result->magic = OP_RESULT_MAGIC;
	result->cipher.alg_err = rc_cipher;
	result->cipher.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	result->auth.alg_err = rc_auth;
	result->auth.hw_err = ODP_CRYPTO_HW_ERR_NONE;

	/* If specified during creation post event to completion queue */
	if (ODP_QUEUE_INVALID != session->compl_queue) {
		odp_queue_enq(session->compl_queue, completion_event);
		*posted = 1;
	}
	return 0;
}

int
odp_crypto_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(odp_crypto_generic_session_t));

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("crypto_pool", mem_size,
			      ODP_CACHE_LINE_SIZE, 0);

	global = odp_shm_addr(shm);

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize it */
	global->max = MAX_SESSIONS;

	return 0;
}

int
odp_hw_random_get(uint8_t *buf, size_t *len, bool use_entropy ODP_UNUSED)
{
	int rc;
	rc = RAND_bytes(buf, *len);
	return ((1 == rc) ? 0 : -1);
}

void
odp_crypto_get_operation_compl_status(odp_buffer_t completion_event,
				      odp_crypto_compl_status_t *auth,
				      odp_crypto_compl_status_t *cipher)
{
	odp_crypto_generic_op_result_t *result;

	result = get_op_result_from_buffer(completion_event);

	if (OP_RESULT_MAGIC != result->magic)
		abort();

	memcpy(auth, &result->auth, sizeof(*auth));
	memcpy(cipher, &result->cipher, sizeof(*cipher));
}


void
odp_crypto_set_operation_compl_ctx(odp_buffer_t completion_event ODP_UNUSED,
				   void *ctx ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

void
*odp_crypto_get_operation_compl_ctx(odp_buffer_t completion_event ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return NULL;
}

odp_packet_t
odp_crypto_get_operation_compl_packet(odp_buffer_t completion_event ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_PACKET_INVALID;
}
