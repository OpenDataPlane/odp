/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/crypto.h>
#include <odp_internal.h>
#include <odp/atomic.h>
#include <odp/spinlock.h>
#include <odp/sync.h>
#include <odp/debug.h>
#include <odp/align.h>
#include <odp/shared_memory.h>
#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>
#include <odp_packet_internal.h>

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
odp_crypto_generic_op_result_t *get_op_result_from_event(odp_event_t ev)
{
	uint8_t   *temp;
	odp_crypto_generic_op_result_t *result;
	odp_buffer_t buf;

	/* HACK: Buffer is not packet any more in the API.
	 * Implementation still works that way. */
	buf = odp_buffer_from_event(ev);

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
	uint8_t *data  = odp_packet_data(params->out_pkt);
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
	uint8_t *data  = odp_packet_data(params->out_pkt);
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
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock iv;
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv, iv_ptr, sizeof(iv));

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     &iv,
			     1);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
enum crypto_alg_err des_decrypt(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock iv;
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv, iv_ptr, sizeof(iv));

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;

	/* Decrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     &iv,
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
		     odp_bool_t *posted,
		     odp_crypto_op_result_t *result)
{
	enum crypto_alg_err rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	enum crypto_alg_err rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_crypto_op_result_t local_result;

	session = (odp_crypto_generic_session_t *)(intptr_t)params->session;

	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->out_pkt)
		if (ODP_POOL_INVALID != session->output_pool)
			params->out_pkt =
				odp_packet_alloc(session->output_pool,
						 odp_packet_len(params->pkt));
	if (params->pkt != params->out_pkt) {
		if (odp_unlikely(ODP_PACKET_INVALID == params->out_pkt))
			ODP_ABORT();
		_odp_packet_copy_to_packet(params->pkt, 0, params->out_pkt, 0,
					   odp_packet_len(params->pkt));
		_odp_packet_copy_md_to_packet(params->pkt, params->out_pkt);
		odp_packet_free(params->pkt);
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

	/* Fill in result */
	local_result.ctx = params->ctx;
	local_result.pkt = params->out_pkt;
	local_result.cipher_status.alg_err = rc_cipher;
	local_result.cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.auth_status.alg_err = rc_auth;
	local_result.auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.ok =
		(rc_cipher == ODP_CRYPTO_ALG_ERR_NONE) &&
		(rc_auth == ODP_CRYPTO_ALG_ERR_NONE);

	/* If specified during creation post event to completion queue */
	if (ODP_QUEUE_INVALID != session->compl_queue) {
		odp_event_t completion_event;
		odp_crypto_generic_op_result_t *op_result;

		/* Linux generic will always use packet for completion event */
		completion_event = odp_packet_to_event(params->out_pkt);

		/* Asynchronous, build result (no HW so no errors) and send it*/
		op_result = get_op_result_from_event(completion_event);
		op_result->magic = OP_RESULT_MAGIC;
		op_result->result = local_result;
		odp_queue_enq(session->compl_queue, completion_event);

		/* Indicate to caller operation was async */
		*posted = 1;
	} else {
		/* Synchronous, simply return results */
		*result = local_result;

		/* Indicate to caller operation was sync */
		*posted = 0;
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
odp_hw_random_get(uint8_t *buf, size_t *len, odp_bool_t use_entropy ODP_UNUSED)
{
	int rc;
	rc = RAND_bytes(buf, *len);
	return ((1 == rc) ? 0 : -1);
}

odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev)
{
	return (odp_crypto_compl_t)ev;
}

odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event)
{
	return (odp_event_t)completion_event;
}

void
odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			odp_crypto_op_result_t *result)
{
	odp_event_t ev = odp_crypto_compl_to_event(completion_event);
	odp_crypto_generic_op_result_t *op_result;

	op_result = get_op_result_from_event(ev);

	if (OP_RESULT_MAGIC != op_result->magic)
		ODP_ABORT();

	memcpy(result, &op_result->result, sizeof(*result));
}

void
odp_crypto_compl_free(odp_crypto_compl_t completion_event ODP_UNUSED)
{
	/* We use the packet as the completion event so nothing to do here */
}
