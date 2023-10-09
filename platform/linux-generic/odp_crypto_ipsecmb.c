/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021, ARM Limited
 * Copyright (c) 2022-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <odp/autoheader_internal.h>

#include <odp/api/crypto.h>
#include <odp/api/spinlock.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp/api/hints.h>

#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp/api/plat/thread_inlines.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_packet_internal.h>

#include <ipsec-mb.h>

#define MAX_SESSIONS 4000
/* Length in bytes */
#define IPSEC_MB_CRYPTO_MAX_CIPHER_KEY_LENGTH      32
#define IPSEC_MB_CRYPTO_MAX_AUTH_KEY_LENGTH        32
#define IPSEC_MB_CRYPTO_MAX_DATA_LENGTH            65536
#define ZUC_DIGEST_LENGTH 4
#define SNOW3G_DIGEST_LENGTH 4

#define ODP_CRYPTO_IPSEC_MB_SHM_NAME "_odp_crypto_ipsecmb"
/*
 * Cipher algorithm capabilities
 *
 * Keep sorted: first by key length, then by IV length
 */
static const odp_crypto_cipher_capability_t cipher_capa_null[] = {
{.key_len = 0, .iv_len = 0} };

static const odp_crypto_cipher_capability_t cipher_capa_zuc_eea3[] = {
{.key_len = 16, .iv_len = 16},
{.key_len = 32, .iv_len = 25} };

static const odp_crypto_cipher_capability_t cipher_capa_snow3g_uea2[] = {
{.key_len = 16, .iv_len = 16} };

/*
 * Authentication algorithm capabilities
 *
 * Keep sorted: first by digest length, then by key length
 */
static const odp_crypto_auth_capability_t auth_capa_null[] = {
{.digest_len = 0, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_zuc_eia3[] = {
{.digest_len = 4, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 16},
{.digest_len = 4, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 25} };

static const odp_crypto_auth_capability_t auth_capa_snow3g_uia2[] = {
{.digest_len = SNOW3G_DIGEST_LENGTH, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 16} };

/** Forward declaration of session structure */
typedef struct odp_crypto_generic_session_t odp_crypto_generic_session_t;

/**
 * Algorithm handler function prototype
 */
typedef odp_crypto_alg_err_t (*crypto_func_t)(odp_packet_t pkt,
					      const odp_crypto_packet_op_param_t *param,
					      odp_crypto_generic_session_t *session);

/**
 * Per crypto session data structure
 */
struct odp_crypto_generic_session_t {
	odp_crypto_generic_session_t *next;

	/* Session creation parameters */
	odp_crypto_session_param_t p;

	odp_bool_t do_cipher_first;
	uint8_t null_crypto_enable :1;

	struct {
		union {
			uint8_t key_data[IPSEC_MB_CRYPTO_MAX_CIPHER_KEY_LENGTH];
			snow3g_key_schedule_t key_sched;
		};
		crypto_func_t func;
	} cipher;

	struct {
		union {
			uint8_t key[IPSEC_MB_CRYPTO_MAX_AUTH_KEY_LENGTH];
			snow3g_key_schedule_t key_sched;
		};
		crypto_func_t func;
	} auth;

	unsigned int idx;
};

typedef struct odp_crypto_global_s odp_crypto_global_t;

struct odp_crypto_global_s {
	odp_spinlock_t                lock;
	odp_crypto_generic_session_t *free;
	odp_crypto_generic_session_t  sessions[MAX_SESSIONS];
};

static odp_crypto_global_t *global;

typedef struct crypto_local_t {
	uint8_t buffer[IPSEC_MB_CRYPTO_MAX_DATA_LENGTH];
	IMB_MGR *mb_mgr;
} crypto_local_t;

static __thread crypto_local_t local;

static
odp_crypto_generic_session_t *alloc_session(void)
{
	odp_crypto_generic_session_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session) {
		global->free = session->next;
		session->next = NULL;
	}
	odp_spinlock_unlock(&global->lock);

	if (!session)
		return NULL;

	session->idx = session - global->sessions;

	return session;
}

static
void free_session(odp_crypto_generic_session_t *session)
{
	odp_spinlock_lock(&global->lock);
	session->next = global->free;
	global->free = session;
	odp_spinlock_unlock(&global->lock);
}

static odp_crypto_alg_err_t
null_crypto_routine(odp_packet_t pkt ODP_UNUSED,
		    const odp_crypto_packet_op_param_t *param ODP_UNUSED,
		    odp_crypto_generic_session_t *session ODP_UNUSED)
{
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t ipsec_mb_cipher_op(odp_packet_t pkt,
					const odp_crypto_packet_op_param_t *param,
					odp_crypto_generic_session_t *session)
{
	IMB_MGR *mb_mgr = local.mb_mgr;
	const uint8_t *iv_ptr = param->cipher_iv_ptr;
	uint32_t in_pos = param->cipher_range.offset;
	uint32_t in_len = param->cipher_range.length;

	_ODP_ASSERT(iv_ptr != NULL);

	uint32_t seg_len = 0;
	uint8_t *data = odp_packet_offset(pkt, in_pos, &seg_len, NULL);

	if (odp_unlikely(seg_len < in_len)) {
		if (odp_unlikely(in_len > IPSEC_MB_CRYPTO_MAX_DATA_LENGTH))
			return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

		/* Packet is segmented within the cipher range. Copy the cipher
		 * range to a contiguous buffer. */
		odp_packet_copy_to_mem(pkt, in_pos, in_len, local.buffer);

		data = local.buffer;
	}

	if (session->p.cipher_alg == ODP_CIPHER_ALG_ZUC_EEA3) {
		if (session->p.cipher_key.length == 16) {
			/* ZUC128 EEA3 */
			IMB_ZUC_EEA3_1_BUFFER(mb_mgr, session->cipher.key_data,
					      iv_ptr,
					      data,
					      data,
					      in_len);
		} else {
			/* Only 16 and 32 byte keys are supported
			* ZUC256 EEA3 */
			IMB_ZUC256_EEA3_1_BUFFER(mb_mgr, session->cipher.key_data,
						 iv_ptr,
						 data,
						 data,
						 in_len);
		}
	} else {
		/* Only ODP_CIPHER_ALG_SNOW3G_UEA2 */
		IMB_SNOW3G_F8_1_BUFFER(mb_mgr, &session->cipher.key_sched,
				       iv_ptr,
				       data,
				       data,
				       in_len);
	}

	if (odp_unlikely(imb_get_errno(mb_mgr) != 0))
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	if (odp_unlikely(seg_len < in_len))
		odp_packet_copy_from_mem(pkt, in_pos, in_len, data);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_zuc_eea3_param(odp_crypto_generic_session_t *session)
{
	if (!((16 == session->p.cipher_key.length &&
	       16 == session->p.cipher_iv_len) ||
	      (32 == session->p.cipher_key.length &&
	       25 == session->p.cipher_iv_len)))
		return -1;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	session->cipher.func = ipsec_mb_cipher_op;

	return 0;
}

static
odp_crypto_alg_err_t auth_ipsec_mb_gen(odp_packet_t pkt,
				       const odp_crypto_packet_op_param_t *param,
				       odp_crypto_generic_session_t *session)
{
	IMB_MGR *mb_mgr = local.mb_mgr;
	const uint8_t *iv_ptr = param->auth_iv_ptr;
	uint32_t in_pos = param->auth_range.offset;
	uint32_t in_len = param->auth_range.length;
	uint32_t auth_tag;

	_ODP_ASSERT(iv_ptr != NULL);

	uint32_t seg_len = 0;
	uint8_t *data = odp_packet_offset(pkt, in_pos, &seg_len, NULL);

	if (odp_unlikely(seg_len < in_len)) {
		if (odp_unlikely(in_len > IPSEC_MB_CRYPTO_MAX_DATA_LENGTH))
			return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

		/* Packet is segmented within the auth range. Copy the auth
		 * range to a contiguous buffer. */
		odp_packet_copy_to_mem(pkt, in_pos, in_len, local.buffer);

		data = local.buffer;
	}

	if (session->p.auth_alg == ODP_AUTH_ALG_ZUC_EIA3) {
		if (session->p.auth_key.length == 16) {
			/* ZUC128 EIA3 */
			IMB_ZUC_EIA3_1_BUFFER(mb_mgr, session->auth.key,
					      iv_ptr,
					      data,
					      param->auth_range.length * 8,
					      &auth_tag);
		} else {
			/* Only 16 and 32 byte keys are supported
			* ZUC256 EIA3 */
			IMB_ZUC256_EIA3_1_BUFFER(mb_mgr, session->auth.key,
						 iv_ptr,
						 data,
						 param->auth_range.length * 8,
						 &auth_tag);
		}
	} else {
		/* Only ODP_AUTH_ALG_SNOW3G_UIA2 */
		IMB_SNOW3G_F9_1_BUFFER(mb_mgr, &session->auth.key_sched,
				       iv_ptr,
				       data,
				       param->auth_range.length * 8,
				       &auth_tag);
	}

	if (odp_unlikely(imb_get_errno(mb_mgr) != 0))
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	/* Copy to the output location */
	odp_packet_copy_from_mem(pkt, param->hash_result_offset,
				 session->p.auth_digest_len,
				 &auth_tag);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_ipsec_mb_check(odp_packet_t pkt,
					 const odp_crypto_packet_op_param_t *param,
					 odp_crypto_generic_session_t *session)
{
	IMB_MGR *mb_mgr = local.mb_mgr;
	const uint8_t *iv_ptr = param->auth_iv_ptr;
	uint32_t in_pos = param->auth_range.offset;
	uint32_t in_len = param->auth_range.length;
	uint32_t bytes = ZUC_DIGEST_LENGTH;
	uint32_t hash_in;
	uint32_t hash_out;

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       bytes, &hash_in);

	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset, 0, bytes);

	_ODP_ASSERT(iv_ptr != NULL);

	uint32_t seg_len = 0;
	uint8_t *data = odp_packet_offset(pkt, in_pos, &seg_len, NULL);

	if (odp_unlikely(seg_len < in_len)) {
		if (odp_unlikely(in_len > IPSEC_MB_CRYPTO_MAX_DATA_LENGTH))
			return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

		/* Packet is segmented within the auth range. Copy the auth
		 * range to a contiguous buffer. */
		odp_packet_copy_to_mem(pkt, in_pos, in_len, local.buffer);

		data = local.buffer;
	}

	if (session->p.auth_alg == ODP_AUTH_ALG_ZUC_EIA3) {
		if (session->p.auth_key.length == 16) {
			/* ZUC128 EIA3 */
			IMB_ZUC_EIA3_1_BUFFER(mb_mgr, session->auth.key,
					      iv_ptr,
					      data,
					      param->auth_range.length * 8,
					      &hash_out);
		} else {
			/* Only 16 and 32 byte keys are supported
			* ZUC256 EIA3 */
			IMB_ZUC256_EIA3_1_BUFFER(mb_mgr, session->auth.key,
						 iv_ptr,
						 data,
						 param->auth_range.length * 8,
						 &hash_out);
		}
	} else {
		/* Only ODP_AUTH_ALG_SNOW3G_UIA2 */
		IMB_SNOW3G_F9_1_BUFFER(mb_mgr, &session->auth.key_sched,
				       iv_ptr,
				       data,
				       param->auth_range.length * 8,
				       &hash_out);
	}

	if (odp_unlikely(imb_get_errno(mb_mgr) != 0))
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	/* Verify match */
	if (hash_in != hash_out)
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_auth_zuc_eia3_param(odp_crypto_generic_session_t *session)
{
	if (!((16 == session->p.auth_key.length &&
	       16 == session->p.auth_iv_len) ||
	      (32 == session->p.auth_key.length &&
	       25 == session->p.auth_iv_len)))
		return -1;

	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_ipsec_mb_gen;
	else
		session->auth.func = auth_ipsec_mb_check;

	if (session->p.auth_digest_len != ZUC_DIGEST_LENGTH)
		return -1;

	memcpy(session->auth.key, session->p.auth_key.data,
	       session->p.auth_key.length);

	return 0;
}

static int process_snow3g_uea2_param(odp_crypto_generic_session_t *session)
{
	if (!(16 == session->p.cipher_key.length &&
	      16 == session->p.cipher_iv_len))
		return -1;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	session->cipher.func = ipsec_mb_cipher_op;

	return IMB_SNOW3G_INIT_KEY_SCHED(local.mb_mgr, session->p.cipher_key.data,
				  &session->cipher.key_sched);
}

static int process_auth_snow3g_uia2_param(odp_crypto_generic_session_t *session)
{
	if (!(16 == session->p.auth_key.length &&
	      16 == session->p.auth_iv_len))
		return -1;

	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_ipsec_mb_gen;
	else
		session->auth.func = auth_ipsec_mb_check;

	if (session->p.auth_digest_len != SNOW3G_DIGEST_LENGTH)
		return -1;

	memcpy(session->auth.key, session->p.auth_key.data,
	       session->p.auth_key.length);

	return IMB_SNOW3G_INIT_KEY_SCHED(local.mb_mgr, session->p.auth_key.data,
				  &session->auth.key_sched);
}

int odp_crypto_capability(odp_crypto_capability_t *capa)
{
	if (NULL == capa)
		return -1;

	memset(capa, 0, sizeof(odp_crypto_capability_t));

	capa->sync_mode = ODP_SUPPORT_PREFERRED;
	capa->async_mode = ODP_SUPPORT_YES;
	capa->queue_type_plain = 1;
	capa->queue_type_sched = 1;

	capa->ciphers.bit.null       = 1;
	capa->auths.bit.null         = 1;

	capa->ciphers.bit.zuc_eea3   = 1;
	capa->auths.bit.zuc_eia3     = 1;

	capa->ciphers.bit.snow3g_uea2 = 1;
	capa->auths.bit.snow3g_uia2   = 1;

	capa->max_sessions = MAX_SESSIONS;

	return 0;
}

int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t dst[],
				 int num_copy)
{
	const odp_crypto_cipher_capability_t *src;
	int num;
	int size = sizeof(odp_crypto_cipher_capability_t);

	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		src = cipher_capa_null;
		num = sizeof(cipher_capa_null) / size;
		break;
	case ODP_CIPHER_ALG_ZUC_EEA3:
		src = cipher_capa_zuc_eea3;
		num = sizeof(cipher_capa_zuc_eea3) / size;
		break;
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		src = cipher_capa_snow3g_uea2;
		num = sizeof(cipher_capa_snow3g_uea2) / size;
		break;
	default:
		return -1;
	}

	if (num < num_copy)
		num_copy = num;

	memcpy(dst, src, num_copy * size);

	return num;
}

int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t dst[], int num_copy)
{
	const odp_crypto_auth_capability_t *src;
	int num;
	int size = sizeof(odp_crypto_auth_capability_t);

	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		src = auth_capa_null;
		num = sizeof(auth_capa_null) / size;
		break;
	case ODP_AUTH_ALG_ZUC_EIA3:
		src = auth_capa_zuc_eia3;
		num = sizeof(auth_capa_zuc_eia3) / size;
		break;
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		src = auth_capa_snow3g_uia2;
		num = sizeof(auth_capa_snow3g_uia2) / size;
		break;
	default:
		return -1;
	}

	if (num < num_copy)
		num_copy = num;

	memcpy(dst, src, num_copy * size);

	return num;
}

int
odp_crypto_session_create(const odp_crypto_session_param_t *param,
			  odp_crypto_session_t *session_out,
			  odp_crypto_ses_create_err_t *status)
{
	int rc = 0;
	odp_crypto_generic_session_t *session;

	if (odp_global_ro.disable.crypto) {
		_ODP_ERR("Crypto is disabled\n");
		/* Dummy output to avoid compiler warning about uninitialized
		 * variables */
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	if (param->cipher_range_in_bits) {
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}
	if (param->auth_range_in_bits) {
		*status = ODP_CRYPTO_SES_ERR_AUTH;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}
	if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP) {
		*status = ODP_CRYPTO_SES_ERR_PARAMS;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	session = alloc_session();
	if (NULL == session) {
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	session->p = *param;

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == param->op)
		session->do_cipher_first =  param->auth_cipher_text;
	else
		session->do_cipher_first = !param->auth_cipher_text;

	/* Process based on cipher */
	switch (param->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		session->cipher.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_CIPHER_ALG_ZUC_EEA3:
		rc = process_zuc_eea3_param(session);
		break;
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		rc = process_snow3g_uea2_param(session);
		break;
	default:
		rc = -1;
	}

	if (param->null_crypto_enable && param->op_mode == ODP_CRYPTO_SYNC)
		rc = -1;
	session->null_crypto_enable = !!param->null_crypto_enable;

	if (rc) {
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		goto err;
	}

	/* Process based on auth */
	switch (param->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_AUTH_ALG_ZUC_EIA3:
		rc = process_auth_zuc_eia3_param(session);
		break;
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		rc = process_auth_snow3g_uia2_param(session);
		break;
	default:
		rc = -1;
	}

	if (rc) {
		*status = ODP_CRYPTO_SES_ERR_AUTH;
		goto err;
	}

	*session_out = (intptr_t)session;
	*status = ODP_CRYPTO_SES_ERR_NONE;
	return 0;

err:
	/* error status should be set at this moment */
	if (session != NULL)
		free_session(session);
	*session_out = ODP_CRYPTO_SESSION_INVALID;
	return -1;
}

int odp_crypto_session_destroy(odp_crypto_session_t session)
{
	odp_crypto_generic_session_t *generic;

	generic = (odp_crypto_generic_session_t *)(intptr_t)session;
	memset(generic, 0, sizeof(*generic));
	free_session(generic);
	return 0;
}

int _odp_crypto_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;

	if (odp_global_ro.disable.crypto) {
		_ODP_PRINT("\nODP crypto is DISABLED\n");
		return 0;
	}

	/* Calculate the memory size we need */
	mem_size  = sizeof(odp_crypto_global_t);

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve(ODP_CRYPTO_IPSEC_MB_SHM_NAME, mem_size,
			      ODP_CACHE_LINE_SIZE,
			      0);
	if (ODP_SHM_INVALID == shm) {
		_ODP_ERR("unable to allocate crypto pool\n");
		return -1;
	}

	global = odp_shm_addr(shm);

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}
	odp_spinlock_init(&global->lock);

	return 0;
}

int _odp_crypto_term_global(void)
{
	int rc = 0;
	int ret;
	int count = 0;
	odp_crypto_generic_session_t *session;

	if (odp_global_ro.disable.crypto)
		return 0;

	for (session = global->free; session != NULL; session = session->next)
		count++;
	if (count != MAX_SESSIONS) {
		_ODP_ERR("crypto sessions still active\n");
		rc = -1;
	}

	ret = odp_shm_free(odp_shm_lookup(ODP_CRYPTO_IPSEC_MB_SHM_NAME));
	if (ret < 0) {
		_ODP_ERR("shm free failed for %s\n", ODP_CRYPTO_IPSEC_MB_SHM_NAME);
		rc = -1;
	}

	return rc;
}

int _odp_crypto_init_local(void)
{
	uint64_t flags = 0;

	if (odp_global_ro.disable.crypto)
		return 0;

	memset(&local, 0, sizeof(local));

	local.mb_mgr = alloc_mb_mgr(flags);
	if (local.mb_mgr == NULL)
		return -1;

	init_mb_mgr_auto(local.mb_mgr, NULL);

	return 0;
}

int _odp_crypto_term_local(void)
{
	if (odp_global_ro.disable.crypto)
		return 0;

	free_mb_mgr(local.mb_mgr);
	return 0;
}

void odp_crypto_session_param_init(odp_crypto_session_param_t *param)
{
	memset(param, 0, sizeof(odp_crypto_session_param_t));
}

uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

static int copy_data_and_metadata(odp_packet_t dst, odp_packet_t src)
{
	int md_copy;
	int rc;

	md_copy = _odp_packet_copy_md_possible(odp_packet_pool(dst),
					       odp_packet_pool(src));
	if (odp_unlikely(md_copy < 0)) {
		_ODP_ERR("Unable to copy packet metadata\n");
		return -1;
	}

	rc = odp_packet_copy_from_pkt(dst, 0, src, 0, odp_packet_len(src));
	if (odp_unlikely(rc < 0)) {
		_ODP_ERR("Unable to copy packet data\n");
		return -1;
	}

	_odp_packet_copy_md(packet_hdr(dst), packet_hdr(src), md_copy);
	return 0;
}

static odp_packet_t get_output_packet(const odp_crypto_generic_session_t *session,
				      odp_packet_t pkt_in,
				      odp_packet_t pkt_out)
{
	int rc;

	if (odp_likely(pkt_in == pkt_out))
		return pkt_out;

	if (pkt_out == ODP_PACKET_INVALID) {
		odp_pool_t pool = session->p.output_pool;

		_ODP_ASSERT(pool != ODP_POOL_INVALID);
		if (pool == odp_packet_pool(pkt_in)) {
			pkt_out = pkt_in;
		} else {
			pkt_out = odp_packet_copy(pkt_in, pool);
			if (odp_likely(pkt_out != ODP_PACKET_INVALID))
				odp_packet_free(pkt_in);
		}
		return pkt_out;
	}
	rc = copy_data_and_metadata(pkt_out, pkt_in);
	if (odp_unlikely(rc < 0))
		return ODP_PACKET_INVALID;

	odp_packet_free(pkt_in);
	return pkt_out;
}

static
int crypto_int(odp_packet_t pkt_in,
	       odp_packet_t *pkt_out,
	       const odp_crypto_packet_op_param_t *param)
{
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_packet_t out_pkt;
	odp_crypto_packet_result_t *op_result;

	session = (odp_crypto_generic_session_t *)(intptr_t)param->session;

	if (odp_likely(session->p.op_type == ODP_CRYPTO_OP_TYPE_BASIC)) {
		out_pkt = pkt_in;
	} else {
		out_pkt = get_output_packet(session, pkt_in, *pkt_out);
		if (odp_unlikely(out_pkt == ODP_PACKET_INVALID))
			return -1;
	}

	if (odp_unlikely(session->null_crypto_enable && param->null_crypto))
		goto out;

	/* Invoke the crypto function */
	if (session->do_cipher_first) {
		rc_cipher = session->cipher.func(out_pkt, param, session);
		rc_auth = session->auth.func(out_pkt, param, session);
	} else {
		rc_auth = session->auth.func(out_pkt, param, session);
		rc_cipher = session->cipher.func(out_pkt, param, session);
	}

out:
	packet_subtype_set(out_pkt, ODP_EVENT_PACKET_CRYPTO);
	op_result = &packet_hdr(out_pkt)->crypto_op_result;
	op_result->cipher_status.alg_err = rc_cipher;
	op_result->auth_status.alg_err = rc_auth;

	/* Synchronous, simply return results */
	*pkt_out = out_pkt;

	return 0;
}

int odp_crypto_op(const odp_packet_t pkt_in[],
		  odp_packet_t pkt_out[],
		  const odp_crypto_packet_op_param_t param[],
		  int num_pkt)
{
	int i, rc;
	odp_crypto_generic_session_t *session;

	for (i = 0; i < num_pkt; i++) {
		session = (odp_crypto_generic_session_t *)(intptr_t)param[i].session;
		_ODP_ASSERT(ODP_CRYPTO_SYNC == session->p.op_mode);

		rc = crypto_int(pkt_in[i], &pkt_out[i], &param[i]);
		if (rc < 0)
			break;
	}

	return i;
}

int odp_crypto_op_enq(const odp_packet_t pkt_in[],
		      const odp_packet_t pkt_out[],
		      const odp_crypto_packet_op_param_t param[],
		      int num_pkt)
{
	odp_packet_t pkt;
	odp_event_t event;
	odp_crypto_generic_session_t *session;
	int i, rc;

	for (i = 0; i < num_pkt; i++) {
		session = (odp_crypto_generic_session_t *)(intptr_t)param[i].session;
		_ODP_ASSERT(ODP_CRYPTO_ASYNC == session->p.op_mode);
		_ODP_ASSERT(ODP_QUEUE_INVALID != session->p.compl_queue);

		if (session->p.op_type != ODP_CRYPTO_OP_TYPE_BASIC)
			pkt = pkt_out[i];

		rc = crypto_int(pkt_in[i], &pkt, &param[i]);
		if (rc < 0)
			break;

		event = odp_packet_to_event(pkt);
		if (odp_queue_enq(session->p.compl_queue, event)) {
			odp_event_free(event);
			break;
		}
	}

	return i;
}
