/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp_posix_extensions.h>
#include <odp/api/crypto.h>
#include <odp_init_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/sync.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp_packet_internal.h>
#include <odp/api/plat/queue_inlines.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>

#include <odp_crypto_internal.h>

#define MAX_SESSIONS 32

/*
 * Cipher algorithm capabilities
 *
 * Keep sorted: first by key length, then by IV length
 */
static const odp_crypto_cipher_capability_t cipher_capa_null[] = {
{.key_len = 0, .iv_len = 0} };

/*
 * Authentication algorithm capabilities
 *
 * Keep sorted: first by digest length, then by key length
 */
static const odp_crypto_auth_capability_t auth_capa_null[] = {
{.digest_len = 0, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

/** Forward declaration of session structure */
typedef struct odp_crypto_generic_session_t odp_crypto_generic_session_t;

/**
 * Algorithm handler function prototype
 */
typedef
odp_crypto_alg_err_t (*crypto_func_t)(odp_packet_t pkt,
				      const odp_crypto_packet_op_param_t *param,
				      odp_crypto_generic_session_t *session);
typedef void (*crypto_init_func_t)(odp_crypto_generic_session_t *session);

/**
 * Per crypto session data structure
 */
struct odp_crypto_generic_session_t {
	odp_crypto_generic_session_t *next;

	/* Session creation parameters */
	odp_crypto_session_param_t p;

	unsigned int idx;
};

typedef struct odp_crypto_global_s odp_crypto_global_t;

struct odp_crypto_global_s {
	odp_spinlock_t                lock;
	odp_crypto_generic_session_t *free;
	odp_crypto_generic_session_t  sessions[MAX_SESSIONS];

	/* These flags are cleared at alloc_session() */
	uint8_t ctx_valid[ODP_THREAD_COUNT_MAX][MAX_SESSIONS];

	odp_ticketlock_t              openssl_lock[];
};

static odp_crypto_global_t *global;

static
odp_crypto_generic_session_t *alloc_session(void)
{
	odp_crypto_generic_session_t *session = NULL;
	unsigned int i;

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

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		global->ctx_valid[i][session->idx] = 0;

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

int odp_crypto_capability(odp_crypto_capability_t *capa)
{
	if (odp_global_ro.disable.crypto) {
		_ODP_ERR("Crypto is disabled\n");
		return -1;
	}

	if (NULL == capa)
		return -1;

	/* Initialize crypto capability structure */
	memset(capa, 0, sizeof(odp_crypto_capability_t));

	capa->sync_mode = ODP_SUPPORT_PREFERRED;
	capa->async_mode = ODP_SUPPORT_YES;
	capa->queue_type_plain = 1;
	capa->queue_type_sched = 1;

	capa->ciphers.bit.null       = 1;

	capa->auths.bit.null         = 1;

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
	int rc;
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
	if (param->op_type == ODP_CRYPTO_OP_TYPE_OOP ||
	    param->op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP) {
		*status = ODP_CRYPTO_SES_ERR_PARAMS;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session) {
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	/* Copy parameters */
	session->p = *param;

	/* Process based on cipher */
	switch (param->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		rc = 0;
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		goto err;
	}

	/* Process based on auth */
	switch (param->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		rc = 0;
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_ERR_AUTH;
		goto err;
	}

	/* We're happy */
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

int
_odp_crypto_init_global(void)
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
	shm = odp_shm_reserve("_odp_crypto_null_global", mem_size,
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

	ret = odp_shm_free(odp_shm_lookup("_odp_crypto_null_global"));
	if (ret < 0) {
		_ODP_ERR("shm free failed for _odp_crypto_pool_null\n");
		rc = -1;
	}

	return rc;
}

int _odp_crypto_init_local(void)
{
	return 0;
}

int _odp_crypto_term_local(void)
{
	return 0;
}

void odp_crypto_session_param_init(odp_crypto_session_param_t *param)
{
	memset(param, 0, sizeof(odp_crypto_session_param_t));
	param->op_type = ODP_CRYPTO_OP_TYPE_BASIC;
}

uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

void odp_crypto_session_print(odp_crypto_session_t hdl)
{
	odp_crypto_generic_session_t *session;

	if (hdl == ODP_CRYPTO_SESSION_INVALID) {
		_ODP_ERR("Invalid crypto session\n");
		return;
	}

	session = (odp_crypto_generic_session_t *)(uintptr_t)hdl;

	_odp_crypto_session_print("null", session->idx, &session->p);
}

static
int crypto_int(odp_packet_t pkt_in,
	       odp_packet_t *pkt_out,
	       const odp_crypto_packet_op_param_t *param ODP_UNUSED)
{
	odp_packet_t out_pkt = pkt_in;
	odp_crypto_packet_result_t *op_result;

	/* Fill in result */
	packet_subtype_set(out_pkt, ODP_EVENT_PACKET_CRYPTO);
	op_result = &packet_hdr(out_pkt)->crypto_op_result;
	op_result->cipher_status.alg_err = ODP_CRYPTO_ALG_ERR_NONE;
	op_result->auth_status.alg_err = ODP_CRYPTO_ALG_ERR_NONE;

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
	odp_packet_t pkt = ODP_PACKET_INVALID;
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
