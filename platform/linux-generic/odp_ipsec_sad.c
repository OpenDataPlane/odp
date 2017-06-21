/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/atomic.h>
#include <odp/api/ipsec.h>
#include <odp/api/random.h>
#include <odp/api/shared_memory.h>

#include <odp_debug_internal.h>
#include <odp_ipsec_internal.h>

#include <string.h>

#define IPSEC_SA_STATE_DISABLE	0x40000000
#define IPSEC_SA_STATE_FREE	0xc0000000 /* This includes disable !!! */

typedef struct ipsec_sa_table_t {
	ipsec_sa_t ipsec_sa[ODP_CONFIG_IPSEC_SAS];
	odp_shm_t shm;
} ipsec_sa_table_t;

static ipsec_sa_table_t *ipsec_sa_tbl;

static inline
ipsec_sa_t *ipsec_sa_entry(uint32_t ipsec_sa_idx)
{
	return &ipsec_sa_tbl->ipsec_sa[ipsec_sa_idx];
}

static inline
ipsec_sa_t *ipsec_sa_entry_from_hdl(odp_ipsec_sa_t ipsec_sa_hdl)
{
	return ipsec_sa_entry(_odp_typeval(ipsec_sa_hdl));
}

static inline
odp_ipsec_sa_t ipsec_sa_index_to_handle(uint32_t ipsec_sa_idx)
{
	return _odp_cast_scalar(odp_ipsec_sa_t, ipsec_sa_idx);
}

int _odp_ipsec_sad_init_global(void)
{
	odp_shm_t shm;
	unsigned i;

	shm = odp_shm_reserve("ipsec_sa_table",
			      sizeof(ipsec_sa_table_t),
			      ODP_CACHE_LINE_SIZE, 0);

	ipsec_sa_tbl = odp_shm_addr(shm);
	if (ipsec_sa_tbl == NULL)
		return -1;

	memset(ipsec_sa_tbl, 0, sizeof(ipsec_sa_table_t));
	ipsec_sa_tbl->shm = shm;

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		ipsec_sa_t *ipsec_sa = ipsec_sa_entry(i);

		ipsec_sa->ipsec_sa_hdl = ipsec_sa_index_to_handle(i);
		ipsec_sa->ipsec_sa_idx = i;
		odp_atomic_init_u32(&ipsec_sa->state, IPSEC_SA_STATE_FREE);
		odp_atomic_init_u32(&ipsec_sa->seq, 0);
		odp_atomic_init_u32(&ipsec_sa->tun_hdr_id, 0);
		odp_atomic_init_u64(&ipsec_sa->bytes, 0);
		odp_atomic_init_u64(&ipsec_sa->packets, 0);
	}

	return 0;
}

int _odp_ipsec_sad_term_global(void)
{
	int i;
	ipsec_sa_t *ipsec_sa;
	int ret = 0;
	int rc = 0;

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		ipsec_sa = ipsec_sa_entry(i);

		if (odp_atomic_load_u32(&ipsec_sa->state) !=
		    IPSEC_SA_STATE_FREE) {
			ODP_ERR("Not destroyed ipsec_sa: %u\n",
				ipsec_sa->ipsec_sa_idx);
			rc = -1;
		}
		odp_atomic_store_u32(&ipsec_sa->state, IPSEC_SA_STATE_FREE);
	}

	ret = odp_shm_free(ipsec_sa_tbl->shm);
	if (ret < 0) {
		ODP_ERR("shm free failed");
		rc = -1;
	}

	return rc;
}

static
ipsec_sa_t *ipsec_sa_reserve(void)
{
	int i;
	ipsec_sa_t *ipsec_sa;

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		uint32_t state = IPSEC_SA_STATE_FREE;

		ipsec_sa = ipsec_sa_entry(i);

		if (odp_atomic_cas_acq_u32(&ipsec_sa->state, &state, 0))
			return ipsec_sa;
	}

	return NULL;
}

static
void ipsec_sa_release(ipsec_sa_t *ipsec_sa)
{
	odp_atomic_store_rel_u32(&ipsec_sa->state, IPSEC_SA_STATE_FREE);
}

static
int ipsec_sa_lock(ipsec_sa_t *ipsec_sa)
{
	int cas = 0;
	uint32_t state = odp_atomic_load_u32(&ipsec_sa->state);

	while (0 == cas) {
		/*
		 * This can be called from lookup path, so we really need this
		 * check
		 */
		if (state & IPSEC_SA_STATE_DISABLE)
			return -1;

		cas = odp_atomic_cas_acq_u32(&ipsec_sa->state, &state,
					     state + 1);
	}

	return 0;
}

/* Do not call directly, use _odp_ipsec_sa_unuse */
static
odp_bool_t ipsec_sa_unlock(ipsec_sa_t *ipsec_sa)
{
	int cas = 0;
	uint32_t state = odp_atomic_load_u32(&ipsec_sa->state);

	while (0 == cas)
		cas = odp_atomic_cas_rel_u32(&ipsec_sa->state, &state,
					     state - 1);

	return state == IPSEC_SA_STATE_DISABLE;
}

ipsec_sa_t *_odp_ipsec_sa_use(odp_ipsec_sa_t sa)
{
	ipsec_sa_t *ipsec_sa;

	ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

	ipsec_sa = ipsec_sa_entry_from_hdl(sa);

	if (ipsec_sa_lock(ipsec_sa) < 0)
		return NULL;

	return ipsec_sa;
}

void _odp_ipsec_sa_unuse(ipsec_sa_t *ipsec_sa)
{
	odp_queue_t queue;
	odp_ipsec_sa_t sa;

	ODP_ASSERT(NULL != ipsec_sa);

	queue = ipsec_sa->queue;
	sa = ipsec_sa->ipsec_sa_hdl;

	if (ipsec_sa_unlock(ipsec_sa) && ODP_QUEUE_INVALID != queue)
		_odp_ipsec_status_send(queue,
				       ODP_IPSEC_STATUS_SA_DISABLE,
				       0,
				       sa);
}

void odp_ipsec_sa_param_init(odp_ipsec_sa_param_t *param)
{
	memset(param, 0, sizeof(odp_ipsec_sa_param_t));
	param->dest_queue = ODP_QUEUE_INVALID;
}

odp_ipsec_sa_t odp_ipsec_sa_create(const odp_ipsec_sa_param_t *param)
{
	ipsec_sa_t *ipsec_sa;
	odp_crypto_session_param_t crypto_param;
	odp_crypto_ses_create_err_t ses_create_rc;

	ipsec_sa = ipsec_sa_reserve();
	if (NULL == ipsec_sa) {
		ODP_ERR("No more free SA\n");
		return ODP_IPSEC_SA_INVALID;
	}

#if 1
	ipsec_sa->in_place = 0;
#else
	ipsec_sa->in_place = 1;
#endif
	ipsec_sa->proto = param->proto;
	ipsec_sa->spi = param->spi;
	odp_atomic_store_u32(&ipsec_sa->seq, param->seq);
	ipsec_sa->context = param->context;
	ipsec_sa->queue = param->dest_queue;
	ipsec_sa->mode = param->mode;
	ipsec_sa->lookup_mode = param->lookup_mode;
	ipsec_sa->dec_ttl = param->opt.dec_ttl;
	ipsec_sa->copy_dscp = param->opt.copy_dscp;
	ipsec_sa->copy_df = param->opt.copy_df;

	odp_atomic_store_u64(&ipsec_sa->bytes, 0);
	odp_atomic_store_u64(&ipsec_sa->packets, 0);
	ipsec_sa->soft_limit_bytes = param->lifetime.soft_limit.bytes;
	ipsec_sa->soft_limit_packets = param->lifetime.soft_limit.packets;
	ipsec_sa->hard_limit_bytes = param->lifetime.hard_limit.bytes;
	ipsec_sa->hard_limit_packets = param->lifetime.hard_limit.packets;

	if (ODP_IPSEC_LOOKUP_DSTADDR_SPI == ipsec_sa->lookup_mode)
		memcpy(&ipsec_sa->lookup_dst_ip, param->lookup_param.dst_addr,
		       sizeof(ipsec_sa->lookup_dst_ip));

	if (ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode &&
	    ODP_IPSEC_DIR_OUTBOUND == param->dir) {
		if (param->tunnel.type != ODP_IPSEC_TUNNEL_IPV4) {
			ipsec_sa_release(ipsec_sa);

			return ODP_IPSEC_SA_INVALID;
		}
		memcpy(&ipsec_sa->tun_src_ip, param->tunnel.ipv4.src_addr,
		       sizeof(ipsec_sa->tun_src_ip));
		memcpy(&ipsec_sa->tun_dst_ip, param->tunnel.ipv4.dst_addr,
		       sizeof(ipsec_sa->tun_dst_ip));
		odp_atomic_store_u32(&ipsec_sa->tun_hdr_id, 0);
		ipsec_sa->tun_ttl = param->tunnel.ipv4.ttl;
		ipsec_sa->tun_dscp = param->tunnel.ipv4.dscp;
		ipsec_sa->tun_df = param->tunnel.ipv4.df;
	}

	odp_crypto_session_param_init(&crypto_param);

	/* Setup parameters and call crypto library to create session */
	crypto_param.op = (ODP_IPSEC_DIR_INBOUND == param->dir) ?
			ODP_CRYPTO_OP_DECODE :
			ODP_CRYPTO_OP_ENCODE;
	crypto_param.auth_cipher_text = 1;

	crypto_param.pref_mode   = ODP_CRYPTO_SYNC;
	crypto_param.compl_queue = ODP_QUEUE_INVALID;
	crypto_param.output_pool = ODP_POOL_INVALID;

	crypto_param.cipher_alg = param->crypto.cipher_alg;
	crypto_param.cipher_key = param->crypto.cipher_key;
	crypto_param.auth_alg = param->crypto.auth_alg;
	crypto_param.auth_key = param->crypto.auth_key;

	switch (crypto_param.auth_alg) {
	case ODP_AUTH_ALG_NULL:
		ipsec_sa->icv_len = 0;
		break;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_MD5_96:
#endif
	case ODP_AUTH_ALG_MD5_HMAC:
		ipsec_sa->icv_len = 12;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		ipsec_sa->icv_len = 12;
		break;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_SHA256_128:
#endif
	case ODP_AUTH_ALG_SHA256_HMAC:
		ipsec_sa->icv_len = 16;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		ipsec_sa->icv_len = 32;
		break;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_AES128_GCM:
#endif
	case ODP_AUTH_ALG_AES_GCM:
		ipsec_sa->icv_len = 16;
		break;
	default:
		return ODP_IPSEC_SA_INVALID;
	}

	switch (crypto_param.cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		ipsec_sa->esp_iv_len = 0;
		ipsec_sa->esp_block_len = 1;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		ipsec_sa->esp_iv_len = 8;
		ipsec_sa->esp_block_len = 8;
		break;
#if ODP_DEPRECATED_API
	case ODP_CIPHER_ALG_AES128_CBC:
	case ODP_CIPHER_ALG_AES128_GCM:
#endif
	case ODP_CIPHER_ALG_AES_CBC:
	case ODP_CIPHER_ALG_AES_GCM:
		ipsec_sa->esp_iv_len = 16;
		ipsec_sa->esp_block_len = 16;
		break;
	default:
		return ODP_IPSEC_SA_INVALID;
	}

	crypto_param.auth_digest_len = ipsec_sa->icv_len;

	if (odp_crypto_session_create(&crypto_param, &ipsec_sa->session,
				      &ses_create_rc))
		goto error;

	return ipsec_sa->ipsec_sa_hdl;

error:
	ipsec_sa_release(ipsec_sa);

	return ODP_IPSEC_SA_INVALID;
}

int odp_ipsec_sa_disable(odp_ipsec_sa_t sa)
{
	ipsec_sa_t *ipsec_sa = ipsec_sa_entry_from_hdl(sa);
	uint32_t state;
	int cas = 0;

	/* This is a custom rwlock implementation. It is not possible to use
	 * original rwlock, because there is no way to test if current code is
	 * the last reader when disable operation is pending. */
	state = odp_atomic_load_u32(&ipsec_sa->state);

	while (0 == cas) {
		if (state & IPSEC_SA_STATE_DISABLE)
			return -1;

		cas = odp_atomic_cas_acq_u32(&ipsec_sa->state, &state,
					     state | IPSEC_SA_STATE_DISABLE);
	}

	if (ODP_QUEUE_INVALID != ipsec_sa->queue) {
		/*
		 * If there were not active state when we disabled SA,
		 * send the event.
		 */
		if (0 == state)
			_odp_ipsec_status_send(ipsec_sa->queue,
					       ODP_IPSEC_STATUS_SA_DISABLE,
					       0,
					       ipsec_sa->ipsec_sa_hdl);

		return 0;
	}

	while (IPSEC_SA_STATE_DISABLE != state) {
		odp_cpu_pause();
		state = odp_atomic_load_u32(&ipsec_sa->state);
	}

	return 0;
}

int odp_ipsec_sa_destroy(odp_ipsec_sa_t sa)
{
	ipsec_sa_t *ipsec_sa = ipsec_sa_entry_from_hdl(sa);
	int rc = 0;
	uint32_t state = odp_atomic_load_u32(&ipsec_sa->state);

	if (IPSEC_SA_STATE_DISABLE != state) {
		ODP_ERR("Distroying not disabled ipsec_sa: %u\n",
			ipsec_sa->ipsec_sa_idx);
		return -1;
	}

	if (odp_crypto_session_destroy(ipsec_sa->session) < 0) {
		ODP_ERR("Error destroying crypto session for ipsec_sa: %u\n",
			ipsec_sa->ipsec_sa_idx);
		rc = -1;
	}

	ipsec_sa_release(ipsec_sa);

	return rc;
}

void *odp_ipsec_sa_context(odp_ipsec_sa_t sa)
{
	ipsec_sa_t *ipsec_sa = ipsec_sa_entry_from_hdl(sa);

	return ipsec_sa->context;
}

uint64_t odp_ipsec_sa_to_u64(odp_ipsec_sa_t sa)
{
	return _odp_pri(sa);
}

int odp_ipsec_mtu_update(odp_ipsec_sa_t sa, uint32_t mtu)
{
	(void)sa;
	(void)mtu;

	return -1;
}

ipsec_sa_t *_odp_ipsec_sa_lookup(const ipsec_sa_lookup_t *lookup)
{
	(void)lookup;

	int i;
	ipsec_sa_t *ipsec_sa;
	ipsec_sa_t *best = NULL;

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		ipsec_sa = ipsec_sa_entry(i);

		if (ipsec_sa_lock(ipsec_sa) < 0)
			continue;

		if (ODP_IPSEC_LOOKUP_DSTADDR_SPI == ipsec_sa->lookup_mode &&
		    lookup->proto == ipsec_sa->proto &&
		    lookup->spi == ipsec_sa->spi &&
		    !memcmp(lookup->dst_addr, &ipsec_sa->lookup_dst_ip,
			    sizeof(ipsec_sa->lookup_dst_ip))) {
			if (NULL != best)
				_odp_ipsec_sa_unuse(best);
			return ipsec_sa;
		} else if (ODP_IPSEC_LOOKUP_SPI == ipsec_sa->lookup_mode &&
				lookup->proto == ipsec_sa->proto &&
				lookup->spi == ipsec_sa->spi) {
			best = ipsec_sa;
		} else {
			_odp_ipsec_sa_unuse(ipsec_sa);
		}
	}

	return best;
}

int _odp_ipsec_sa_update_stats(ipsec_sa_t *ipsec_sa, uint32_t len,
			       odp_ipsec_op_status_t *status)
{
	uint64_t bytes = odp_atomic_fetch_add_u64(&ipsec_sa->bytes, len) + len;
	uint64_t packets = odp_atomic_fetch_add_u64(&ipsec_sa->packets, 1) + 1;
	int rc = 0;

	if (ipsec_sa->soft_limit_bytes > 0 &&
	    bytes > ipsec_sa->soft_limit_bytes)
		status->error.soft_exp_bytes = 1;

	if (ipsec_sa->soft_limit_packets > 0 &&
	    packets > ipsec_sa->soft_limit_packets)
		status->error.soft_exp_packets = 1;

	if (ipsec_sa->hard_limit_bytes > 0 &&
	    bytes > ipsec_sa->hard_limit_bytes) {
		status->error.hard_exp_bytes = 1;
		rc = -1;
	}
	if (ipsec_sa->hard_limit_packets > 0 &&
	    packets > ipsec_sa->hard_limit_packets) {
		status->error.hard_exp_packets = 1;
		rc = -1;
	}

	return rc;
}
