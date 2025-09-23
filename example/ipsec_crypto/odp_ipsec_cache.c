/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <stdlib.h>
#include <string.h>

#include <odp_api.h>

#include <odp/helper/ipsec.h>

#include <odp_ipsec_cache.h>

/** Global pointer to ipsec_cache db */
ipsec_cache_t *ipsec_cache;

void init_ipsec_cache(void)
{
	odp_shm_t shm;
	int i;

	shm = odp_shm_reserve("shm_ipsec_cache",
			      sizeof(ipsec_cache_t),
			      ODP_CACHE_LINE_SIZE,
			      0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	ipsec_cache = odp_shm_addr(shm);

	if (ipsec_cache == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(ipsec_cache, 0, sizeof(*ipsec_cache));

	for (i = 0; i < MAX_DB; i++)
		ipsec_cache->array[i].state.session =
		ODP_CRYPTO_SESSION_INVALID;
}

int create_ipsec_cache_entry(sa_db_entry_t *cipher_sa,
			     sa_db_entry_t *auth_sa,
			     tun_db_entry_t *tun,
			     crypto_api_mode_e api_mode,
			     odp_bool_t in,
			     odp_queue_t completionq)
{
	odp_crypto_session_param_t params;
	ipsec_cache_entry_t *entry;
	odp_crypto_ses_create_err_t ses_create_rc;
	odp_crypto_session_t session;
	sa_mode_t mode = IPSEC_SA_MODE_TRANSPORT;

	/* Verify we have a good entry */
	entry = &ipsec_cache->array[ipsec_cache->index];
	if (MAX_DB <= ipsec_cache->index)
		return -1;

	/* Verify SA mode match in case of cipher&auth */
	if (cipher_sa && auth_sa &&
	    (cipher_sa->mode != auth_sa->mode))
		return -1;

	odp_crypto_session_param_init(&params);

	/* Setup parameters and call crypto library to create session */
	params.op = (in) ? ODP_CRYPTO_OP_DECODE : ODP_CRYPTO_OP_ENCODE;
	params.op_type = ODP_CRYPTO_OP_TYPE_BASIC;
	params.auth_cipher_text = TRUE;
	params.output_pool = ODP_POOL_INVALID;
	if (CRYPTO_API_SYNC == api_mode) {
		params.op_mode = ODP_CRYPTO_SYNC;
		params.compl_queue = ODP_QUEUE_INVALID;
		entry->async = FALSE;
	} else {
		params.op_mode = ODP_CRYPTO_ASYNC;
		params.compl_queue = completionq;
		entry->async = TRUE;
	}

	entry->sa_flags = 0;

	/* Cipher */
	if (cipher_sa) {
		params.cipher_alg  = cipher_sa->alg.u.cipher;
		params.cipher_key.data  = cipher_sa->key.data;
		params.cipher_key.length  = cipher_sa->key.length;
		params.cipher_iv_len = cipher_sa->iv_len;
		mode = cipher_sa->mode;
		if (cipher_sa->flags & BIT_MODE_CIPHER)
			entry->sa_flags |= BIT_MODE_CIPHER;
	} else {
		params.cipher_alg = ODP_CIPHER_ALG_NULL;
		params.cipher_iv_len = 0;
	}

	/* Auth */
	if (auth_sa) {
		params.auth_alg = auth_sa->alg.u.auth;
		params.auth_key.data = auth_sa->key.data;
		params.auth_key.length = auth_sa->key.length;
		params.auth_digest_len = auth_sa->icv_len;
		mode = auth_sa->mode;
		params.hash_result_in_auth_range = true;
		if (auth_sa->flags & BIT_MODE_AUTH)
			entry->sa_flags |= BIT_MODE_AUTH;
	} else {
		params.auth_alg = ODP_AUTH_ALG_NULL;
	}

	/* Synchronous session create for now */
	if (odp_crypto_session_create(&params, &session, &ses_create_rc))
		return -1;
	if (ODP_CRYPTO_SES_ERR_NONE != ses_create_rc)
		return -1;

	/* Copy remainder */
	if (cipher_sa) {
		entry->src_ip = cipher_sa->src_ip;
		entry->dst_ip = cipher_sa->dst_ip;
		entry->esp.alg = cipher_sa->alg.u.cipher;
		entry->esp.spi = cipher_sa->spi;
		entry->esp.block_len = cipher_sa->block_len;
		entry->esp.iv_len = cipher_sa->iv_len;
		memcpy(&entry->esp.key, &cipher_sa->key, sizeof(ipsec_key_t));
	}
	if (auth_sa) {
		entry->src_ip = auth_sa->src_ip;
		entry->dst_ip = auth_sa->dst_ip;
		entry->ah.alg = auth_sa->alg.u.auth;
		entry->ah.spi = auth_sa->spi;
		entry->ah.icv_len = auth_sa->icv_len;
		memcpy(&entry->ah.key, &auth_sa->key, sizeof(ipsec_key_t));
	}

	if (tun) {
		entry->tun_src_ip = tun->tun_src_ip;
		entry->tun_dst_ip = tun->tun_dst_ip;
		mode = IPSEC_SA_MODE_TUNNEL;

		int ret;

		if (!in) {
			/* init tun hdr id */
			ret = odp_random_data((uint8_t *)
					      &entry->state.tun_hdr_id,
					      sizeof(entry->state.tun_hdr_id),
					      1);
			if (ret != sizeof(entry->state.tun_hdr_id))
				return -1;
		}
	}
	entry->mode = mode;

	/* Initialize state */
	entry->state.esp_seq = 0;
	entry->state.ah_seq = 0;
	entry->state.session = session;

	/* Add entry to the appropriate list */
	ipsec_cache->index++;
	if (in) {
		entry->next = ipsec_cache->in_list;
		ipsec_cache->in_list = entry;
	} else {
		entry->next = ipsec_cache->out_list;
		ipsec_cache->out_list = entry;
	}

	return 0;
}

ipsec_cache_entry_t *find_ipsec_cache_entry_in(uint32_t src_ip,
					       uint32_t dst_ip,
					       odph_ahhdr_t *ah,
					       odph_esphdr_t *esp)
{
	ipsec_cache_entry_t *entry = ipsec_cache->in_list;

	/* Look for a hit */
	for (; NULL != entry; entry = entry->next) {
		if ((entry->src_ip != src_ip) || (entry->dst_ip != dst_ip))
			if ((entry->tun_src_ip != src_ip) ||
			    (entry->tun_dst_ip != dst_ip))
				continue;
		if (ah &&
		    ((!entry->ah.alg) ||
		     (entry->ah.spi != odp_be_to_cpu_32(ah->spi))))
			continue;
		if (esp &&
		    ((!entry->esp.alg) ||
		     (entry->esp.spi != odp_be_to_cpu_32(esp->spi))))
			continue;
		break;
	}

	return entry;
}

ipsec_cache_entry_t *find_ipsec_cache_entry_out(uint32_t src_ip,
						uint32_t dst_ip,
						uint8_t proto ODP_UNUSED)
{
	ipsec_cache_entry_t *entry = ipsec_cache->out_list;

	/* Look for a hit */
	for (; NULL != entry; entry = entry->next) {
		if ((entry->src_ip == src_ip) && (entry->dst_ip == dst_ip))
			break;
	}
	return entry;
}

int destroy_ipsec_cache(void)
{
	ipsec_cache_entry_t *entry;
	int i;
	int ret = 0;

	for (i = 0; i < MAX_DB; i++) {
		entry = &ipsec_cache->array[i];
		if (entry->state.session != ODP_CRYPTO_SESSION_INVALID)
			ret += odp_crypto_session_destroy(entry->state.session);
	}

	return ret;
}
