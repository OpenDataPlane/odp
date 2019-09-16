/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

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
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	ipsec_cache = odp_shm_addr(shm);

	if (ipsec_cache == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(ipsec_cache, 0, sizeof(*ipsec_cache));

	for (i = 0; i < MAX_DB; i++)
		ipsec_cache->array[i].ipsec_sa = ODP_IPSEC_SA_INVALID;
}

int create_ipsec_cache_entry(sa_db_entry_t *cipher_sa,
			     sa_db_entry_t *auth_sa,
			     tun_db_entry_t *tun,
			     odp_bool_t in,
			     odp_queue_t completionq)
{
	odp_ipsec_sa_param_t param;
	ipsec_cache_entry_t *entry;
	odp_ipsec_sa_t ipsec_sa;
	uint32_t tun_src_ip, tun_dst_ip;
	sa_mode_t mode = IPSEC_SA_MODE_TRANSPORT;

	/* Verify we have a good entry */
	entry = &ipsec_cache->array[ipsec_cache->index];
	if (MAX_DB <= ipsec_cache->index)
		return -1;

	odp_ipsec_sa_param_init(&param);
	param.dir = in ? ODP_IPSEC_DIR_INBOUND : ODP_IPSEC_DIR_OUTBOUND;
	param.inbound.lookup_mode = in ? ODP_IPSEC_LOOKUP_SPI :
		ODP_IPSEC_LOOKUP_DISABLED;
	param.proto = cipher_sa ? ODP_IPSEC_ESP : ODP_IPSEC_AH;

	param.mode = tun ? ODP_IPSEC_MODE_TUNNEL : ODP_IPSEC_MODE_TRANSPORT;

	param.dest_queue = completionq;

	/* Cipher */
	if (cipher_sa) {
		param.crypto.cipher_alg  = cipher_sa->alg.u.cipher;
		param.crypto.cipher_key.data  = cipher_sa->key.data;
		param.crypto.cipher_key.length  = cipher_sa->key.length;
		param.spi = cipher_sa->spi;
	} else {
		param.crypto.cipher_alg = ODP_CIPHER_ALG_NULL;
	}

	/* Auth */
	if (auth_sa) {
		param.crypto.auth_alg = auth_sa->alg.u.auth;
		param.crypto.auth_key.data = auth_sa->key.data;
		param.crypto.auth_key.length = auth_sa->key.length;
		param.spi = auth_sa->spi;
	} else {
		param.crypto.auth_alg = ODP_AUTH_ALG_NULL;
	}

	if (ODP_IPSEC_MODE_TUNNEL == param.mode) {
		tun_src_ip = odp_cpu_to_be_32(tun->tun_src_ip);
		tun_dst_ip = odp_cpu_to_be_32(tun->tun_dst_ip);
		param.outbound.tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
		param.outbound.tunnel.ipv4.src_addr = &tun_src_ip;
		param.outbound.tunnel.ipv4.dst_addr = &tun_dst_ip;
	}

	ipsec_sa = odp_ipsec_sa_create(&param);
	if (ODP_IPSEC_SA_INVALID == ipsec_sa) {
		ODPH_ERR("Error: SA creation failed\n");
		exit(EXIT_FAILURE);
	}

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
	}
	entry->mode = mode;

	/* Add entry to the appropriate list */
	ipsec_cache->index++;
	if (in) {
		entry->next = ipsec_cache->in_list;
		ipsec_cache->in_list = entry;
	} else {
		entry->next = ipsec_cache->out_list;
		ipsec_cache->out_list = entry;
	}

	entry->ipsec_sa = ipsec_sa;

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
		if (entry->ipsec_sa != ODP_IPSEC_SA_INVALID) {
			ret += odp_ipsec_sa_disable(entry->ipsec_sa);
			ret += odp_ipsec_sa_destroy(entry->ipsec_sa);
		}
	}

	return ret;
}
