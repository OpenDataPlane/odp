/*
 * Copyright (c) 2017 NXP. All rights reserved.
 */
/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <odp.h>
#include <odp/helper/odph_api.h>

#include <odp_ipsec_offload_cache.h>

/** Global pointer to ipsec_cache db */
ipsec_cache_t *ipsec_cache;

#define IPDEFTTL 64

void init_ipsec_cache(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("shm_ipsec_cache",
			      sizeof(ipsec_cache_t),
			      ODP_CACHE_LINE_SIZE,
			      0);

	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Error: shared mem reserve failed.\n");

	ipsec_cache = odp_shm_addr(shm);

	if (ipsec_cache == NULL)
		ODPH_ABORT("Error: shared mem alloc failed.\n");
	memset(ipsec_cache, 0, sizeof(*ipsec_cache));
}

int create_ipsec_cache_entry(sa_db_entry_t *cipher_sa,
			     sa_db_entry_t *auth_sa,
			     tun_db_entry_t *tun,
			     odp_bool_t in,
			     odp_queue_t completionq)
{
	odp_ipsec_sa_param_t sa_params;
	ipsec_cache_entry_t *entry;
	odp_ipsec_sa_t sa;
	uint32_t src_ip, dst_ip;

	odp_ipsec_sa_param_init(&sa_params);

	/* Verify we have a good entry */
	entry = &ipsec_cache->array[ipsec_cache->index];
	if (MAX_DB <= ipsec_cache->index)
		return -1;

	/* Verify SA mode match in case of cipher&auth */
	if (!tun) {
		printf("\n TRANSPORT MODE not supported");
		return -1;
	}

	/* Setup parameters and call ipsec library to create sa */
	if (in) {
		sa_params.dir = ODP_IPSEC_DIR_INBOUND;
		sa_params.inbound.lookup_mode = ODP_IPSEC_LOOKUP_SPI;
	} else {
		sa_params.dir = ODP_IPSEC_DIR_OUTBOUND;

		src_ip = odp_cpu_to_be_32(tun->tun_src_ip);
		dst_ip = odp_cpu_to_be_32(tun->tun_dst_ip);
		sa_params.outbound.tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
		sa_params.outbound.tunnel.ipv4.src_addr = &src_ip;
		sa_params.outbound.tunnel.ipv4.dst_addr = &dst_ip;
		sa_params.outbound.tunnel.ipv4.ttl = IPDEFTTL;
		sa_params.outbound.tunnel.ipv4.dscp = 0;
		sa_params.outbound.tunnel.ipv4.df = 1;
	}

	sa_params.dest_queue = completionq;
	sa_params.mode = ODP_IPSEC_MODE_TUNNEL;

	/* Cipher */
	if (cipher_sa) {
		sa_params.crypto.cipher_alg  = cipher_sa->alg.u.cipher;
		sa_params.crypto.cipher_key.data  = cipher_sa->key.data;
		sa_params.crypto.cipher_key.length  = cipher_sa->key.length;
		sa_params.spi = cipher_sa->spi;
	} else {
		sa_params.crypto.cipher_alg = ODP_CIPHER_ALG_NULL;
	}

	/* Auth */
	if (auth_sa) {
		sa_params.crypto.auth_alg = auth_sa->alg.u.auth;
		sa_params.crypto.auth_key.data = auth_sa->key.data;
		sa_params.crypto.auth_key.length = auth_sa->key.length;
	} else {
		sa_params.crypto.auth_alg = ODP_AUTH_ALG_NULL;
	}

	sa = odp_ipsec_sa_create(&sa_params);
	if (sa == ODP_IPSEC_SA_INVALID)
		return -1;

	/* Copy selector IPs in cache entry*/
	if (cipher_sa) {
		entry->src_ip = cipher_sa->src_ip;
		entry->dst_ip = cipher_sa->dst_ip;
	} else if (auth_sa) {
		entry->src_ip = auth_sa->src_ip;
		entry->dst_ip = auth_sa->dst_ip;
	}

	/* Initialize state */
	entry->sa = sa;

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

ipsec_cache_entry_t *find_ipsec_cache_entry_out(uint32_t src_ip,
						uint32_t dst_ip)
{
	ipsec_cache_entry_t *entry = ipsec_cache->out_list;

	/* Look for a hit */
	for (; NULL != entry; entry = entry->next) {
		if ((entry->src_ip == src_ip) && (entry->dst_ip == dst_ip))
			break;
	}
	return entry;
}
