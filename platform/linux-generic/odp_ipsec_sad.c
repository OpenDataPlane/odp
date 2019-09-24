/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/atomic.h>
#include <odp/api/ipsec.h>
#include <odp/api/random.h>
#include <odp/api/shared_memory.h>

#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_ring_mpmc_internal.h>

#include <odp/api/plat/atomic_inlines.h>
#include <odp/api/plat/cpu_inlines.h>

#include <string.h>

#define IPSEC_SA_STATE_DISABLE	0x40000000
#define IPSEC_SA_STATE_FREE	0xc0000000
#define IPSEC_SA_STATE_RESERVED	0x80000000

/*
 * We do not have global IPv4 ID counter that is accessed for every outbound
 * packet. Instead, we split IPv4 ID space to fixed size blocks that we
 * allocate to threads on demand. When a thread has used its block of IDs,
 * it frees it and allocates a new block. Free blocks are kept in a ring so
 * that the block last freed is the one to be allocated last to maximize
 * the time before IPv4 ID reuse.
 */
#define IPV4_ID_BLOCK_SIZE 64 /* must be power of 2 */
#define IPV4_ID_RING_SIZE (UINT16_MAX / IPV4_ID_BLOCK_SIZE)
#define IPV4_ID_RING_MASK (IPV4_ID_RING_SIZE - 1)

#if IPV4_ID_RING_SIZE <= ODP_THREAD_COUNT_MAX
#warning IPV4_ID_RING_SIZE is too small for the maximum number of threads.
#endif

/*
 * To avoid checking and updating the packet and byte counters in the
 * SA for every packet, we increment the global counters once for several
 * packets. We decrement a preallocated thread-local quota for every
 * packet. When the quota runs out, we get a new quota by incementing the
 * global counter.
 *
 * This improves performance but the looser synchronization between
 * threads makes life time warnings and errors somewhat inaccurate.
 * The warnings and errors may get triggered a bit too early since
 * some threads may still have unused quota when the first thread
 * hits the limit.
 */
#define SA_LIFE_PACKETS_PREALLOC  64
#define SA_LIFE_BYTES_PREALLOC    4000

typedef struct sa_thread_local_s {
	/*
	 * Packets that can be processed in this thread before looking at
	 * the SA-global packet counter and checking hard and soft limits.
	 */
	uint32_t packet_quota;
	/*
	 * Bytes that can be processed in this thread before looking at
	 * at the SA-global byte counter and checking hard and soft limits.
	 */
	uint32_t byte_quota;
	/*
	 * Life time status when this thread last checked the global
	 * counter(s).
	 */
	odp_ipsec_op_status_t lifetime_status;
} sa_thread_local_t;

typedef struct ODP_ALIGNED_CACHE ipsec_thread_local_s {
	sa_thread_local_t sa[ODP_CONFIG_IPSEC_SAS];
	uint16_t first_ipv4_id; /* first ID of current block of IDs */
	uint16_t next_ipv4_id;  /* next ID to be used */
} ipsec_thread_local_t;

typedef struct ipsec_sa_table_t {
	ipsec_sa_t ipsec_sa[ODP_CONFIG_IPSEC_SAS];
	ipsec_thread_local_t per_thread[ODP_THREAD_COUNT_MAX];
	struct ODP_ALIGNED_CACHE {
		ring_mpmc_t ipv4_id_ring;
		uint32_t ODP_ALIGNED_CACHE ipv4_id_data[IPV4_ID_RING_SIZE];
	} hot;
	odp_shm_t shm;
} ipsec_sa_table_t;

static ipsec_sa_table_t *ipsec_sa_tbl;

static inline ipsec_sa_t *ipsec_sa_entry(uint32_t ipsec_sa_idx)
{
	return &ipsec_sa_tbl->ipsec_sa[ipsec_sa_idx];
}

static inline ipsec_sa_t *ipsec_sa_entry_from_hdl(odp_ipsec_sa_t ipsec_sa_hdl)
{
	return ipsec_sa_entry(_odp_typeval(ipsec_sa_hdl) - 1);
}

static inline odp_ipsec_sa_t ipsec_sa_index_to_handle(uint32_t ipsec_sa_idx)
{
	return _odp_cast_scalar(odp_ipsec_sa_t, ipsec_sa_idx + 1);
}

ipsec_sa_t *_odp_ipsec_sa_entry_from_hdl(odp_ipsec_sa_t sa)
{
	ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);
	return ipsec_sa_entry_from_hdl(sa);
}

static inline sa_thread_local_t *ipsec_sa_thread_local(ipsec_sa_t *sa)
{
	return &ipsec_sa_tbl->per_thread[odp_thread_id()].sa[sa->ipsec_sa_idx];
}

static void init_sa_thread_local(ipsec_sa_t *sa)
{
	sa_thread_local_t *sa_tl;
	int n;

	for (n = 0; n < ODP_THREAD_COUNT_MAX; n++) {
		sa_tl = &ipsec_sa_tbl->per_thread[n].sa[sa->ipsec_sa_idx];
		sa_tl->packet_quota = 0;
		sa_tl->byte_quota = 0;
		sa_tl->lifetime_status.all = 0;
	}
}

int _odp_ipsec_sad_init_global(void)
{
	odp_shm_t shm;
	unsigned i;

	shm = odp_shm_reserve("_odp_ipsec_sa_table",
			      sizeof(ipsec_sa_table_t),
			      ODP_CACHE_LINE_SIZE,
			      0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	ipsec_sa_tbl = odp_shm_addr(shm);
	memset(ipsec_sa_tbl, 0, sizeof(ipsec_sa_table_t));
	ipsec_sa_tbl->shm = shm;

	ring_mpmc_init(&ipsec_sa_tbl->hot.ipv4_id_ring);
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		/*
		 * Make the current ID block fully used, forcing allocation
		 * of a fresh block at first use.
		 */
		ipsec_sa_tbl->per_thread[i].first_ipv4_id = 0;
		ipsec_sa_tbl->per_thread[i].next_ipv4_id = IPV4_ID_BLOCK_SIZE;
	}
	/*
	 * Initialize IPv4 ID ring with ID blocks.
	 *
	 * The last ID block is left unused since the ring can hold
	 * only IPV4_ID_RING_SIZE - 1 entries.
	 */
	for (i = 0; i < IPV4_ID_RING_SIZE - 1; i++) {
		uint32_t data = i * IPV4_ID_BLOCK_SIZE;

		ring_mpmc_enq_multi(&ipsec_sa_tbl->hot.ipv4_id_ring,
				    ipsec_sa_tbl->hot.ipv4_id_data,
				    IPV4_ID_RING_MASK,
				    &data,
				    1);
	}

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		ipsec_sa_t *ipsec_sa = ipsec_sa_entry(i);

		ipsec_sa->ipsec_sa_hdl = ipsec_sa_index_to_handle(i);
		ipsec_sa->ipsec_sa_idx = i;
		odp_atomic_init_u32(&ipsec_sa->state, IPSEC_SA_STATE_FREE);
		odp_atomic_init_u64(&ipsec_sa->hot.bytes, 0);
		odp_atomic_init_u64(&ipsec_sa->hot.packets, 0);
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

static ipsec_sa_t *ipsec_sa_reserve(void)
{
	int i;
	ipsec_sa_t *ipsec_sa;

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		uint32_t state = IPSEC_SA_STATE_FREE;

		ipsec_sa = ipsec_sa_entry(i);

		if (odp_atomic_cas_acq_u32(&ipsec_sa->state, &state,
					   IPSEC_SA_STATE_RESERVED))
			return ipsec_sa;
	}

	return NULL;
}

static void ipsec_sa_release(ipsec_sa_t *ipsec_sa)
{
	odp_atomic_store_rel_u32(&ipsec_sa->state, IPSEC_SA_STATE_FREE);
}

/* Mark reserved SA as available now */
static void ipsec_sa_publish(ipsec_sa_t *ipsec_sa)
{
	odp_atomic_store_rel_u32(&ipsec_sa->state, 0);
}

static int ipsec_sa_lock(ipsec_sa_t *ipsec_sa)
{
	int cas = 0;
	uint32_t state = odp_atomic_load_u32(&ipsec_sa->state);

	while (0 == cas) {
		/*
		 * This can be called from lookup path, so we really need this
		 * check. Thanks to the way flags are defined we actually test
		 * that the SA is not DISABLED, FREE or RESERVED using just one
		 * condition.
		 */
		if (state & IPSEC_SA_STATE_FREE)
			return -1;

		cas = odp_atomic_cas_acq_u32(&ipsec_sa->state, &state,
					     state + 1);
	}

	return 0;
}

/* Do not call directly, use _odp_ipsec_sa_unuse */
static odp_bool_t ipsec_sa_unlock(ipsec_sa_t *ipsec_sa)
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
	odp_ipsec_warn_t warn = { .all = 0 };

	ODP_ASSERT(NULL != ipsec_sa);

	queue = ipsec_sa->queue;
	sa = ipsec_sa->ipsec_sa_hdl;

	if (ipsec_sa_unlock(ipsec_sa) && ODP_QUEUE_INVALID != queue)
		_odp_ipsec_status_send(queue,
				       ODP_IPSEC_STATUS_SA_DISABLE,
				       sa, 0, warn);
}

void odp_ipsec_sa_param_init(odp_ipsec_sa_param_t *param)
{
	memset(param, 0, sizeof(odp_ipsec_sa_param_t));
	param->dest_queue = ODP_QUEUE_INVALID;
}

/* Return IV length required for the cipher for IPsec use */
uint32_t _odp_ipsec_cipher_iv_len(odp_cipher_alg_t cipher)
{
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		return 0;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		return 8;
#if ODP_DEPRECATED_API
	case ODP_CIPHER_ALG_AES128_CBC:
#endif
	case ODP_CIPHER_ALG_AES_CBC:
	case ODP_CIPHER_ALG_AES_CTR:
		return 16;
#if ODP_DEPRECATED_API
	case ODP_CIPHER_ALG_AES128_GCM:
#endif
	case ODP_CIPHER_ALG_AES_GCM:
		return 12;
	case ODP_CIPHER_ALG_AES_CCM:
		return 11;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		return 12;
	default:
		return (uint32_t)-1;
	}
}

/* Return digest length required for the cipher for IPsec use */
uint32_t _odp_ipsec_auth_digest_len(odp_auth_alg_t auth)
{
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		return 0;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_MD5_96:
#endif
	case ODP_AUTH_ALG_MD5_HMAC:
	case ODP_AUTH_ALG_SHA1_HMAC:
		return 12;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_SHA256_128:
#endif
	case ODP_AUTH_ALG_SHA256_HMAC:
		return 16;
	case ODP_AUTH_ALG_SHA384_HMAC:
		return 24;
	case ODP_AUTH_ALG_SHA512_HMAC:
		return 32;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		return 12;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_AES128_GCM:
#endif
	case ODP_AUTH_ALG_AES_GCM:
	case ODP_AUTH_ALG_AES_GMAC:
		return 16;
	case ODP_AUTH_ALG_AES_CCM:
		return 16;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		return 16;
	default:
		return (uint32_t)-1;
	}
}

odp_ipsec_sa_t odp_ipsec_sa_create(const odp_ipsec_sa_param_t *param)
{
	ipsec_sa_t *ipsec_sa;
	odp_crypto_session_param_t crypto_param;
	odp_crypto_ses_create_err_t ses_create_rc;
	const odp_crypto_key_t *salt_param = NULL;

	ipsec_sa = ipsec_sa_reserve();
	if (NULL == ipsec_sa) {
		ODP_ERR("No more free SA\n");
		return ODP_IPSEC_SA_INVALID;
	}

	ipsec_sa->proto = param->proto;
	ipsec_sa->spi = param->spi;
	ipsec_sa->context = param->context;
	ipsec_sa->queue = param->dest_queue;
	ipsec_sa->mode = param->mode;
	ipsec_sa->flags = 0;
	if (param->opt.esn) {
		ODP_ERR("ESN is not supported!\n");
		return ODP_IPSEC_SA_INVALID;
	}
	if (ODP_IPSEC_DIR_INBOUND == param->dir) {
		ipsec_sa->lookup_mode = param->inbound.lookup_mode;
		if (ODP_IPSEC_LOOKUP_DSTADDR_SPI == ipsec_sa->lookup_mode) {
			ipsec_sa->in.lookup_ver =
				param->inbound.lookup_param.ip_version;
			if (ODP_IPSEC_IPV4 == ipsec_sa->in.lookup_ver)
				memcpy(&ipsec_sa->in.lookup_dst_ipv4,
				       param->inbound.lookup_param.dst_addr,
				       sizeof(ipsec_sa->in.lookup_dst_ipv4));
			else
				memcpy(&ipsec_sa->in.lookup_dst_ipv6,
				       param->inbound.lookup_param.dst_addr,
				       sizeof(ipsec_sa->in.lookup_dst_ipv6));
		}

		if (param->inbound.antireplay_ws > IPSEC_ANTIREPLAY_WS)
			goto error;
		ipsec_sa->antireplay = (param->inbound.antireplay_ws != 0);
		odp_atomic_init_u64(&ipsec_sa->hot.in.antireplay, 0);
	} else {
		ipsec_sa->lookup_mode = ODP_IPSEC_LOOKUP_DISABLED;
		odp_atomic_store_u64(&ipsec_sa->hot.out.seq, 1);
		ipsec_sa->out.frag_mode = param->outbound.frag_mode;
		ipsec_sa->out.mtu = param->outbound.mtu;
	}
	ipsec_sa->dec_ttl = param->opt.dec_ttl;
	ipsec_sa->copy_dscp = param->opt.copy_dscp;
	ipsec_sa->copy_df = param->opt.copy_df;
	ipsec_sa->copy_flabel = param->opt.copy_flabel;
	ipsec_sa->udp_encap = param->opt.udp_encap;

	odp_atomic_store_u64(&ipsec_sa->hot.bytes, 0);
	odp_atomic_store_u64(&ipsec_sa->hot.packets, 0);
	ipsec_sa->soft_limit_bytes = param->lifetime.soft_limit.bytes;
	ipsec_sa->soft_limit_packets = param->lifetime.soft_limit.packets;
	ipsec_sa->hard_limit_bytes = param->lifetime.hard_limit.bytes;
	ipsec_sa->hard_limit_packets = param->lifetime.hard_limit.packets;

	if (ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode &&
	    ODP_IPSEC_DIR_OUTBOUND == param->dir) {
		if (ODP_IPSEC_TUNNEL_IPV4 == param->outbound.tunnel.type) {
			ipsec_sa->tun_ipv4 = 1;
			memcpy(&ipsec_sa->out.tun_ipv4.src_ip,
			       param->outbound.tunnel.ipv4.src_addr,
			       sizeof(ipsec_sa->out.tun_ipv4.src_ip));
			memcpy(&ipsec_sa->out.tun_ipv4.dst_ip,
			       param->outbound.tunnel.ipv4.dst_addr,
			       sizeof(ipsec_sa->out.tun_ipv4.dst_ip));
			ipsec_sa->out.tun_ipv4.param.src_addr =
				&ipsec_sa->out.tun_ipv4.src_ip;
			ipsec_sa->out.tun_ipv4.param.dst_addr =
				&ipsec_sa->out.tun_ipv4.dst_ip;
			ipsec_sa->out.tun_ipv4.param.ttl =
				param->outbound.tunnel.ipv4.ttl;
			ipsec_sa->out.tun_ipv4.param.dscp =
				param->outbound.tunnel.ipv4.dscp;
			ipsec_sa->out.tun_ipv4.param.df =
				param->outbound.tunnel.ipv4.df;
		} else {
			ipsec_sa->tun_ipv4 = 0;
			memcpy(&ipsec_sa->out.tun_ipv6.src_ip,
			       param->outbound.tunnel.ipv6.src_addr,
			       sizeof(ipsec_sa->out.tun_ipv6.src_ip));
			memcpy(&ipsec_sa->out.tun_ipv6.dst_ip,
			       param->outbound.tunnel.ipv6.dst_addr,
			       sizeof(ipsec_sa->out.tun_ipv6.dst_ip));
			ipsec_sa->out.tun_ipv4.param.src_addr =
				&ipsec_sa->out.tun_ipv6.src_ip;
			ipsec_sa->out.tun_ipv4.param.dst_addr =
				&ipsec_sa->out.tun_ipv6.dst_ip;
			ipsec_sa->out.tun_ipv6.param.hlimit =
				param->outbound.tunnel.ipv6.hlimit;
			ipsec_sa->out.tun_ipv6.param.dscp =
				param->outbound.tunnel.ipv6.dscp;
			ipsec_sa->out.tun_ipv6.param.flabel =
				param->outbound.tunnel.ipv6.flabel;
		}
	}

	odp_crypto_session_param_init(&crypto_param);

	/* Setup parameters and call crypto library to create session */
	crypto_param.op = (ODP_IPSEC_DIR_INBOUND == param->dir) ?
			ODP_CRYPTO_OP_DECODE :
			ODP_CRYPTO_OP_ENCODE;
	crypto_param.auth_cipher_text = 1;

	crypto_param.op_mode   = ODP_CRYPTO_SYNC;
	crypto_param.compl_queue = ODP_QUEUE_INVALID;
	crypto_param.output_pool = ODP_POOL_INVALID;

	crypto_param.cipher_alg = param->crypto.cipher_alg;
	crypto_param.cipher_key = param->crypto.cipher_key;
	crypto_param.auth_alg = param->crypto.auth_alg;
	crypto_param.auth_key = param->crypto.auth_key;

	crypto_param.cipher_iv.length =
		_odp_ipsec_cipher_iv_len(crypto_param.cipher_alg);

	crypto_param.auth_digest_len =
		_odp_ipsec_auth_digest_len(crypto_param.auth_alg);

	if ((uint32_t)-1 == crypto_param.cipher_iv.length ||
	    (uint32_t)-1 == crypto_param.auth_digest_len)
		goto error;

	ipsec_sa->salt_length = 0;

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
#endif
	case ODP_CIPHER_ALG_AES_CBC:
		ipsec_sa->esp_iv_len = 16;
		ipsec_sa->esp_block_len = 16;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		ipsec_sa->use_counter_iv = 1;
		ipsec_sa->aes_ctr_iv = 1;
		ipsec_sa->esp_iv_len = 8;
		ipsec_sa->esp_block_len = 1;
		/* 4 byte nonse */
		ipsec_sa->salt_length = 4;
		salt_param = &param->crypto.cipher_key_extra;
		break;
#if ODP_DEPRECATED_API
	case ODP_CIPHER_ALG_AES128_GCM:
#endif
	case ODP_CIPHER_ALG_AES_GCM:
		ipsec_sa->use_counter_iv = 1;
		ipsec_sa->esp_iv_len = 8;
		ipsec_sa->esp_block_len = 16;
		ipsec_sa->salt_length = 4;
		salt_param = &param->crypto.cipher_key_extra;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		ipsec_sa->use_counter_iv = 1;
		ipsec_sa->esp_iv_len = 8;
		ipsec_sa->esp_block_len = 16;
		ipsec_sa->salt_length = 3;
		salt_param = &param->crypto.cipher_key_extra;
		break;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		ipsec_sa->use_counter_iv = 1;
		ipsec_sa->esp_iv_len = 8;
		ipsec_sa->esp_block_len = 1;
		ipsec_sa->salt_length = 4;
		salt_param = &param->crypto.cipher_key_extra;
		break;
	default:
		goto error;
	}

	switch (crypto_param.auth_alg) {
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_AES128_GCM:
#endif
	case ODP_AUTH_ALG_AES_GCM:
		crypto_param.auth_aad_len = sizeof(ipsec_aad_t);
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (ODP_CIPHER_ALG_NULL != crypto_param.cipher_alg)
			goto error;
		ipsec_sa->use_counter_iv = 1;
		ipsec_sa->esp_iv_len = 8;
		ipsec_sa->esp_block_len = 16;
		crypto_param.auth_iv.length = 12;
		ipsec_sa->salt_length = 4;
		salt_param = &param->crypto.auth_key_extra;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		crypto_param.auth_aad_len = sizeof(ipsec_aad_t);
		break;
	default:
		break;
	}

	ipsec_sa->icv_len = crypto_param.auth_digest_len;

	if (ipsec_sa->salt_length) {
		if (ipsec_sa->salt_length > IPSEC_MAX_SALT_LEN) {
			ODP_ERR("IPSEC_MAX_SALT_LEN too small\n");
			goto error;
		}

		if (ipsec_sa->salt_length != salt_param->length) {
			ODP_ERR("Bad extra keying material length: %i\n",
				salt_param->length);
			goto error;
		}

		memcpy(ipsec_sa->salt, salt_param->data, ipsec_sa->salt_length);
	}

	if (odp_crypto_session_create(&crypto_param, &ipsec_sa->session,
				      &ses_create_rc))
		goto error;

	init_sa_thread_local(ipsec_sa);

	ipsec_sa_publish(ipsec_sa);

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
		odp_ipsec_warn_t warn = { .all = 0 };

		/*
		 * If there were not active state when we disabled SA,
		 * send the event.
		 */
		if (0 == state)
			_odp_ipsec_status_send(ipsec_sa->queue,
					       ODP_IPSEC_STATUS_SA_DISABLE,
					       ipsec_sa->ipsec_sa_hdl,
					       0, warn);

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

int odp_ipsec_sa_mtu_update(odp_ipsec_sa_t sa, uint32_t mtu)
{
	ipsec_sa_t *ipsec_sa;

	ipsec_sa = _odp_ipsec_sa_use(sa);
	ODP_ASSERT(NULL != ipsec_sa);

	ipsec_sa->out.mtu = mtu;

	_odp_ipsec_sa_unuse(ipsec_sa);

	return 0;
}

ipsec_sa_t *_odp_ipsec_sa_lookup(const ipsec_sa_lookup_t *lookup)
{
	int i;
	ipsec_sa_t *best = NULL;

	for (i = 0; i < ODP_CONFIG_IPSEC_SAS; i++) {
		ipsec_sa_t *ipsec_sa = ipsec_sa_entry(i);

		if (ipsec_sa_lock(ipsec_sa) < 0)
			continue;

		if (ODP_IPSEC_LOOKUP_DSTADDR_SPI == ipsec_sa->lookup_mode &&
		    lookup->proto == ipsec_sa->proto &&
		    lookup->spi == ipsec_sa->spi &&
		    lookup->ver == ipsec_sa->in.lookup_ver &&
		    !memcmp(lookup->dst_addr, &ipsec_sa->in.lookup_dst_ipv4,
			    lookup->ver == ODP_IPSEC_IPV4 ?
				    _ODP_IPV4ADDR_LEN :
				    _ODP_IPV6ADDR_LEN)) {
			if (NULL != best)
				_odp_ipsec_sa_unuse(best);
			return ipsec_sa;
		} else if (NULL == best &&
			   ODP_IPSEC_LOOKUP_SPI == ipsec_sa->lookup_mode &&
			   lookup->proto == ipsec_sa->proto &&
			   lookup->spi == ipsec_sa->spi) {
			best = ipsec_sa;
		} else {
			_odp_ipsec_sa_unuse(ipsec_sa);
		}
	}

	return best;
}

int _odp_ipsec_sa_stats_precheck(ipsec_sa_t *ipsec_sa,
				 odp_ipsec_op_status_t *status)
{
	int rc = 0;
	sa_thread_local_t *sa_tl = ipsec_sa_thread_local(ipsec_sa);

	if (sa_tl->lifetime_status.error.hard_exp_packets ||
	    sa_tl->lifetime_status.error.hard_exp_bytes) {
		status->all |= sa_tl->lifetime_status.all;
		rc = -1;
	}

	return rc;
}

int _odp_ipsec_sa_stats_update(ipsec_sa_t *ipsec_sa, uint32_t len,
			       odp_ipsec_op_status_t *status)
{
	sa_thread_local_t *sa_tl = ipsec_sa_thread_local(ipsec_sa);
	uint64_t packets, bytes;

	if (odp_unlikely(sa_tl->packet_quota == 0)) {
		packets = odp_atomic_fetch_add_u64(&ipsec_sa->hot.packets,
						   SA_LIFE_PACKETS_PREALLOC);
		packets += SA_LIFE_PACKETS_PREALLOC;
		sa_tl->packet_quota += SA_LIFE_PACKETS_PREALLOC;

		if (ipsec_sa->soft_limit_packets > 0 &&
		    packets >= ipsec_sa->soft_limit_packets)
			sa_tl->lifetime_status.warn.soft_exp_packets = 1;

		if (ipsec_sa->hard_limit_packets > 0 &&
		    packets >= ipsec_sa->hard_limit_packets)
			sa_tl->lifetime_status.error.hard_exp_packets = 1;
	}
	sa_tl->packet_quota--;

	if (odp_unlikely(sa_tl->byte_quota < len)) {
		bytes = odp_atomic_fetch_add_u64(&ipsec_sa->hot.bytes,
						 len + SA_LIFE_BYTES_PREALLOC);
		bytes += len + SA_LIFE_BYTES_PREALLOC;
		sa_tl->byte_quota += len + SA_LIFE_BYTES_PREALLOC;

		if (ipsec_sa->soft_limit_bytes > 0 &&
		    bytes >= ipsec_sa->soft_limit_bytes)
			sa_tl->lifetime_status.warn.soft_exp_bytes = 1;

		if (ipsec_sa->hard_limit_bytes > 0 &&
		    bytes >= ipsec_sa->hard_limit_bytes)
			sa_tl->lifetime_status.error.hard_exp_bytes = 1;
	}
	sa_tl->byte_quota -= len;

	status->all |= sa_tl->lifetime_status.all;

	if (sa_tl->lifetime_status.error.hard_exp_packets ||
	    sa_tl->lifetime_status.error.hard_exp_bytes)
		return -1;
	return 0;
}

int _odp_ipsec_sa_replay_precheck(ipsec_sa_t *ipsec_sa, uint32_t seq,
				  odp_ipsec_op_status_t *status)
{
	/* Try to be as quick as possible, we will discard packets later */
	if (ipsec_sa->antireplay &&
	    seq + IPSEC_ANTIREPLAY_WS <=
	    (odp_atomic_load_u64(&ipsec_sa->hot.in.antireplay) & 0xffffffff)) {
		status->error.antireplay = 1;
		return -1;
	}

	return 0;
}

int _odp_ipsec_sa_replay_update(ipsec_sa_t *ipsec_sa, uint32_t seq,
				odp_ipsec_op_status_t *status)
{
	int cas = 0;
	uint64_t state, new_state;

	if (!ipsec_sa->antireplay)
		return 0;

	state = odp_atomic_load_u64(&ipsec_sa->hot.in.antireplay);

	while (0 == cas) {
		uint32_t max_seq = state & 0xffffffff;
		uint32_t mask = state >> 32;

		if (seq + IPSEC_ANTIREPLAY_WS <= max_seq) {
			status->error.antireplay = 1;
			return -1;
		} else if (seq >= max_seq + IPSEC_ANTIREPLAY_WS) {
			mask = 1;
			max_seq = seq;
		} else if (seq > max_seq) {
			mask <<= seq - max_seq;
			mask |= 1;
			max_seq = seq;
		} else if (mask & (1U << (max_seq - seq))) {
			status->error.antireplay = 1;
			return -1;
		} else {
			mask |= (1U << (max_seq - seq));
		}

		new_state = (((uint64_t)mask) << 32) | max_seq;

		cas = odp_atomic_cas_acq_rel_u64(&ipsec_sa->hot.in.antireplay,
						 &state, new_state);
	}

	return 0;
}

uint16_t _odp_ipsec_sa_alloc_ipv4_id(ipsec_sa_t *ipsec_sa)
{
	(void) ipsec_sa;
	ipsec_thread_local_t *tl = &ipsec_sa_tbl->per_thread[odp_thread_id()];
	uint32_t data;

	if (odp_unlikely(tl->next_ipv4_id ==
			 tl->first_ipv4_id + IPV4_ID_BLOCK_SIZE)) {
		/* Return used ID block to the ring */
		data = tl->first_ipv4_id;
		ring_mpmc_enq_multi(&ipsec_sa_tbl->hot.ipv4_id_ring,
				    ipsec_sa_tbl->hot.ipv4_id_data,
				    IPV4_ID_RING_MASK,
				    &data,
				    1);
		/* Get new ID block */
		ring_mpmc_deq_multi(&ipsec_sa_tbl->hot.ipv4_id_ring,
				    ipsec_sa_tbl->hot.ipv4_id_data,
				    IPV4_ID_RING_MASK,
				    &data,
				    1);
		tl->first_ipv4_id = data;
		tl->next_ipv4_id = data;
	}

	/* No need to convert to BE: ID just should not be duplicated */
	return tl->next_ipv4_id++;
}
