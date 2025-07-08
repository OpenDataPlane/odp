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
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/thread_inlines.h>
#include <odp_macros_internal.h>
#include <odp_packet_internal.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp_global_data.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>

#include <odp_crypto_internal.h>

#include <string.h>
#include <stdlib.h>

#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(OPENSSL_NO_POLY1305)
#define _ODP_HAVE_CHACHA20_POLY1305 1
#else
#define _ODP_HAVE_CHACHA20_POLY1305 0
#endif

/* Ignore warnings about APIs deprecated in OpenSSL 3.0 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#define MAX_SESSIONS 4000
#define AES_BLOCK_SIZE 16
#define AES_KEY_LENGTH 16

/*
 * Cipher algorithm capabilities
 *
 * Keep sorted: first by key length, then by IV length
 */
static const odp_crypto_cipher_capability_t cipher_capa_null[] = {
{.key_len = 0, .iv_len = 0, .bit_mode = 1} };

static const odp_crypto_cipher_capability_t cipher_capa_trides_cbc[] = {
{.key_len = 24, .iv_len = 8} };

static const odp_crypto_cipher_capability_t cipher_capa_trides_ecb[] = {
{.key_len = 24} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_cbc[] = {
{.key_len = 16, .iv_len = 16},
{.key_len = 24, .iv_len = 16},
{.key_len = 32, .iv_len = 16} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_ctr[] = {
{.key_len = 16, .iv_len = 16},
{.key_len = 24, .iv_len = 16},
{.key_len = 32, .iv_len = 16} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_ecb[] = {
{.key_len = 16},
{.key_len = 24},
{.key_len = 32} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_cfb128[] = {
{.key_len = 16, .iv_len = 16},
{.key_len = 24, .iv_len = 16},
{.key_len = 32, .iv_len = 16} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_xts[] = {
{.key_len = 32, .iv_len = 16},
{.key_len = 64, .iv_len = 16} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_gcm[] = {
{.key_len = 16, .iv_len = 12},
{.key_len = 24, .iv_len = 12},
{.key_len = 32, .iv_len = 12} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_ccm[] = {
{.key_len = 16, .iv_len = 11},
{.key_len = 16, .iv_len = 13},
{.key_len = 24, .iv_len = 11},
{.key_len = 24, .iv_len = 13},
{.key_len = 32, .iv_len = 11},
{.key_len = 32, .iv_len = 13} };

#if _ODP_HAVE_CHACHA20_POLY1305
static const odp_crypto_cipher_capability_t cipher_capa_chacha20_poly1305[] = {
{.key_len = 32, .iv_len = 12} };
#endif

static const odp_crypto_cipher_capability_t cipher_capa_aes_eea2[] = {
{.key_len = 16, .iv_len = 16, .bit_mode = 1} };

/*
 * Authentication algorithm capabilities
 *
 * Keep sorted: first by digest length, then by key length
 */
static const odp_crypto_auth_capability_t auth_capa_null[] = {
{.digest_len = 0, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0}, .bit_mode = 1} };

static const odp_crypto_auth_capability_t auth_capa_md5_hmac[] = {
{.digest_len = 12, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 16, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha1_hmac[] = {
{.digest_len = 12, .key_len = 20, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 20, .key_len = 20, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha224_hmac[] = {
{.digest_len = 28, .key_len = 28, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha256_hmac[] = {
{.digest_len = 16, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 32, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha384_hmac[] = {
{.digest_len = 24, .key_len = 48, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 48, .key_len = 48, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha512_hmac[] = {
{.digest_len = 32, .key_len = 64, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 64, .key_len = 64, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_aes_xcbc[] = {
{.digest_len = 12, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 16, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_aes_gcm[] = {
{.digest_len = 16, .key_len = 0, .aad_len = {.min = 8, .max = 12, .inc = 4} } };

static const odp_crypto_auth_capability_t auth_capa_aes_ccm[] = {
{.digest_len = 8, .key_len = 0, .aad_len = {.min = 8, .max = 12, .inc = 4} } };

static const odp_crypto_auth_capability_t auth_capa_aes_gmac[] = {
{.digest_len = 16, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 12 },
{.digest_len = 16, .key_len = 24, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 12 },
{.digest_len = 16, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 12 } };

static const odp_crypto_auth_capability_t auth_capa_aes_cmac[] = {
{.digest_len = 12, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 12, .key_len = 24, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 12, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 16, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 16, .key_len = 24, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 16, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

#if _ODP_HAVE_CHACHA20_POLY1305
static const odp_crypto_auth_capability_t auth_capa_chacha20_poly1305[] = {
{.digest_len = 16, .key_len = 0, .aad_len = {.min = 8, .max = 12, .inc = 4} } };
#endif

static const odp_crypto_auth_capability_t auth_capa_aes_eia2[] = {
{.digest_len = 4, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0},
	.iv_len = 8} };

static const odp_crypto_auth_capability_t auth_capa_md5[] = {
{.digest_len = 16, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha1[] = {
{.digest_len = 20, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha224[] = {
{.digest_len = 28, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha256[] = {
{.digest_len = 32, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha384[] = {
{.digest_len = 48, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha512[] = {
{.digest_len = 64, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

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

	odp_bool_t do_cipher_first;
	uint8_t cipher_range_in_bits : 1;
	uint8_t auth_range_in_bits : 1;
	uint8_t auth_range_used : 1;
	uint8_t null_crypto_enable : 1;

	struct {
		uint8_t key_data[EVP_MAX_KEY_LENGTH];
		const EVP_CIPHER *evp_cipher;
		crypto_func_t func;
		crypto_init_func_t init;
	} cipher;

	struct {
		uint8_t  key[EVP_MAX_KEY_LENGTH];
		union {
			const EVP_MD *evp_md;
			const EVP_CIPHER *evp_cipher;
		};
		crypto_func_t func;
		crypto_init_func_t init;
	} auth;

	unsigned idx;
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

typedef struct crypto_local_t {
	EVP_MD_CTX *md_ctx[MAX_SESSIONS];
	HMAC_CTX *hmac_ctx[MAX_SESSIONS];
	CMAC_CTX *cmac_ctx[MAX_SESSIONS];
	EVP_CIPHER_CTX *cipher_ctx[MAX_SESSIONS];
	EVP_CIPHER_CTX *mac_cipher_ctx[MAX_SESSIONS];
	uint8_t *ctx_valid;
} crypto_local_t;

static __thread crypto_local_t local;

static inline void crypto_init(odp_crypto_generic_session_t *session)
{
	if (local.ctx_valid[session->idx])
		return;

	session->cipher.init(session);
	session->auth.init(session);

	local.ctx_valid[session->idx] = 1;
}

static
odp_crypto_generic_session_t *alloc_session(void)
{
	odp_crypto_generic_session_t *session = NULL;
	unsigned i;

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

static odp_crypto_alg_err_t
null_crypto_routine(odp_packet_t pkt ODP_UNUSED,
		    const odp_crypto_packet_op_param_t *param ODP_UNUSED,
		    odp_crypto_generic_session_t *session ODP_UNUSED)
{
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static void
null_crypto_init_routine(odp_crypto_generic_session_t *session)
{
	(void)session;
}

/* Mimic new OpenSSL 1.1.y API */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = malloc(sizeof(*ctx));

	HMAC_CTX_init(ctx);
	return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}

static EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *ctx = malloc(sizeof(*ctx));

	EVP_MD_CTX_init(ctx);
	return ctx;
}

static void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	EVP_MD_CTX_cleanup(ctx);
	free(ctx);
}
#endif

static void
auth_hmac_init(odp_crypto_generic_session_t *session)
{
	HMAC_CTX *ctx = local.hmac_ctx[session->idx];

	HMAC_Init_ex(ctx,
		     session->auth.key,
		     session->p.auth_key.length,
		     session->auth.evp_md,
		     NULL);
}

static
void packet_hmac(odp_packet_t pkt,
		 const odp_crypto_packet_op_param_t *param,
		 odp_crypto_generic_session_t *session,
		 uint8_t *hash)
{
	HMAC_CTX *ctx = local.hmac_ctx[session->idx];
	uint32_t offset = param->auth_range.offset;
	uint32_t len   = param->auth_range.length;

	_ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	/* Reinitialize HMAC calculation without resetting the key */
	HMAC_Init_ex(ctx, NULL, 0, NULL, NULL);

	/* Hash it */
	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		uint32_t maclen = len > seglen ? seglen : len;

		HMAC_Update(ctx, mapaddr, maclen);
		offset  += maclen;
		len     -= maclen;
	}

	HMAC_Final(ctx, hash, NULL);
}

static void xor_block(uint8_t *res, const uint8_t *op)
{
	int i;

	for (i = 0; i < AES_BLOCK_SIZE; i++)
		res[i] ^= op[i];
}

static void memxor(uint8_t *res, const uint8_t *op, size_t len)
{
	for (size_t i = 0; i < len; i++)
		res[i] ^= op[i];
}

static
void packet_aes_xcbc_mac(odp_packet_t pkt,
			 const odp_crypto_packet_op_param_t *param,
			 odp_crypto_generic_session_t *session,
			 uint8_t *hash)
{
	uint8_t e[AES_BLOCK_SIZE] = {0};
	size_t eoff = 0;
	uint32_t offset = param->auth_range.offset;
	uint32_t len   = param->auth_range.length;
	uint32_t seglen = 0;
	uint32_t datalen = 0;
	int dummy_len = 0;
	EVP_CIPHER_CTX *ctx;
	void *mapaddr;
	uint8_t *data = NULL;

	_ODP_ASSERT(offset + len <= odp_packet_len(pkt));
	_ODP_ASSERT(session != NULL);
	_ODP_ASSERT(sizeof(session->auth.key) >= 3 * AES_KEY_LENGTH);

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, session->auth.evp_cipher,
			   NULL, session->auth.key, NULL);

	while (len > 0) {
		mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		datalen = seglen >= len ? len : seglen;
		data = (uint8_t *)mapaddr;
		offset += datalen;
		len -= datalen;
		if (eoff != 0) {
			if (eoff + datalen > AES_BLOCK_SIZE) {
				/* bytes needed to fill the partial block */
				uint32_t remaining_len = AES_BLOCK_SIZE - eoff;

				memxor(e + eoff, data, remaining_len);
				datalen -= remaining_len;
				data += remaining_len;
				eoff = 0;
				EVP_EncryptUpdate(ctx,
						  e, &dummy_len, e, sizeof(e));
			} else {
				memxor(e + eoff, data, datalen);
				eoff += datalen;
				continue;
			}
		}
		while (datalen > AES_BLOCK_SIZE) {
			xor_block(e, data);
			EVP_EncryptUpdate(ctx, e, &dummy_len, e, sizeof(e));
			data += AES_BLOCK_SIZE;
			datalen -= AES_BLOCK_SIZE;
		}
		/* Segmentation handle */
		if (datalen > 0) {
			memxor(e, data, datalen);
			eoff = datalen;
		}
	}

	if (eoff == AES_BLOCK_SIZE) {
		xor_block(e, session->auth.key + AES_KEY_LENGTH);
	} else {
		e[eoff] ^= 0x80;
		xor_block(e, session->auth.key + AES_KEY_LENGTH * 2);
	}
	EVP_EncryptUpdate(ctx, hash, &dummy_len, e, sizeof(e));
	EVP_CIPHER_CTX_free(ctx);
}

static
odp_crypto_alg_err_t auth_xcbcmac_gen(odp_packet_t pkt,
				      const odp_crypto_packet_op_param_t *param,
				      odp_crypto_generic_session_t *session)
{
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Hash it */
	packet_aes_xcbc_mac(pkt, param, session, hash);

	/* Copy to the output location */
	odp_packet_copy_from_mem(pkt,
				 param->hash_result_offset,
				 session->p.auth_digest_len,
				 hash);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static odp_crypto_alg_err_t
auth_xcbcmac_check(odp_packet_t pkt,
		   const odp_crypto_packet_op_param_t *param,
		   odp_crypto_generic_session_t *session)
{
	uint32_t bytes = session->p.auth_digest_len;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       bytes, hash_in);

	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset, 0, bytes);

	/* Hash it */
	packet_aes_xcbc_mac(pkt, param, session, hash_out);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_aesxcbc_param(odp_crypto_generic_session_t *session,
				 const EVP_CIPHER *cipher)
{
	uint32_t k1[4] = { 0x01010101, 0x01010101, 0x01010101, 0x01010101 };
	uint32_t k2[4] = { 0x02020202, 0x02020202, 0x02020202, 0x02020202 };
	uint32_t k3[4] = { 0x03030303, 0x03030303, 0x03030303, 0x03030303 };
	EVP_CIPHER_CTX *ctx;
	int dummy_len = 0;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_xcbcmac_gen;
	else
		session->auth.func = auth_xcbcmac_check;
	session->auth.init = null_crypto_init_routine;

	session->auth.evp_cipher = cipher;
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, session->auth.evp_cipher, NULL,
			   session->p.auth_key.data, NULL);
	/*  K1 = 0x01010101010101010101010101010101 encrypted with Key K */
	EVP_EncryptUpdate(ctx, session->auth.key,
			  &dummy_len, (uint8_t *)k1, AES_BLOCK_SIZE);

	/*  K2 = 0x02020202020202020202020202020202 encrypted with Key K */
	EVP_EncryptUpdate(ctx, session->auth.key + AES_KEY_LENGTH,
			  &dummy_len, (uint8_t *)k2, AES_BLOCK_SIZE);

	/*  K3 = 0x03030303030303030303030303030303 encrypted with Key K */
	EVP_EncryptUpdate(ctx, session->auth.key + AES_KEY_LENGTH * 2,
			  &dummy_len, (uint8_t *)k3, AES_BLOCK_SIZE);

	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static
odp_crypto_alg_err_t auth_hmac_gen(odp_packet_t pkt,
				   const odp_crypto_packet_op_param_t *param,
				   odp_crypto_generic_session_t *session)
{
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Hash it */
	packet_hmac(pkt, param, session, hash);

	/* Copy to the output location */
	odp_packet_copy_from_mem(pkt,
				 param->hash_result_offset,
				 session->p.auth_digest_len,
				 hash);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_hmac_check(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	uint32_t bytes = session->p.auth_digest_len;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       bytes, hash_in);

	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset, 0, bytes);

	/* Hash it */
	packet_hmac(pkt, param, session, hash_out);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static void
auth_cmac_init(odp_crypto_generic_session_t *session)
{
	CMAC_CTX *ctx = local.cmac_ctx[session->idx];

	CMAC_Init(ctx,
		  session->auth.key,
		  session->p.auth_key.length,
		  session->auth.evp_cipher,
		  NULL);
}

static
void packet_cmac(odp_packet_t pkt,
		 const odp_crypto_packet_op_param_t *param,
		 odp_crypto_generic_session_t *session,
		 uint8_t *hash)
{
	CMAC_CTX *ctx = local.cmac_ctx[session->idx];
	uint32_t offset = param->auth_range.offset;
	uint32_t len   = param->auth_range.length;
	size_t outlen;

	_ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	/* Reinitialize CMAC calculation without resetting the key */
	CMAC_Init(ctx, NULL, 0, NULL, NULL);

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		uint32_t maclen = len > seglen ? seglen : len;

		CMAC_Update(ctx, mapaddr, maclen);
		offset  += maclen;
		len     -= maclen;
	}

	CMAC_Final(ctx, hash, &outlen);
}

static
odp_crypto_alg_err_t auth_cmac_gen(odp_packet_t pkt,
				   const odp_crypto_packet_op_param_t *param,
				   odp_crypto_generic_session_t *session)
{
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Hash it */
	packet_cmac(pkt, param, session, hash);

	/* Copy to the output location */
	odp_packet_copy_from_mem(pkt,
				 param->hash_result_offset,
				 session->p.auth_digest_len,
				 hash);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_cmac_check(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	uint32_t bytes = session->p.auth_digest_len;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       bytes, hash_in);

	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset, 0, bytes);

	/* Hash it */
	packet_cmac(pkt, param, session, hash_out);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int packet_cmac_eia2(odp_packet_t pkt,
		     const odp_crypto_packet_op_param_t *param,
		     odp_crypto_generic_session_t *session,
		     uint8_t *hash)
{
	CMAC_CTX *ctx = local.cmac_ctx[session->idx];
	const void *iv_ptr = param->auth_iv_ptr;
	uint32_t offset = param->auth_range.offset;
	uint32_t len    = param->auth_range.length;
	size_t outlen;

	_ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	/* Reinitialize CMAC calculation without resetting the key */
	CMAC_Init(ctx, NULL, 0, NULL, NULL);

	CMAC_Update(ctx, iv_ptr, session->p.auth_iv_len);

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		uint32_t maclen = len > seglen ? seglen : len;

		CMAC_Update(ctx, mapaddr, maclen);
		offset  += maclen;
		len     -= maclen;
	}

	if (1 != CMAC_Final(ctx, hash, &outlen))
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;
	else
		return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_cmac_eia2_gen(odp_packet_t pkt,
					const odp_crypto_packet_op_param_t
							*param,
					odp_crypto_generic_session_t *session)
{
	uint8_t  hash[EVP_MAX_MD_SIZE];
	int ret;

	/* Hash it */
	ret = packet_cmac_eia2(pkt, param, session, hash);
	if (ret != ODP_CRYPTO_ALG_ERR_NONE)
		return ret;

	/* Copy to the output location */
	odp_packet_copy_from_mem(pkt,
				 param->hash_result_offset,
				 session->p.auth_digest_len,
				 hash);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_cmac_eia2_check(odp_packet_t pkt,
					  const odp_crypto_packet_op_param_t
							*param,
					  odp_crypto_generic_session_t *session)
{
	uint32_t bytes = session->p.auth_digest_len;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];
	int ret;

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       bytes, hash_in);

	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset, 0, bytes);

	/* Hash it */
	ret = packet_cmac_eia2(pkt, param, session, hash_out);
	if (ret != ODP_CRYPTO_ALG_ERR_NONE)
		return ret;

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
void packet_digest(odp_packet_t pkt,
		   const odp_crypto_packet_op_param_t *param,
		   odp_crypto_generic_session_t *session,
		   uint8_t *hash)
{
	EVP_MD_CTX *ctx = local.md_ctx[session->idx];
	uint32_t offset = param->auth_range.offset;
	uint32_t len   = param->auth_range.length;

	_ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	EVP_DigestInit_ex(ctx,
			  session->auth.evp_md,
			  NULL);

	/* Hash it */
	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		uint32_t maclen = len > seglen ? seglen : len;

		EVP_DigestUpdate(ctx, mapaddr, maclen);
		offset  += maclen;
		len     -= maclen;
	}

	EVP_DigestFinal_ex(ctx, hash, NULL);
}

static
odp_crypto_alg_err_t auth_digest_gen(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Hash it */
	packet_digest(pkt, param, session, hash);

	/* Copy to the output location */
	odp_packet_copy_from_mem(pkt,
				 param->hash_result_offset,
				 session->p.auth_digest_len,
				 hash);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_digest_check(odp_packet_t pkt,
				       const odp_crypto_packet_op_param_t
							*param,
				       odp_crypto_generic_session_t *session)
{
	uint32_t bytes = session->p.auth_digest_len;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       bytes, hash_in);

	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset, 0, bytes);

	/* Hash it */
	packet_digest(pkt, param, session, hash_out);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int internal_aad(EVP_CIPHER_CTX *ctx,
		 odp_packet_t pkt,
		 const odp_crypto_packet_op_param_t *param,
		 odp_bool_t encrypt)
{
	uint32_t offset = param->auth_range.offset;
	uint32_t len   = param->auth_range.length;
	int dummy_len;
	int ret;

	_ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		uint32_t maclen = len > seglen ? seglen : len;

		if (encrypt)
			EVP_EncryptUpdate(ctx, NULL, &dummy_len, mapaddr, maclen);
		else
			EVP_DecryptUpdate(ctx, NULL, &dummy_len, mapaddr, maclen);
		offset  += maclen;
		len     -= maclen;
	}

	if (encrypt)
		ret = EVP_EncryptFinal_ex(ctx, NULL, &dummy_len);
	else
		ret = EVP_DecryptFinal_ex(ctx, NULL, &dummy_len);

	return ret;
}

typedef int (*evp_update_t)(EVP_CIPHER_CTX *, unsigned char *,
			    int *, const unsigned char *, int);

typedef int (*evp_final_t)(EVP_CIPHER_CTX *, unsigned char *, int *);

static inline int internal_crypt(EVP_CIPHER_CTX *ctx,
				 odp_packet_t pkt,
				 const odp_crypto_packet_op_param_t *param,
				 evp_update_t EVP_update,
				 evp_final_t EVP_final)
{
	uint32_t in_pos = param->cipher_range.offset;
	uint32_t out_pos = in_pos;
	uint32_t in_len = param->cipher_range.length;
	uint8_t block[EVP_MAX_BLOCK_LENGTH];
	uint32_t buffered = 0;
	uint32_t block_len = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
	int out_len;
	int rc;

	_ODP_ASSERT(in_pos + in_len <= odp_packet_len(pkt));

	/*
	 * In the following loop we process one packet segment per iteration.
	 * We rely on the following properties of the encrypt/decrypt update
	 * function with the algorithms that we use:
	 *
	 * - The function processes (and writes to output) only whole blocks.
	 * - Input data beyond the last full block is buffered inside OpenSSL.
	 * - The amount of buffered data is always less than one block.
	 * - Total amount of output data does not exceed the total amount
	 *   of input data at any point.
	 */
	while (in_len > 0) {
		uint32_t seglen = 0;
		uint8_t *in_addr = odp_packet_offset(pkt, in_pos,
						     &seglen, NULL);
		uint32_t len = in_len < seglen ? in_len : seglen;

		if (odp_unlikely(buffered > 0)) {
			/*
			 * Leftover data from the previous segment is
			 * in the buffer inside OpenSSL.
			 */
			uint32_t remaining_len = block_len - buffered;

			if (odp_likely(len >= remaining_len)) {
				/*
				 * Let's fill the buffered input data to a
				 * full block and get the output block to
				 * a memory buffer. The buffer is then copied
				 * to the packet, crossing segment boundary.
				 */
				rc = EVP_update(ctx, block, &out_len,
						in_addr, remaining_len);
				if (odp_unlikely(rc != 1))
					goto err;
				if (odp_unlikely(out_len != (int)block_len))
					goto err;
				in_addr += remaining_len;
				in_pos += remaining_len;
				len -= remaining_len;
				in_len -= remaining_len;
				buffered = 0;
				rc = odp_packet_copy_from_mem(pkt, out_pos,
							      block_len, block);
				if (odp_unlikely(rc))
					goto err;
				out_pos += block_len;
			} else {
				/*
				 * Not enough data in this segment to fill
				 * the buffer to a full block. Fill the buffer
				 * a bit more and go to the next segment.
				 */
				rc = EVP_update(ctx, block, &out_len,
						in_addr, len);
				if (odp_unlikely(rc != 1))
					goto err;
				if (odp_unlikely(out_len > 0))
					goto err;
				in_pos += len;
				in_len -= len;
				buffered += len;
				continue;
			}
		}
		_ODP_ASSERT(buffered == 0);

		if (in_len > 0) {
			/*
			 * No input is buffered inside OpenSSL. We pass the
			 * whole remaining segment to OpenSSL and expect to
			 * get a multiple of block size of data processed,
			 * with the rest left in the buffer.
			 */
			rc = EVP_update(ctx, in_addr, &out_len, in_addr, len);
			if (odp_unlikely(rc != 1))
				goto err;
			_ODP_ASSERT(_ODP_CHECK_IS_POWER2(block_len));
			buffered = len & (block_len - 1);
			if (odp_unlikely(out_len + buffered != len))
				goto err;
			in_pos += len;
			in_len -= len;
			out_pos += len - buffered;
		}
	}
	if (odp_unlikely(buffered > 0))
		goto err;
	/*
	 * We do not expect any more data out since the cipher range is
	 * supposed to be a multiple of the block size.
	 */
	rc = EVP_final(ctx, block, &out_len);
	if (odp_unlikely(out_len != 0))
		return 0;
	return rc;
err:
	_ODP_ERR("internal error\n");
	(void)EVP_final(ctx, block, &out_len);
	return 0;
}

static int internal_encrypt(EVP_CIPHER_CTX *ctx,
			    odp_packet_t pkt,
			    const odp_crypto_packet_op_param_t *param)
{
	return internal_crypt(ctx, pkt, param,
			      EVP_EncryptUpdate,
			      EVP_EncryptFinal_ex);
}

static int internal_decrypt(EVP_CIPHER_CTX *ctx,
			    odp_packet_t pkt,
			    const odp_crypto_packet_op_param_t *param)
{
	return internal_crypt(ctx, pkt, param,
			      EVP_DecryptUpdate,
			      EVP_DecryptFinal_ex);
}

static void
cipher_encrypt_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];

	EVP_EncryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t cipher_encrypt(odp_packet_t pkt,
				    const odp_crypto_packet_op_param_t *param,
				    odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	int ret;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);

	ret = internal_encrypt(ctx, pkt, param);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static void
cipher_decrypt_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];

	EVP_DecryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t cipher_decrypt(odp_packet_t pkt,
				    const odp_crypto_packet_op_param_t *param,
				    odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	int ret;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);

	ret = internal_decrypt(ctx, pkt, param);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_cipher_param(odp_crypto_generic_session_t *session,
				const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	/* Verify IV len is correct */
	if ((uint32_t)EVP_CIPHER_iv_length(cipher) !=
	       session->p.cipher_iv_len)
		return -1;

	session->cipher.evp_cipher = cipher;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op) {
		session->cipher.func = cipher_encrypt;
		session->cipher.init = cipher_encrypt_init;
	} else {
		session->cipher.func = cipher_decrypt;
		session->cipher.init = cipher_decrypt_init;
	}

	return 0;
}

static odp_crypto_alg_err_t cipher_encrypt_bytes(odp_packet_t pkt,
						 const odp_crypto_packet_op_param_t *param,
						 odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	int dummy_len = 0;
	int cipher_len;
	uint32_t in_len = param->cipher_range.length;
	uint32_t offset = param->cipher_range.offset;
	uint8_t data[in_len];
	int ret;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);
	odp_packet_copy_to_mem(pkt, offset, in_len, data);
	EVP_EncryptUpdate(ctx, data, &cipher_len, data, in_len);
	ret = EVP_EncryptFinal_ex(ctx, data + cipher_len, &dummy_len);
	cipher_len += dummy_len;
	odp_packet_copy_from_mem(pkt, offset, in_len, data);
	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static odp_crypto_alg_err_t cipher_decrypt_bytes(odp_packet_t pkt,
						 const odp_crypto_packet_op_param_t *param,
						 odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	int dummy_len = 0;
	int cipher_len;
	uint32_t in_len = param->cipher_range.length;
	uint32_t offset = param->cipher_range.offset;
	uint8_t data[in_len];
	int ret;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);
	odp_packet_copy_to_mem(pkt, offset, in_len, data);
	EVP_DecryptUpdate(ctx, data, &cipher_len, data, in_len);
	ret = EVP_DecryptFinal_ex(ctx, data + cipher_len, &dummy_len);
	cipher_len += dummy_len;
	odp_packet_copy_from_mem(pkt, offset, in_len, data);
	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static odp_crypto_alg_err_t cipher_encrypt_bits(odp_packet_t pkt,
						const odp_crypto_packet_op_param_t *param,
						odp_crypto_generic_session_t *session)
{
	odp_crypto_packet_op_param_t new_param = *param;

	new_param.cipher_range.offset /= 8;
	new_param.cipher_range.length = (new_param.cipher_range.length + 7) / 8;
	return cipher_encrypt_bytes(pkt, &new_param, session);
}

static odp_crypto_alg_err_t cipher_decrypt_bits(odp_packet_t pkt,
						const odp_crypto_packet_op_param_t *param,
						odp_crypto_generic_session_t *session)
{
	odp_crypto_packet_op_param_t new_param = *param;

	new_param.cipher_range.offset /= 8;
	new_param.cipher_range.length = (new_param.cipher_range.length + 7) / 8;
	return cipher_decrypt_bytes(pkt, &new_param, session);
}

static int process_cipher_param_bits(odp_crypto_generic_session_t *session,
				     const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	/* Verify IV len is correct */
	if ((uint32_t)EVP_CIPHER_iv_length(cipher) !=
	       session->p.cipher_iv_len)
		return -1;

	session->cipher.evp_cipher = cipher;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op) {
		session->cipher.init = cipher_encrypt_init;
		session->cipher.func = session->cipher_range_in_bits ? cipher_encrypt_bits
								     : cipher_encrypt_bytes;

	} else {
		session->cipher.init = cipher_decrypt_init;
		session->cipher.func = session->cipher_range_in_bits ? cipher_decrypt_bits
								     : cipher_decrypt_bytes;
	}

	return 0;
}

static void
aes_gcm_encrypt_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];

	EVP_EncryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.cipher_iv_len, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t aes_gcm_encrypt(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	const uint8_t *aad_head = param->aad_ptr;
	uint32_t aad_len = session->p.auth_aad_len;
	int dummy_len = 0;
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_len > 0)
		EVP_EncryptUpdate(ctx, NULL, &dummy_len,
				  aad_head, aad_len);

	ret = internal_encrypt(ctx, pkt, param);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
			    session->p.auth_digest_len, block);
	odp_packet_copy_from_mem(pkt, param->hash_result_offset,
				 session->p.auth_digest_len, block);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static void
aes_gcm_decrypt_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];

	EVP_DecryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.cipher_iv_len, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t aes_gcm_decrypt(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	const uint8_t *aad_head = param->aad_ptr;
	uint32_t aad_len = session->p.auth_aad_len;
	int dummy_len = 0;
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);

	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       session->p.auth_digest_len, block);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
			    session->p.auth_digest_len, block);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_len > 0)
		EVP_DecryptUpdate(ctx, NULL, &dummy_len,
				  aad_head, aad_len);

	ret = internal_decrypt(ctx, pkt, param);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_ICV_CHECK :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_aes_gcm_param(odp_crypto_generic_session_t *session,
				 const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	/* Verify IV len is correct */
	if (12 != session->p.cipher_iv_len)
		return -1;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	session->cipher.evp_cipher = cipher;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op) {
		session->cipher.func = aes_gcm_encrypt;
		session->cipher.init = aes_gcm_encrypt_init;
	} else {
		session->cipher.func = aes_gcm_decrypt;
		session->cipher.init = aes_gcm_decrypt_init;
	}

	return 0;
}

static void
aes_gmac_gen_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.mac_cipher_ctx[session->idx];

	EVP_EncryptInit_ex(ctx, session->auth.evp_cipher, NULL,
			   session->auth.key, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.auth_iv_len, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t aes_gmac_gen(odp_packet_t pkt,
				  const odp_crypto_packet_op_param_t *param,
				  odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.mac_cipher_ctx[session->idx];
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, param->auth_iv_ptr);

	ret = internal_aad(ctx, pkt, param, true);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
			    session->p.auth_digest_len, block);
	odp_packet_copy_from_mem(pkt, param->hash_result_offset,
				 session->p.auth_digest_len, block);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static void
aes_gmac_check_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.mac_cipher_ctx[session->idx];

	EVP_DecryptInit_ex(ctx, session->auth.evp_cipher, NULL,
			   session->auth.key, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.auth_iv_len, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t aes_gmac_check(odp_packet_t pkt,
				    const odp_crypto_packet_op_param_t *param,
				    odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.mac_cipher_ctx[session->idx];
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, param->auth_iv_ptr);

	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       session->p.auth_digest_len, block);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
			    session->p.auth_digest_len, block);
	if (odp_unlikely(session->p.hash_result_in_auth_range))
		_odp_packet_set_data(pkt, param->hash_result_offset,
				     0, session->p.auth_digest_len);

	ret = internal_aad(ctx, pkt, param, false);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_ICV_CHECK :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_aes_gmac_param(odp_crypto_generic_session_t *session,
				  const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.auth_key.length)
		return -1;

	/* Verify IV len is correct */
	if (12 != session->p.auth_iv_len)
		return -1;

	memcpy(session->auth.key, session->p.auth_key.data,
	       session->p.auth_key.length);

	session->auth.evp_cipher = cipher;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op) {
		session->auth.func = aes_gmac_gen;
		session->auth.init = aes_gmac_gen_init;
	} else {
		session->auth.func = aes_gmac_check;
		session->auth.init = aes_gmac_check_init;
	}

	return 0;
}

static void
aes_ccm_encrypt_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];

	EVP_EncryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
			    session->p.cipher_iv_len, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t aes_ccm_encrypt(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	const uint8_t *aad_head = param->aad_ptr;
	uint32_t aad_len = session->p.auth_aad_len;
	int dummy_len = 0;
	int cipher_len;
	uint32_t in_len = param->cipher_range.length;
	uint8_t data[in_len];
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
			    session->p.auth_digest_len, NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, session->cipher.key_data, param->cipher_iv_ptr);

	/* Set len */
	EVP_EncryptUpdate(ctx, NULL, &dummy_len, NULL, in_len);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_len > 0)
		EVP_EncryptUpdate(ctx, NULL, &dummy_len,
				  aad_head, aad_len);

	odp_packet_copy_to_mem(pkt, param->cipher_range.offset, in_len,
			       data);

	EVP_EncryptUpdate(ctx, data, &cipher_len, data, in_len);

	ret = EVP_EncryptFinal_ex(ctx, data + cipher_len, &dummy_len);
	cipher_len += dummy_len;

	odp_packet_copy_from_mem(pkt, param->cipher_range.offset, in_len,
				 data);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG,
			    session->p.auth_digest_len, block);
	odp_packet_copy_from_mem(pkt, param->hash_result_offset,
				 session->p.auth_digest_len, block);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static void
aes_ccm_decrypt_init(odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];

	EVP_DecryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.cipher_iv_len, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
}

static
odp_crypto_alg_err_t aes_ccm_decrypt(odp_packet_t pkt,
				     const odp_crypto_packet_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	const uint8_t *aad_head = param->aad_ptr;
	uint32_t aad_len = session->p.auth_aad_len;
	int dummy_len = 0;
	int cipher_len;
	uint32_t in_len = param->cipher_range.length;
	uint8_t data[in_len];
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	odp_packet_copy_to_mem(pkt, param->hash_result_offset,
			       session->p.auth_digest_len, block);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
			    session->p.auth_digest_len, block);
	EVP_DecryptInit_ex(ctx, NULL, NULL, session->cipher.key_data, param->cipher_iv_ptr);

	/* Set len */
	EVP_DecryptUpdate(ctx, NULL, &dummy_len, NULL, in_len);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_len > 0)
		EVP_DecryptUpdate(ctx, NULL, &dummy_len,
				  aad_head, aad_len);

	odp_packet_copy_to_mem(pkt, param->cipher_range.offset, in_len,
			       data);

	ret = EVP_DecryptUpdate(ctx, data, &cipher_len, data, in_len);

	EVP_DecryptFinal_ex(ctx, data + cipher_len, &dummy_len);
	cipher_len += dummy_len;

	odp_packet_copy_from_mem(pkt, param->cipher_range.offset, in_len,
				 data);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_ICV_CHECK :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_aes_ccm_param(odp_crypto_generic_session_t *session,
				 const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	/* Verify IV len is correct */
	if (11 != session->p.cipher_iv_len &&
	    13 != session->p.cipher_iv_len)
		return -1;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	session->cipher.evp_cipher = cipher;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op) {
		session->cipher.func = aes_ccm_encrypt;
		session->cipher.init = aes_ccm_encrypt_init;
	} else {
		session->cipher.func = aes_ccm_decrypt;
		session->cipher.init = aes_ccm_decrypt_init;
	}

	return 0;
}

static
odp_crypto_alg_err_t xts_encrypt(odp_packet_t pkt,
				 const odp_crypto_packet_op_param_t *param,
				 odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	int dummy_len = 0;
	int cipher_len;
	uint32_t in_len = param->cipher_range.length;
	uint8_t data[in_len];
	int ret;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);

	odp_packet_copy_to_mem(pkt, param->cipher_range.offset, in_len,
			       data);

	EVP_EncryptUpdate(ctx, data, &cipher_len, data, in_len);

	ret = EVP_EncryptFinal_ex(ctx, data + cipher_len, &dummy_len);
	cipher_len += dummy_len;

	odp_packet_copy_from_mem(pkt, param->cipher_range.offset, in_len,
				 data);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t xts_decrypt(odp_packet_t pkt,
				 const odp_crypto_packet_op_param_t *param,
				 odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx = local.cipher_ctx[session->idx];
	int dummy_len = 0;
	int cipher_len;
	uint32_t in_len = param->cipher_range.length;
	uint8_t data[in_len];
	int ret;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, param->cipher_iv_ptr);

	odp_packet_copy_to_mem(pkt, param->cipher_range.offset, in_len,
			       data);

	EVP_DecryptUpdate(ctx, data, &cipher_len, data, in_len);

	ret = EVP_DecryptFinal_ex(ctx, data + cipher_len, &dummy_len);
	cipher_len += dummy_len;

	odp_packet_copy_from_mem(pkt, param->cipher_range.offset, in_len,
				 data);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_xts_param(odp_crypto_generic_session_t *session,
			     const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	/* Verify IV len is correct */
	if ((uint32_t)EVP_CIPHER_iv_length(cipher) !=
	       session->p.cipher_iv_len)
		return -1;

	session->cipher.evp_cipher = cipher;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op) {
		session->cipher.func = xts_encrypt;
		session->cipher.init = cipher_encrypt_init;
	} else {
		session->cipher.func = xts_decrypt;
		session->cipher.init = cipher_decrypt_init;
	}

	return 0;
}

static int process_auth_hmac_param(odp_crypto_generic_session_t *session,
				   const EVP_MD *evp_md)
{
	/* Verify IV len is correct */
	if (0 != session->p.auth_iv_len)
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_hmac_gen;
	else
		session->auth.func = auth_hmac_check;
	session->auth.init = auth_hmac_init;

	session->auth.evp_md = evp_md;

	/* Number of valid bytes */
	if (session->p.auth_digest_len < (unsigned)EVP_MD_size(evp_md) / 2)
		return -1;

	/* Convert keys */
	memcpy(session->auth.key, session->p.auth_key.data,
	       session->p.auth_key.length);

	return 0;
}

static int process_auth_cmac_param(odp_crypto_generic_session_t *session,
				   const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.auth_key.length)
		return -1;

	if (0 != session->p.auth_iv_len)
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_cmac_gen;
	else
		session->auth.func = auth_cmac_check;
	session->auth.init = auth_cmac_init;

	session->auth.evp_cipher = cipher;

	/* Number of valid bytes */
	if (session->p.auth_digest_len <
	    (unsigned)EVP_CIPHER_block_size(cipher) / 2)
		return -1;

	/* Convert keys */
	memcpy(session->auth.key, session->p.auth_key.data,
	       session->p.auth_key.length);

	return 0;
}

static int process_auth_cmac_eia2_param(odp_crypto_generic_session_t *session,
					const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.auth_key.length)
		return -1;

	/* Verify IV len is correct */
	if (8 != session->p.auth_iv_len)
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_cmac_eia2_gen;
	else
		session->auth.func = auth_cmac_eia2_check;
	session->auth.init = auth_cmac_init;

	session->auth.evp_cipher = cipher;

	/* Number of valid bytes */
	if (session->p.auth_digest_len != 4)
		return -1;

	/* Convert keys */
	memcpy(session->auth.key, session->p.auth_key.data,
	       session->p.auth_key.length);

	return 0;
}

static int process_digest_param(odp_crypto_generic_session_t *session,
				const EVP_MD *md)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_MD_size(md) !=
	    session->p.auth_digest_len)
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_digest_gen;
	else
		session->auth.func = auth_digest_check;
	session->auth.init = null_crypto_init_routine;

	session->auth.evp_md = md;

	return 0;
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

	capa->max_sessions = MAX_SESSIONS;
	capa->sync_mode = ODP_SUPPORT_PREFERRED;
	capa->async_mode = ODP_SUPPORT_YES;
	capa->queue_type_plain = 1;
	capa->queue_type_sched = 1;

	/* Memory allocation in libssl is not compatible with process mode */
	if (odp_global_ro.init_param.mem_model == ODP_MEM_MODEL_PROCESS) {
		capa->ciphers.bit.null = 1;
		capa->auths.bit.null = 1;
		return 0;
	}

	capa->ciphers.bit.null       = 1;
	capa->ciphers.bit.trides_cbc = 1;
	capa->ciphers.bit.trides_ecb = 1;
	capa->ciphers.bit.aes_cbc    = 1;
	capa->ciphers.bit.aes_ctr    = 1;
	capa->ciphers.bit.aes_ecb    = 1;
	capa->ciphers.bit.aes_cfb128 = 1;
	capa->ciphers.bit.aes_xts    = 1;
	capa->ciphers.bit.aes_gcm    = 1;
	capa->ciphers.bit.aes_ccm    = 1;
#if _ODP_HAVE_CHACHA20_POLY1305
	capa->ciphers.bit.chacha20_poly1305 = 1;
#endif
	capa->ciphers.bit.aes_eea2   = 1;

	capa->auths.bit.null         = 1;
	capa->auths.bit.md5_hmac     = 1;
	capa->auths.bit.sha1_hmac    = 1;
	capa->auths.bit.sha224_hmac  = 1;
	capa->auths.bit.sha256_hmac  = 1;
	capa->auths.bit.sha384_hmac  = 1;
	capa->auths.bit.sha512_hmac  = 1;
	capa->auths.bit.aes_xcbc_mac = 1;
	capa->auths.bit.aes_gcm      = 1;
	capa->auths.bit.aes_ccm      = 1;
	capa->auths.bit.aes_gmac     = 1;
	capa->auths.bit.aes_cmac     = 1;
#if _ODP_HAVE_CHACHA20_POLY1305
	capa->auths.bit.chacha20_poly1305 = 1;
#endif
	capa->auths.bit.aes_eia2 = 1;

	capa->auths.bit.md5          = 1;
	capa->auths.bit.sha1         = 1;
	capa->auths.bit.sha224       = 1;
	capa->auths.bit.sha256       = 1;
	capa->auths.bit.sha384       = 1;
	capa->auths.bit.sha512       = 1;

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
	case ODP_CIPHER_ALG_3DES_CBC:
		src = cipher_capa_trides_cbc;
		num = sizeof(cipher_capa_trides_cbc) / size;
		break;
	case ODP_CIPHER_ALG_3DES_ECB:
		src = cipher_capa_trides_ecb;
		num = sizeof(cipher_capa_trides_ecb) / size;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		src = cipher_capa_aes_cbc;
		num = sizeof(cipher_capa_aes_cbc) / size;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		src = cipher_capa_aes_ctr;
		num = sizeof(cipher_capa_aes_ctr) / size;
		break;
	case ODP_CIPHER_ALG_AES_ECB:
		src = cipher_capa_aes_ecb;
		num = sizeof(cipher_capa_aes_ecb) / size;
		break;
	case ODP_CIPHER_ALG_AES_CFB128:
		src = cipher_capa_aes_cfb128;
		num = sizeof(cipher_capa_aes_cfb128) / size;
		break;
	case ODP_CIPHER_ALG_AES_XTS:
		src = cipher_capa_aes_xts;
		num = sizeof(cipher_capa_aes_xts) / size;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		src = cipher_capa_aes_gcm;
		num = sizeof(cipher_capa_aes_gcm) / size;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		src = cipher_capa_aes_ccm;
		num = sizeof(cipher_capa_aes_ccm) / size;
		break;
#if _ODP_HAVE_CHACHA20_POLY1305
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		src = cipher_capa_chacha20_poly1305;
		num = sizeof(cipher_capa_chacha20_poly1305) / size;
		break;
#endif
	case ODP_CIPHER_ALG_AES_EEA2:
		src = cipher_capa_aes_eea2;
		num = sizeof(cipher_capa_aes_eea2) / size;
		break;
	default:
		return -1;
	}

	if (num < num_copy)
		num_copy = num;

	if (dst)
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
	case ODP_AUTH_ALG_MD5_HMAC:
		src = auth_capa_md5_hmac;
		num = sizeof(auth_capa_md5_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		src = auth_capa_sha1_hmac;
		num = sizeof(auth_capa_sha1_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA224_HMAC:
		src = auth_capa_sha224_hmac;
		num = sizeof(auth_capa_sha224_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		src = auth_capa_sha256_hmac;
		num = sizeof(auth_capa_sha256_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		src = auth_capa_sha384_hmac;
		num = sizeof(auth_capa_sha384_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		src = auth_capa_sha512_hmac;
		num = sizeof(auth_capa_sha512_hmac) / size;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		src = auth_capa_aes_xcbc;
		num = sizeof(auth_capa_aes_xcbc) / size;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		src = auth_capa_aes_gcm;
		num = sizeof(auth_capa_aes_gcm) / size;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		src = auth_capa_aes_gmac;
		num = sizeof(auth_capa_aes_gmac) / size;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		src = auth_capa_aes_ccm;
		num = sizeof(auth_capa_aes_ccm) / size;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		src = auth_capa_aes_cmac;
		num = sizeof(auth_capa_aes_cmac) / size;
		break;
#if _ODP_HAVE_CHACHA20_POLY1305
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		src = auth_capa_chacha20_poly1305;
		num = sizeof(auth_capa_chacha20_poly1305) / size;
		break;
#endif
	case ODP_AUTH_ALG_AES_EIA2:
		src = auth_capa_aes_eia2;
		num = sizeof(auth_capa_aes_eia2) / size;
		break;
	case ODP_AUTH_ALG_MD5:
		src = auth_capa_md5;
		num = sizeof(auth_capa_md5) / size;
		break;
	case ODP_AUTH_ALG_SHA1:
		src = auth_capa_sha1;
		num = sizeof(auth_capa_sha1) / size;
		break;
	case ODP_AUTH_ALG_SHA224:
		src = auth_capa_sha224;
		num = sizeof(auth_capa_sha224) / size;
		break;
	case ODP_AUTH_ALG_SHA256:
		src = auth_capa_sha256;
		num = sizeof(auth_capa_sha256) / size;
		break;
	case ODP_AUTH_ALG_SHA384:
		src = auth_capa_sha384;
		num = sizeof(auth_capa_sha384) / size;
		break;
	case ODP_AUTH_ALG_SHA512:
		src = auth_capa_sha512;
		num = sizeof(auth_capa_sha512) / size;
		break;
	default:
		return -1;
	}

	if (num < num_copy)
		num_copy = num;

	if (dst)
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
	int cipher_bit_mode_supported = 0;
	int auth_bit_mode_supported = 0;

	if (odp_global_ro.disable.crypto) {
		_ODP_ERR("Crypto is disabled\n");
		/* Dummy output to avoid compiler warning about uninitialized
		 * variables */
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	/* Process mode is not supported with libssl based algos */
	if (odp_global_ro.init_param.mem_model == ODP_MEM_MODEL_PROCESS &&
	    (param->cipher_alg != ODP_CIPHER_ALG_NULL ||
	     param->auth_alg != ODP_AUTH_ALG_NULL)) {
		*status = param->cipher_alg != ODP_CIPHER_ALG_NULL ?
			ODP_CRYPTO_SES_ERR_CIPHER : ODP_CRYPTO_SES_ERR_AUTH;
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

	session->cipher_range_in_bits = !!param->cipher_range_in_bits;
	session->auth_range_in_bits = !!param->auth_range_in_bits;
	session->auth_range_used = 1;
	session->null_crypto_enable = !!param->null_crypto_enable;

	if (session->null_crypto_enable && param->op_mode == ODP_CRYPTO_SYNC) {
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		goto err;
	}

	if (session->p.cipher_iv_len > EVP_MAX_IV_LENGTH) {
		_ODP_DBG("Maximum IV length exceeded\n");
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		goto err;
	}

	if (session->p.auth_iv_len > EVP_MAX_IV_LENGTH) {
		_ODP_DBG("Maximum auth IV length exceeded\n");
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		goto err;
	}

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == param->op)
		session->do_cipher_first =  param->auth_cipher_text;
	else
		session->do_cipher_first = !param->auth_cipher_text;

	/* Process based on cipher */
	switch (param->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		session->cipher.func = null_crypto_routine;
		session->cipher.init = null_crypto_init_routine;
		cipher_bit_mode_supported = 1;
		rc = 0;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		rc = process_cipher_param(session, EVP_des_ede3_cbc());
		break;
	case ODP_CIPHER_ALG_3DES_ECB:
		rc = process_cipher_param(session, EVP_des_ede3_ecb());
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (param->cipher_key.length == 16)
			rc = process_cipher_param(session, EVP_aes_128_cbc());
		else if (param->cipher_key.length == 24)
			rc = process_cipher_param(session, EVP_aes_192_cbc());
		else if (param->cipher_key.length == 32)
			rc = process_cipher_param(session, EVP_aes_256_cbc());
		else
			rc = -1;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		if (param->cipher_key.length == 16)
			rc = process_cipher_param(session, EVP_aes_128_ctr());
		else if (param->cipher_key.length == 24)
			rc = process_cipher_param(session, EVP_aes_192_ctr());
		else if (param->cipher_key.length == 32)
			rc = process_cipher_param(session, EVP_aes_256_ctr());
		else
			rc = -1;
		break;
	case ODP_CIPHER_ALG_AES_ECB:
		if (param->cipher_key.length == 16)
			rc = process_cipher_param(session, EVP_aes_128_ecb());
		else if (param->cipher_key.length == 24)
			rc = process_cipher_param(session, EVP_aes_192_ecb());
		else if (param->cipher_key.length == 32)
			rc = process_cipher_param(session, EVP_aes_256_ecb());
		else
			rc = -1;
		break;
	case ODP_CIPHER_ALG_AES_CFB128:
		if (param->cipher_key.length == 16)
			rc = process_cipher_param(session,
						  EVP_aes_128_cfb128());
		else if (param->cipher_key.length == 24)
			rc = process_cipher_param(session,
						  EVP_aes_192_cfb128());
		else if (param->cipher_key.length == 32)
			rc = process_cipher_param(session,
						  EVP_aes_256_cfb128());
		else
			rc = -1;
		break;
	case ODP_CIPHER_ALG_AES_XTS:
		if (param->cipher_key.length == 32)
			rc = process_xts_param(session, EVP_aes_128_xts());
		else if (param->cipher_key.length == 64)
			rc = process_xts_param(session, EVP_aes_256_xts());
		else
			rc = -1;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time */
		if (param->auth_alg != ODP_AUTH_ALG_AES_GCM)
			rc = -1;
		else if (param->cipher_key.length == 16)
			rc = process_aes_gcm_param(session, EVP_aes_128_gcm());
		else if (param->cipher_key.length == 24)
			rc = process_aes_gcm_param(session, EVP_aes_192_gcm());
		else if (param->cipher_key.length == 32)
			rc = process_aes_gcm_param(session, EVP_aes_256_gcm());
		else
			rc = -1;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		/* AES-CCM requires to do both auth and
		 * cipher at the same time */
		if (param->auth_alg != ODP_AUTH_ALG_AES_CCM)
			rc = -1;
		else if (param->cipher_key.length == 16)
			rc = process_aes_ccm_param(session, EVP_aes_128_ccm());
		else if (param->cipher_key.length == 24)
			rc = process_aes_ccm_param(session, EVP_aes_192_ccm());
		else if (param->cipher_key.length == 32)
			rc = process_aes_ccm_param(session, EVP_aes_256_ccm());
		else
			rc = -1;
		break;
#if _ODP_HAVE_CHACHA20_POLY1305
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		/* ChaCha20_Poly1305 requires to do both auth and
		 * cipher at the same time */
		if (param->auth_alg != ODP_AUTH_ALG_CHACHA20_POLY1305)
			rc = -1;
		else
			rc = process_aes_gcm_param(session,
						   EVP_chacha20_poly1305());
		break;
#endif
	case ODP_CIPHER_ALG_AES_EEA2:
		if (param->cipher_key.length == 16)
			rc = process_cipher_param_bits(session,
						       EVP_aes_128_ctr());
		else
			rc = -1;
		cipher_bit_mode_supported = 1;
		break;
	default:
		rc = -1;
	}

	if (session->cipher_range_in_bits && !cipher_bit_mode_supported)
		rc = -1;

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		goto err;
	}

	/* Process based on auth */
	switch (param->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		session->auth.func = null_crypto_routine;
		session->auth.init = null_crypto_init_routine;
		auth_bit_mode_supported = 1;
		rc = 0;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		rc = process_auth_hmac_param(session, EVP_md5());
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		rc = process_auth_hmac_param(session, EVP_sha1());
		break;
	case ODP_AUTH_ALG_SHA224_HMAC:
		rc = process_auth_hmac_param(session, EVP_sha224());
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		rc = process_auth_hmac_param(session, EVP_sha256());
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		rc = process_auth_hmac_param(session, EVP_sha384());
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		rc = process_auth_hmac_param(session, EVP_sha512());
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		rc = process_aesxcbc_param(session, EVP_aes_128_ecb());
		break;
	case ODP_AUTH_ALG_AES_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time */
		if (param->cipher_alg == ODP_CIPHER_ALG_AES_GCM) {
			session->auth.func = null_crypto_routine;
			session->auth.init = null_crypto_init_routine;
			rc = 0;
		} else {
			rc = -1;
		}
		session->auth_range_used = 0;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (param->auth_key.length == 16)
			rc = process_aes_gmac_param(session, EVP_aes_128_gcm());
		else if (param->auth_key.length == 24)
			rc = process_aes_gmac_param(session, EVP_aes_192_gcm());
		else if (param->auth_key.length == 32)
			rc = process_aes_gmac_param(session, EVP_aes_256_gcm());
		else
			rc = -1;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		/* AES-CCM requires to do both auth and
		 * cipher at the same time */
		if (param->cipher_alg == ODP_CIPHER_ALG_AES_CCM) {
			session->auth.func = null_crypto_routine;
			session->auth.init = null_crypto_init_routine;
			rc = 0;
		} else {
			rc = -1;
		}
		session->auth_range_used = 0;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		if (param->auth_key.length == 16)
			rc = process_auth_cmac_param(session,
						     EVP_aes_128_cbc());
		else if (param->auth_key.length == 24)
			rc = process_auth_cmac_param(session,
						     EVP_aes_192_cbc());
		else if (param->auth_key.length == 32)
			rc = process_auth_cmac_param(session,
						     EVP_aes_256_cbc());
		else
			rc = -1;
		break;
#if _ODP_HAVE_CHACHA20_POLY1305
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		/* ChaCha20_Poly1305 requires to do both auth and
		 * cipher at the same time */
		if (param->cipher_alg == ODP_CIPHER_ALG_CHACHA20_POLY1305) {
			session->auth.func = null_crypto_routine;
			session->auth.init = null_crypto_init_routine;
			rc = 0;
		} else {
			rc = -1;
		}
		session->auth_range_used = 0;
		break;
#endif
	case ODP_AUTH_ALG_AES_EIA2:
		if (param->auth_key.length == 16)
			rc = process_auth_cmac_eia2_param(session,
							  EVP_aes_128_cbc());
		else
			rc = -1;
		break;
	case ODP_AUTH_ALG_MD5:
		rc = process_digest_param(session, EVP_md5());
		break;
	case ODP_AUTH_ALG_SHA1:
		rc = process_digest_param(session, EVP_sha1());
		break;
	case ODP_AUTH_ALG_SHA224:
		rc = process_digest_param(session, EVP_sha224());
		break;
	case ODP_AUTH_ALG_SHA256:
		rc = process_digest_param(session, EVP_sha256());
		break;
	case ODP_AUTH_ALG_SHA384:
		rc = process_digest_param(session, EVP_sha384());
		break;
	case ODP_AUTH_ALG_SHA512:
		rc = process_digest_param(session, EVP_sha512());
		break;
	default:
		rc = -1;
	}

	if (session->auth_range_in_bits && !auth_bit_mode_supported)
		rc = -1;

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void ODP_UNUSED openssl_thread_id(CRYPTO_THREADID ODP_UNUSED *id)
{
	CRYPTO_THREADID_set_numeric(id, odp_thread_id());
}

static void ODP_UNUSED openssl_lock(int mode, int n,
				    const char *file ODP_UNUSED,
				    int line ODP_UNUSED)
{
	if (mode & CRYPTO_LOCK)
		odp_ticketlock_lock(&global->openssl_lock[n]);
	else
		odp_ticketlock_unlock(&global->openssl_lock[n]);
}
#endif

int _odp_crypto_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;
	int nlocks = CRYPTO_num_locks();

	if (odp_global_ro.disable.crypto) {
		_ODP_PRINT("\nODP crypto is DISABLED\n");
		return 0;
	}

	/* Calculate the memory size we need */
	mem_size  = sizeof(odp_crypto_global_t);
	mem_size += nlocks * sizeof(odp_ticketlock_t);

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("_odp_crypto_ssl_global", mem_size,
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

	if (nlocks > 0) {
		for (idx = 0; idx < nlocks; idx++)
			odp_ticketlock_init(&global->openssl_lock[idx]);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		CRYPTO_THREADID_set_callback(openssl_thread_id);
		CRYPTO_set_locking_callback(openssl_lock);
#endif
	}

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);
#endif

	ret = odp_shm_free(odp_shm_lookup("_odp_crypto_ssl_global"));
	if (ret < 0) {
		_ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

int _odp_crypto_init_local(void)
{
	unsigned i;
	int id;

	memset(&local, 0, sizeof(local));

	if (odp_global_ro.disable.crypto)
		return 0;

	for (i = 0; i < MAX_SESSIONS; i++) {
		local.hmac_ctx[i] = HMAC_CTX_new();
		local.cmac_ctx[i] = CMAC_CTX_new();
		local.cipher_ctx[i] = EVP_CIPHER_CTX_new();
		local.mac_cipher_ctx[i] = EVP_CIPHER_CTX_new();
		local.md_ctx[i] = EVP_MD_CTX_new();

		if (local.hmac_ctx[i] == NULL ||
		    local.cmac_ctx[i] == NULL ||
		    local.md_ctx[i] == NULL ||
		    local.cipher_ctx[i] == NULL ||
		    local.mac_cipher_ctx[i] == NULL) {
			_odp_crypto_term_local();
			return -1;
		}
	}

	id = odp_thread_id();
	local.ctx_valid = global->ctx_valid[id];
	/* No need to clear flags here, alloc_session did the job for us */

	return 0;
}

int _odp_crypto_term_local(void)
{
	unsigned i;

	if (odp_global_ro.disable.crypto)
		return 0;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (local.cmac_ctx[i] != NULL)
			CMAC_CTX_free(local.cmac_ctx[i]);
		if (local.hmac_ctx[i] != NULL)
			HMAC_CTX_free(local.hmac_ctx[i]);
		if (local.cipher_ctx[i] != NULL)
			EVP_CIPHER_CTX_free(local.cipher_ctx[i]);
		if (local.mac_cipher_ctx[i] != NULL)
			EVP_CIPHER_CTX_free(local.mac_cipher_ctx[i]);
		if (local.md_ctx[i] != NULL)
			EVP_MD_CTX_free(local.md_ctx[i]);
	}

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

	_odp_crypto_session_print("openssl", session->idx, &session->p);
}

#if ODP_DEPRECATED_API
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
#endif

static
int crypto_int(odp_packet_t pkt_in,
	       odp_packet_t *pkt_out,
	       const odp_crypto_packet_op_param_t *param)
{
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_packet_t out_pkt = pkt_in;
	odp_crypto_packet_result_t *op_result;

	session = (odp_crypto_generic_session_t *)(intptr_t)param->session;

#if ODP_DEPRECATED_API
	if (odp_unlikely(session->p.op_type == ODP_CRYPTO_OP_TYPE_LEGACY)) {
		out_pkt = get_output_packet(session, pkt_in, *pkt_out);
		if (odp_unlikely(out_pkt == ODP_PACKET_INVALID))
			return -1;
	}
#endif

	if (odp_unlikely(session->null_crypto_enable && param->null_crypto))
		goto out;

	if (ODP_DEBUG) {
		if (session->p.auth_alg != ODP_AUTH_ALG_NULL &&
		    param->hash_result_offset + session->p.auth_digest_len
		    > odp_packet_len(out_pkt)) {
			_ODP_ERR("Invalid hash result offset\n");
			rc_cipher = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
			rc_auth = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
			goto out;
		}
	}
	_ODP_ASSERT(session->p.cipher_iv_len == 0 || param->cipher_iv_ptr != NULL);
	_ODP_ASSERT(session->p.auth_iv_len == 0 || param->auth_iv_ptr != NULL);

	crypto_init(session);

	/* Invoke the functions */
	if (session->do_cipher_first) {
		rc_cipher = session->cipher.func(out_pkt, param, session);
		rc_auth = session->auth.func(out_pkt, param, session);
	} else {
		rc_auth = session->auth.func(out_pkt, param, session);
		rc_cipher = session->cipher.func(out_pkt, param, session);
	}

out:
	/* Fill in result */
	packet_subtype_set(out_pkt, ODP_EVENT_PACKET_CRYPTO);
	op_result = &packet_hdr(out_pkt)->crypto_op_result;
	op_result->cipher_status.alg_err = rc_cipher;
	op_result->auth_status.alg_err = rc_auth;

	/* Synchronous, simply return results */
	*pkt_out = out_pkt;

	return 0;
}

/*
 * Copy cipher range and auth range from src to dst,
 * with shifting by dst_offset_shift.
 */
static void copy_ranges(odp_packet_t dst,
			odp_packet_t src,
			const odp_crypto_generic_session_t *session,
			const odp_crypto_packet_op_param_t *param)
{
	odp_packet_data_range_t c_range = param->cipher_range;
	odp_packet_data_range_t a_range = param->auth_range;
	int32_t shift = param->dst_offset_shift;
	int rc;

	if (session->cipher_range_in_bits) {
		c_range.offset /= 8;
		c_range.length = (c_range.length + 7) / 8;
	}
	if (session->auth_range_in_bits) {
		a_range.offset /= 8;
		a_range.length = (a_range.length + 7) / 8;
	}

	if (c_range.length > 0) {
		rc = odp_packet_copy_from_pkt(dst, c_range.offset + shift,
					      src, c_range.offset,
					      c_range.length);
		if (rc) {
			_ODP_ERR("cipher range copying failed\n");
			return;
		}
	}
	if (session->auth_range_used && a_range.length > 0) {
		rc = odp_packet_copy_from_pkt(dst, a_range.offset + shift,
					      src, a_range.offset,
					      a_range.length);
		if (rc) {
			_ODP_ERR("auth range copying failed\n");
			return;
		}
	}
}

static int crypto_int_oop_encode(odp_packet_t pkt_in,
				 odp_packet_t *pkt_out,
				 const odp_crypto_generic_session_t *session,
				 const odp_crypto_packet_op_param_t *param)
{
	odp_crypto_packet_op_param_t new_param = *param;
	const uint32_t c_scale = session->cipher_range_in_bits ? 8 : 1;
	const uint32_t a_scale = session->auth_range_in_bits ? 8 : 1;

	copy_ranges(*pkt_out, pkt_in, session, param);

	new_param.cipher_range.offset += param->dst_offset_shift * c_scale;
	new_param.auth_range.offset += param->dst_offset_shift * a_scale;

	return crypto_int(*pkt_out, pkt_out, &new_param);
}

static int crypto_int_oop_decode(odp_packet_t pkt_in,
				 odp_packet_t *pkt_out,
				 const odp_crypto_generic_session_t *session,
				 const odp_crypto_packet_op_param_t *param)
{
	odp_packet_t copy;
	int rc;

	copy = odp_packet_copy(pkt_in, odp_packet_pool(pkt_in));
	if (copy == ODP_PACKET_INVALID)
		return -1;

	rc = crypto_int(copy, &copy, param);
	if (rc < 0) {
		odp_packet_free(copy);
		return rc;
	}

	copy_ranges(*pkt_out, copy, session, param);

	packet_subtype_set(*pkt_out, ODP_EVENT_PACKET_CRYPTO);
	packet_hdr(*pkt_out)->crypto_op_result = packet_hdr(copy)->crypto_op_result;
	odp_packet_free(copy);

	return 0;
}

/*
 * Slow out-of-place operation implemented using copying and in-place operation
 */
static int crypto_int_oop(odp_packet_t pkt_in,
			  odp_packet_t *pkt_out,
			  const odp_crypto_packet_op_param_t *param)
{
	odp_crypto_generic_session_t *session;
	int rc;

	session = (odp_crypto_generic_session_t *)(intptr_t)param->session;

	if (session->p.op == ODP_CRYPTO_OP_ENCODE)
		rc = crypto_int_oop_encode(pkt_in, pkt_out, session, param);
	else
		rc = crypto_int_oop_decode(pkt_in, pkt_out, session, param);
	if (rc)
		return rc;

	if (session->p.op_mode == ODP_CRYPTO_ASYNC)
		packet_hdr(*pkt_out)->crypto_op_result.pkt_in = pkt_in;

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

		if (odp_likely(session->p.op_type == ODP_CRYPTO_OP_TYPE_BASIC)) {
			rc = crypto_int(pkt_in[i], &pkt_out[i], &param[i]);
		} else if (session->p.op_type == ODP_CRYPTO_OP_TYPE_OOP) {
			rc = crypto_int_oop(pkt_in[i], &pkt_out[i], &param[i]);
		} else if (!ODP_DEPRECATED_API ||
			   session->p.op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP) {
			if (pkt_out[i] == ODP_PACKET_INVALID) /* basic */
				rc = crypto_int(pkt_in[i], &pkt_out[i], &param[i]);
			else                                  /* oop */
				rc = crypto_int_oop(pkt_in[i], &pkt_out[i], &param[i]);
		} else {
#if ODP_DEPRECATED_API
			_ODP_ASSERT(session->p.op_type == ODP_CRYPTO_OP_TYPE_LEGACY);
			rc = crypto_int(pkt_in[i], &pkt_out[i], &param[i]);
#endif
		}
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

		if (odp_likely(session->p.op_type == ODP_CRYPTO_OP_TYPE_BASIC)) {
			rc = crypto_int(pkt_in[i], &pkt, &param[i]);
		} else if (session->p.op_type == ODP_CRYPTO_OP_TYPE_OOP) {
			pkt = pkt_out[i];
			rc = crypto_int_oop(pkt_in[i], &pkt, &param[i]);
		} else if (!ODP_DEPRECATED_API ||
			   session->p.op_type == ODP_CRYPTO_OP_TYPE_BASIC_AND_OOP) {
			pkt = pkt_out[i];
			if (pkt_out[i] == ODP_PACKET_INVALID) /* basic */
				rc = crypto_int(pkt_in[i], &pkt, &param[i]);
			else                                  /* oop */
				rc = crypto_int_oop(pkt_in[i], &pkt, &param[i]);
		} else {
#if ODP_DEPRECATED_API
			_ODP_ASSERT(session->p.op_type == ODP_CRYPTO_OP_TYPE_LEGACY);
			pkt = pkt_out[i];
			rc = crypto_int(pkt_in[i], &pkt, &param[i]);
#endif
		}
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
