/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/crypto.h>
#include <odp_internal.h>
#include <odp/api/atomic.h>
#include <odp/api/spinlock.h>
#include <odp/api/sync.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp_packet_internal.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>

#include <string.h>
#include <math.h>

#include <openssl/rand.h>

/* default number supported by DPDK crypto */
#define MAX_SESSIONS 2048
#define NB_MBUF  8192

typedef struct crypto_session_entry_s crypto_session_entry_t;
struct crypto_session_entry_s {
		struct crypto_session_entry_s *next;
		uint64_t rte_session;
		odp_bool_t do_cipher_first;
		struct rte_crypto_sym_xform cipher_xform;
		struct rte_crypto_sym_xform auth_xform;
		struct {
			uint8_t *data;
			uint16_t length;
		} iv;
		odp_queue_t compl_queue; /**< Async mode completion
					      event queue */
		odp_pool_t output_pool;  /**< Output buffer pool */
};

struct crypto_global_s {
	odp_spinlock_t                lock;
	uint8_t enabled_crypto_devs;
	uint8_t enabled_crypto_dev_ids[RTE_CRYPTO_MAX_DEVS];
	crypto_session_entry_t *free;
	crypto_session_entry_t sessions[MAX_SESSIONS];
	int is_crypto_dev_initialized;
	struct rte_mempool *crypto_op_pool;
};

typedef struct crypto_global_s crypto_global_t;
static crypto_global_t *global;
static odp_shm_t crypto_global_shm;

static odp_crypto_generic_op_result_t *get_op_result_from_event(odp_event_t ev)
{
	return &(odp_packet_hdr(odp_packet_from_event(ev))->op_result);
}

static inline int is_valid_size(uint16_t length, uint16_t min,
				uint16_t max, uint16_t increment)
{
	uint16_t supp_size = min;

	if (length < supp_size)
		return -1;

	for (; supp_size <= max; supp_size += increment) {
		if (length == supp_size)
			return 0;
	}

	return -1;
}

static int cipher_alg_odp_to_rte(odp_cipher_alg_t cipher_alg,
				 struct rte_crypto_sym_xform *cipher_xform)
{
	int rc = 0;

	switch (cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_NULL;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_3DES_CBC;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
	     /* deprecated */
	case ODP_CIPHER_ALG_AES128_CBC:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
	     /* deprecated */
	case ODP_CIPHER_ALG_AES128_GCM:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_GCM;
		break;
	default:
		rc = -1;
	}

	return rc;
}

static int auth_alg_odp_to_rte(odp_auth_alg_t auth_alg,
			       struct rte_crypto_sym_xform *auth_xform)
{
	int rc = 0;

	/* Process based on auth */
	switch (auth_alg) {
	case ODP_AUTH_ALG_NULL:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_NULL;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
	     /* deprecated */
	case ODP_AUTH_ALG_MD5_96:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_MD5_HMAC;
		auth_xform->auth.digest_length = 12;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
	     /* deprecated */
	case ODP_AUTH_ALG_SHA256_128:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
		auth_xform->auth.digest_length = 16;
		break;
	case ODP_AUTH_ALG_AES_GCM:
	     /* deprecated */
	case ODP_AUTH_ALG_AES128_GCM:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_AES_GCM;
		auth_xform->auth.digest_length = 16;
		break;
	default:
		rc = -1;
	}

	return rc;
}

static crypto_session_entry_t *alloc_session(void)
{
	crypto_session_entry_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session)
		global->free = session->next;
	odp_spinlock_unlock(&global->lock);

	return session;
}

static void free_session(crypto_session_entry_t *session)
{
	odp_spinlock_lock(&global->lock);
	session->next = global->free;
	global->free = session;
	odp_spinlock_unlock(&global->lock);
}

int odp_crypto_init_global(void)
{
	size_t mem_size;
	int idx;
	int16_t cdev_id, cdev_count;
	int rc = -1;
	unsigned cache_size = 0;
	unsigned nb_queue_pairs = 0, queue_pair;

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(crypto_session_entry_t));

	/* Allocate our globally shared memory */
	crypto_global_shm = odp_shm_reserve("crypto_pool", mem_size,
					    ODP_CACHE_LINE_SIZE, 0);

	if (crypto_global_shm != ODP_SHM_INVALID) {
		global = odp_shm_addr(crypto_global_shm);

		if (global == NULL) {
			ODP_ERR("Failed to find the reserved shm block");
			return -1;
		}
	} else {
		ODP_ERR("Shared memory reserve failed.\n");
		return -1;
	}

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}

	global->enabled_crypto_devs = 0;
	odp_spinlock_init(&global->lock);

	odp_spinlock_lock(&global->lock);
	if (global->is_crypto_dev_initialized)
		return 0;

	if (RTE_MEMPOOL_CACHE_MAX_SIZE > 0) {
		unsigned j;

		j = ceil((double)NB_MBUF / RTE_MEMPOOL_CACHE_MAX_SIZE);
		j = RTE_MAX(j, 2UL);
		for (; j <= (NB_MBUF / 2); ++j)
			if ((NB_MBUF % j) == 0) {
				cache_size = NB_MBUF / j;
				break;
			}
		if (odp_unlikely(cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE ||
				 (uint32_t)cache_size * 1.5 > NB_MBUF)) {
			ODP_ERR("cache_size calc failure: %d\n", cache_size);
			cache_size = 0;
		}
	}

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		printf("No crypto devices available\n");
		return 0;
	}

	for (cdev_id = cdev_count - 1; cdev_id >= 0; cdev_id--) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		nb_queue_pairs = odp_cpu_count();
		if (nb_queue_pairs > dev_info.max_nb_queue_pairs)
			nb_queue_pairs = dev_info.max_nb_queue_pairs;

		struct rte_cryptodev_qp_conf qp_conf;

		struct rte_cryptodev_config conf = {
			.nb_queue_pairs = nb_queue_pairs,
			.socket_id = SOCKET_ID_ANY,
			.session_mp = {
				.nb_objs = NB_MBUF,
				.cache_size = cache_size
			}
		};

		rc = rte_cryptodev_configure(cdev_id, &conf);
		if (rc < 0) {
			ODP_ERR("Failed to configure cryptodev %u", cdev_id);
			return -1;
		}

		qp_conf.nb_descriptors = NB_MBUF;

		for (queue_pair = 0; queue_pair < nb_queue_pairs - 1;
							queue_pair++) {
			rc = rte_cryptodev_queue_pair_setup(cdev_id,
							    queue_pair,
							    &qp_conf,
							    SOCKET_ID_ANY);
			if (rc < 0) {
				ODP_ERR("Fail to setup queue pair %u on dev %u",
					queue_pair, cdev_id);
				return -1;
			}
		}

		rc = rte_cryptodev_start(cdev_id);
		if (rc < 0) {
			ODP_ERR("Failed to start device %u: error %d\n",
				cdev_id, rc);
			return -1;
		}

		global->enabled_crypto_devs++;
		global->enabled_crypto_dev_ids[
				global->enabled_crypto_devs - 1] = cdev_id;
	}

	/* create crypto op pool */
	global->crypto_op_pool = rte_crypto_op_pool_create("crypto_op_pool",
						   RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						   NB_MBUF, cache_size, 0,
						   rte_socket_id());

	if (global->crypto_op_pool == NULL) {
		ODP_ERR("Cannot create crypto op pool\n");
		return -1;
	}

	global->is_crypto_dev_initialized = 1;
	odp_spinlock_unlock(&global->lock);

	return 0;
}

int odp_crypto_capability(odp_crypto_capability_t *capability)
{
	uint8_t i, cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	enum rte_crypto_auth_algorithm cap_auth_algo;
	enum rte_crypto_cipher_algorithm cap_cipher_algo;

	if (NULL == capability)
		return -1;

	/* Initialize crypto capability structure */
	memset(capability, 0, sizeof(odp_crypto_capability_t));

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		i = 0;
		cap = &dev_info.capabilities[i];
		if ((dev_info.feature_flags &
			RTE_CRYPTODEV_FF_HW_ACCELERATED)) {
			odp_crypto_cipher_algos_t *hw_ciphers;

			hw_ciphers = &capability->hw_ciphers;
			while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
				cap_cipher_algo = cap->sym.cipher.algo;
				if (cap->sym.xform_type ==
					RTE_CRYPTO_SYM_XFORM_CIPHER) {
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_NULL) {
						hw_ciphers->bit.null = 1;
					}
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_3DES_CBC) {
						hw_ciphers->bit.trides_cbc = 1;
						hw_ciphers->bit.des = 1;
					}
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_AES_CBC) {
						hw_ciphers->bit.aes_cbc = 1;
						/* Deprecated */
						hw_ciphers->bit.aes128_cbc = 1;
					}
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_AES_GCM) {
						hw_ciphers->bit.aes_gcm = 1;
						/* Deprecated */
						hw_ciphers->bit.aes128_gcm = 1;
					}
				}

				cap_auth_algo = cap->sym.auth.algo;
				if (cap->sym.xform_type ==
				    RTE_CRYPTO_SYM_XFORM_AUTH) {
					odp_crypto_auth_algos_t *hw_auths;

					hw_auths = &capability->hw_auths;
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_NULL) {
						hw_auths->bit.null = 1;
					}
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_AES_GCM) {
						hw_auths->bit.aes_gcm = 1;
						/* Deprecated */
						hw_auths->bit.aes128_gcm = 1;
					}
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_MD5_HMAC) {
						hw_auths->bit.md5_hmac = 1;
						/* Deprecated */
						hw_auths->bit.md5_96 = 1;
					}
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_SHA256_HMAC) {
						hw_auths->bit.sha256_hmac = 1;
						/* Deprecated */
						hw_auths->bit.sha256_128 = 1;
					}
				}
				cap = &dev_info.capabilities[++i];
			}
		} else {
			while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
				odp_crypto_cipher_algos_t *ciphers;

				ciphers = &capability->ciphers;
				cap_cipher_algo = cap->sym.cipher.algo;
				if (cap->sym.xform_type ==
				    RTE_CRYPTO_SYM_XFORM_CIPHER) {
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_NULL) {
						ciphers->bit.null = 1;
					}
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_3DES_CBC) {
						ciphers->bit.trides_cbc = 1;
						ciphers->bit.des = 1;
					}
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_AES_CBC) {
						ciphers->bit.aes_cbc = 1;
						/* Deprecated */
						ciphers->bit.aes128_cbc = 1;
					}
					if (cap_cipher_algo ==
						RTE_CRYPTO_CIPHER_AES_GCM) {
						ciphers->bit.aes_gcm = 1;
						/* Deprecated */
						ciphers->bit.aes128_gcm = 1;
					}
				}

				cap_auth_algo = cap->sym.auth.algo;
				if (cap->sym.xform_type ==
				    RTE_CRYPTO_SYM_XFORM_AUTH) {
					odp_crypto_auth_algos_t *auths;

					auths = &capability->auths;
					if (cap_auth_algo ==
					    RTE_CRYPTO_AUTH_NULL) {
						auths->bit.null = 1;
					}
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_AES_GCM) {
						auths->bit.aes_gcm = 1;
						/* Deprecated */
						auths->bit.aes128_gcm = 1;
					}
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_MD5_HMAC) {
						auths->bit.md5_hmac = 1;
						/* Deprecated */
						auths->bit.md5_96 = 1;
					}
					if (cap_auth_algo ==
						RTE_CRYPTO_AUTH_SHA256_HMAC) {
						auths->bit.sha256_hmac = 1;
						/* Deprecated */
						auths->bit.sha256_128 = 1;
					}
				}
				cap = &dev_info.capabilities[++i];
			}
		}

		/* Read from the device with the lowest max_nb_sessions */
		if (capability->max_sessions > dev_info.sym.max_nb_sessions)
			capability->max_sessions = dev_info.sym.max_nb_sessions;

		if (capability->max_sessions == 0)
			capability->max_sessions = dev_info.sym.max_nb_sessions;
	}

	/* Make sure the session count doesn't exceed MAX_SESSIONS */
	if (capability->max_sessions > MAX_SESSIONS)
		capability->max_sessions = MAX_SESSIONS;

	return 0;
}

int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t dst[],
				 int num_copy)
{
	odp_crypto_cipher_capability_t src[num_copy];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_cipher_capability_t);

	uint8_t i, cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	enum rte_crypto_cipher_algorithm cap_cipher_algo;
	struct rte_crypto_sym_xform cipher_xform;

	rc = cipher_alg_odp_to_rte(cipher, &cipher_xform);

	/* Check result */
	if (rc)
		return -1;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		i = 0;
		cap = &dev_info.capabilities[i];
		while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
			cap_cipher_algo = cap->sym.cipher.algo;
			if (cap->sym.xform_type ==
			    RTE_CRYPTO_SYM_XFORM_CIPHER) {
				if (cap_cipher_algo == cipher_xform.cipher.algo)
						break;
			}
					cap = &dev_info.capabilities[++i];
		}

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		uint32_t key_size_min = cap->sym.cipher.key_size.min;
		uint32_t key_size_max = cap->sym.cipher.key_size.max;
		uint32_t key_inc = cap->sym.cipher.key_size.increment;
		uint32_t iv_size_max = cap->sym.cipher.iv_size.max;
		uint32_t iv_size_min = cap->sym.cipher.iv_size.min;
		uint32_t iv_inc = cap->sym.cipher.iv_size.increment;

		for (uint32_t key_len = key_size_min; key_len <= key_size_max;
							   key_len += key_inc) {
			for (uint32_t iv_size = iv_size_min;
				iv_size <= iv_size_max; iv_size += iv_inc) {
				src[idx].key_len = key_len;
				src[idx].iv_len = iv_size;
				idx++;
				if (iv_inc == 0)
					break;
			}

			if (key_inc == 0)
				break;
		}
	}

	if (idx < num_copy)
		num_copy = idx;

	memcpy(dst, src, num_copy * size);

	return idx;
}

int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t dst[],
				 int num_copy)
{
	odp_crypto_auth_capability_t src[num_copy];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_auth_capability_t);

	uint8_t i, cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	enum rte_crypto_auth_algorithm cap_auth_algo;
	struct rte_crypto_sym_xform auth_xform;

	rc = auth_alg_odp_to_rte(auth, &auth_xform);

	/* Check result */
	if (rc)
		return -1;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		i = 0;
		cap = &dev_info.capabilities[i];
		while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
			cap_auth_algo = cap->sym.auth.algo;
			if (cap->sym.xform_type ==
			    RTE_CRYPTO_SYM_XFORM_CIPHER) {
				if (cap_auth_algo == auth_xform.auth.algo)
						break;
			}
					cap = &dev_info.capabilities[++i];
		}

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		uint8_t key_size_min = cap->sym.auth.key_size.min;
		uint8_t key_size_max = cap->sym.auth.key_size.max;
		uint8_t increment = cap->sym.auth.key_size.increment;
		uint8_t digest_size_max = cap->sym.auth.digest_size.max;

		if (key_size_min == key_size_max) {
			src[idx].key_len = key_size_min;
			src[idx].digest_len = digest_size_max;
			src[idx].aad_len.min = cap->sym.auth.aad_size.min;
			src[idx].aad_len.max = cap->sym.auth.aad_size.max;
			src[idx].aad_len.inc = cap->sym.auth.aad_size.increment;
			idx++;
		} else {
			for (uint8_t key_len = key_size_min;
				key_len <= key_size_max;
				key_len += increment) {
				idx = (key_len - key_size_min) / increment;
				src[idx].key_len = key_len;
				src[idx].digest_len = digest_size_max;
				src[idx].aad_len.min =
						cap->sym.auth.aad_size.min;
				src[idx].aad_len.max =
						cap->sym.auth.aad_size.max;
				src[idx].aad_len.inc =
					       cap->sym.auth.aad_size.increment;
				idx++;
			}
		}
	}

	if (idx < num_copy)
		num_copy = idx;

	memcpy(dst, src, num_copy * size);

	return idx;
}

static int get_crypto_dev(struct rte_crypto_sym_xform *cipher_xform,
			  struct rte_crypto_sym_xform *auth_xform,
			  uint16_t iv_length, uint8_t *dev_id)
{
	uint8_t cdev_id, id;
	const struct rte_cryptodev_capabilities *cap;
	enum rte_crypto_cipher_algorithm cap_cipher_algo;
	enum rte_crypto_auth_algorithm cap_auth_algo;
	enum rte_crypto_cipher_algorithm app_cipher_algo;
	enum rte_crypto_auth_algorithm app_auth_algo;

	for (id = 0; id < global->enabled_crypto_devs; id++) {
		struct rte_cryptodev_info dev_info;
		int i = 0;

		cdev_id = global->enabled_crypto_dev_ids[id];
		rte_cryptodev_info_get(cdev_id, &dev_info);
		app_cipher_algo = cipher_xform->cipher.algo;
		cap = &dev_info.capabilities[i];
		while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
			cap_cipher_algo = cap->sym.cipher.algo;
			if (cap->sym.xform_type ==
			    RTE_CRYPTO_SYM_XFORM_CIPHER) {
				if (cap_cipher_algo == app_cipher_algo)
						break;
			}
					cap = &dev_info.capabilities[++i];
		}

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		/* Check if key size is supported by the algorithm. */
		if (cipher_xform->cipher.key.length) {
			if (is_valid_size(cipher_xform->cipher.key.length,
					  cap->sym.cipher.key_size.min,
					  cap->sym.cipher.key_size.max,
					  cap->sym.cipher.key_size.
					  increment) != 0) {
				ODP_ERR("Unsupported cipher key length\n");
				return -1;
			}
		/* No size provided, use minimum size. */
		} else
			cipher_xform->cipher.key.length =
					cap->sym.cipher.key_size.min;

		/* Check if iv length is supported by the algorithm. */
		if (iv_length) {
			if (is_valid_size(iv_length,
					  cap->sym.cipher.iv_size.min,
					  cap->sym.cipher.iv_size.max,
					  cap->sym.cipher.iv_size.
					  increment) != 0) {
				ODP_ERR("Unsupported iv length\n");
				return -1;
			}
		}

		i = 0;
		app_auth_algo = auth_xform->auth.algo;
		cap = &dev_info.capabilities[i];
		while (cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED) {
			cap_auth_algo = cap->sym.auth.algo;
			if ((cap->sym.xform_type ==
			    RTE_CRYPTO_SYM_XFORM_AUTH) &
			    (cap_auth_algo == app_auth_algo)) {
				break;
			}

			cap = &dev_info.capabilities[++i];
		}

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		/* Check if key size is supported by the algorithm. */
		if (auth_xform->auth.key.length) {
			if (is_valid_size(auth_xform->auth.key.length,
					  cap->sym.auth.key_size.min,
					  cap->sym.auth.key_size.max,
					  cap->sym.auth.key_size.
					  increment) != 0) {
				ODP_ERR("Unsupported auth key length\n");
				return -1;
			}
		/* No size provided, use minimum size. */
		} else
			auth_xform->auth.key.length =
					cap->sym.auth.key_size.min;

		/* Check if digest size is supported by the algorithm. */
		if (auth_xform->auth.digest_length) {
			if (is_valid_size(auth_xform->auth.digest_length,
					  cap->sym.auth.digest_size.min,
					  cap->sym.auth.digest_size.max,
					  cap->sym.auth.digest_size.
					  increment) != 0) {
				ODP_ERR("Unsupported digest length\n");
				return -1;
			}
		/* No size provided, use minimum size. */
		} else
			auth_xform->auth.digest_length =
					cap->sym.auth.digest_size.min;

		memcpy(dev_id, &cdev_id, sizeof(cdev_id));
		return 0;
	}

	return -1;
}

int odp_crypto_session_create(odp_crypto_session_params_t *params,
			      odp_crypto_session_t *session_out,
			      odp_crypto_ses_create_err_t *status)
{
	int rc = 0;
	uint8_t cdev_id = 0;
	struct rte_crypto_sym_xform cipher_xform;
	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform *first_xform;
	struct rte_cryptodev_sym_session *session;
	crypto_session_entry_t *entry;

	*session_out = ODP_CRYPTO_SESSION_INVALID;

	if (rte_cryptodev_count() == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	/* Allocate memory for this session */
	entry = alloc_session();
	if (entry == NULL) {
		ODP_ERR("Failed to allocate a session entry");
		return -1;
	}

	/* Default to successful result */
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;

	/* Cipher Data */
	cipher_xform.cipher.key.data = rte_malloc("crypto key",
						params->cipher_key.length, 0);
	if (cipher_xform.cipher.key.data == NULL) {
		ODP_ERR("Failed to allocate memory for cipher key\n");
		/* remove the crypto_session_entry_t */
		memset(entry, 0, sizeof(*entry));
		free_session(entry);
		return -1;
	}

	cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cipher_xform.next = NULL;
	cipher_xform.cipher.key.length = params->cipher_key.length;
	memcpy(cipher_xform.cipher.key.data,
	       params->cipher_key.data,
	       params->cipher_key.length);

	/* Authentication Data */
	auth_xform.auth.key.data = rte_malloc("auth key",
						params->auth_key.length, 0);
	if (auth_xform.auth.key.data == NULL) {
		ODP_ERR("Failed to allocate memory for auth key\n");
		/* remove the crypto_session_entry_t */
		memset(entry, 0, sizeof(*entry));
		free_session(entry);
		return -1;
	}
	auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	auth_xform.next = NULL;
	auth_xform.auth.key.length = params->auth_key.length;
	memcpy(auth_xform.auth.key.data,
	       params->auth_key.data,
	       params->auth_key.length);

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		entry->do_cipher_first =  params->auth_cipher_text;
	else
		entry->do_cipher_first = !params->auth_cipher_text;

	/* Process based on cipher */
	/* Derive order */
	if (entry->do_cipher_first) {
		cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
		auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
		first_xform = &cipher_xform;
		first_xform->next = &auth_xform;
	} else {
		cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		auth_xform.auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
		first_xform = &auth_xform;
		first_xform->next = &cipher_xform;
	}

	rc = cipher_alg_odp_to_rte(params->cipher_alg, &cipher_xform);

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;
		return -1;
	}

	rc = auth_alg_odp_to_rte(params->auth_alg, &auth_xform);

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH;
		/* remove the crypto_session_entry_t */
		memset(entry, 0, sizeof(*entry));
		free_session(entry);
		return -1;
	}

	rc = get_crypto_dev(&cipher_xform,
			    &auth_xform,
			    params->iv.length,
			    &cdev_id);

	if (rc) {
		ODP_ERR("Couldn't find a crypto device");
		/* remove the crypto_session_entry_t */
		memset(entry, 0, sizeof(*entry));
		free_session(entry);
		return -1;
	}

	/* Setup session */
	session = rte_cryptodev_sym_session_create(cdev_id, first_xform);

	if (session == NULL)
		/* remove the crypto_session_entry_t */
		memset(entry, 0, sizeof(*entry));
		free_session(entry);
		return -1;

	entry->rte_session  = (intptr_t)session;
	entry->cipher_xform = cipher_xform;
	entry->auth_xform = auth_xform;
	entry->iv.length = params->iv.length;
	entry->iv.data = params->iv.data;
	entry->output_pool = params->output_pool;
	entry->compl_queue = params->compl_queue;

	/* We're happy */
	*session_out = (intptr_t)entry;

	return 0;
}

int odp_crypto_session_destroy(odp_crypto_session_t session)
{
	struct rte_cryptodev_sym_session *rte_session = NULL;
	crypto_session_entry_t *entry;

	entry = (crypto_session_entry_t *)session;

	rte_session =
		(struct rte_cryptodev_sym_session *)
						(intptr_t)entry->rte_session;

	rte_session = rte_cryptodev_sym_session_free(rte_session->dev_id,
						     rte_session);

	if (rte_session != NULL)
		return -1;

	/* remove the crypto_session_entry_t */
	memset(entry, 0, sizeof(*entry));
	free_session(entry);

	return 0;
}

int odp_crypto_operation(odp_crypto_op_params_t *params,
			 odp_bool_t *posted,
			 odp_crypto_op_result_t *result)
{
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	struct rte_crypto_sym_xform cipher_xform;
	struct rte_crypto_sym_xform auth_xform;
	struct rte_cryptodev_sym_session *rte_session = NULL;
	odp_crypto_op_result_t local_result;
	crypto_session_entry_t *entry;
	uint8_t *data_addr, *aad_head;
	struct rte_crypto_op *op;
	uint16_t rc;
	uint32_t plain_len, aad_len;
	odp_bool_t pkt_allocated = 0;

	entry = (crypto_session_entry_t *)(intptr_t)params->session;
	if (entry == NULL)
		return -1;

	rte_session =
		(struct rte_cryptodev_sym_session *)
						(intptr_t)entry->rte_session;

	if (rte_session == NULL)
		return -1;

	cipher_xform = entry->cipher_xform;
	auth_xform = entry->auth_xform;

	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->out_pkt &&
	    ODP_POOL_INVALID != entry->output_pool) {
		params->out_pkt = odp_packet_alloc(entry->output_pool,
						   odp_packet_len(params->pkt));
		pkt_allocated = 1;
	}

	if (params->pkt != params->out_pkt) {
		if (odp_unlikely(ODP_PACKET_INVALID == params->out_pkt))
			ODP_ABORT();
		(void)odp_packet_copy_from_pkt(params->out_pkt,
					       0,
					       params->pkt,
					       0,
					       odp_packet_len(params->pkt));
		_odp_packet_copy_md_to_packet(params->pkt, params->out_pkt);
		odp_packet_free(params->pkt);
		params->pkt = ODP_PACKET_INVALID;
	}

	data_addr = odp_packet_data(params->out_pkt);

	odp_spinlock_init(&global->lock);
	odp_spinlock_lock(&global->lock);
	op = rte_crypto_op_alloc(global->crypto_op_pool,
				 RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (op == NULL) {
		if (pkt_allocated)
			odp_packet_free(params->out_pkt);
		ODP_ERR("Failed to allocate crypto operation");
		return -1;
	}

	odp_spinlock_unlock(&global->lock);

	/* Set crypto operation data parameters */
	rte_crypto_op_attach_sym_session(op, rte_session);
	op->sym->auth.digest.data = data_addr + params->hash_result_offset;
	op->sym->auth.digest.phys_addr =
		rte_pktmbuf_mtophys_offset((struct rte_mbuf *)params->out_pkt,
					   odp_packet_len(params->out_pkt) -
					   auth_xform.auth.digest_length);
	op->sym->auth.digest.length = auth_xform.auth.digest_length;

	/* For SNOW3G algorithms, offset/length must be in bits */
	if (auth_xform.auth.algo == RTE_CRYPTO_AUTH_SNOW3G_UIA2) {
		op->sym->auth.data.offset = params->auth_range.offset << 3;
		op->sym->auth.data.length = params->auth_range.length << 3;
	} else {
		op->sym->auth.data.offset = params->auth_range.offset;
		op->sym->auth.data.length = params->auth_range.length;
	}

	aad_head = data_addr + params->auth_range.offset;
	plain_len   = params->cipher_range.length;
	aad_len = params->auth_range.length - plain_len;

	if (aad_len > 0) {
		op->sym->auth.aad.data = rte_malloc("aad", aad_len, 0);
		if (op->sym->auth.aad.data == NULL) {
			rte_crypto_op_free(op);
			if (pkt_allocated)
				odp_packet_free(params->out_pkt);
			ODP_ERR("Failed to allocate memory for AAD");
			return -1;
		}

		memcpy(op->sym->auth.aad.data, aad_head, aad_len);
		op->sym->auth.aad.phys_addr =
				rte_malloc_virt2phy(op->sym->auth.aad.data);
		op->sym->auth.aad.length = aad_len;
	}

	if (entry->iv.length == 0) {
		rte_crypto_op_free(op);
		if (pkt_allocated)
			odp_packet_free(params->out_pkt);
		ODP_ERR("Wrong IV length");
		return -1;
	}

	op->sym->cipher.iv.data = rte_malloc("iv", entry->iv.length, 0);
	if (op->sym->cipher.iv.data == NULL) {
		rte_crypto_op_free(op);
		if (pkt_allocated)
			odp_packet_free(params->out_pkt);
		ODP_ERR("Failed to allocate memory for IV");
		return -1;
	}

	if (params->override_iv_ptr) {
		memcpy(op->sym->cipher.iv.data,
		       params->override_iv_ptr,
		       entry->iv.length);
	} else if (entry->iv.data) {
		memcpy(op->sym->cipher.iv.data,
		       entry->iv.data,
		       entry->iv.length);

		op->sym->cipher.iv.phys_addr =
				rte_malloc_virt2phy(op->sym->cipher.iv.data);
		op->sym->cipher.iv.length = entry->iv.length;
	} else {
		rc_cipher = ODP_CRYPTO_ALG_ERR_IV_INVALID;
	}

	/* For SNOW3G algorithms, offset/length must be in bits */
	if (cipher_xform.cipher.algo == RTE_CRYPTO_CIPHER_SNOW3G_UEA2) {
		op->sym->cipher.data.offset = params->cipher_range.offset << 3;
		op->sym->cipher.data.length = params->cipher_range.length << 3;

	} else {
		op->sym->cipher.data.offset = params->cipher_range.offset;
		op->sym->cipher.data.length = params->cipher_range.length;
	}

	if (rc_cipher == ODP_CRYPTO_ALG_ERR_NONE &&
	    rc_auth == ODP_CRYPTO_ALG_ERR_NONE) {
		int queue_pair = odp_cpu_id();

		op->sym->m_src = (struct rte_mbuf *)params->out_pkt;
		rc = rte_cryptodev_enqueue_burst(rte_session->dev_id,
						 queue_pair, &op, 1);
		if (rc == 0) {
			rte_crypto_op_free(op);
			if (pkt_allocated)
				odp_packet_free(params->out_pkt);
			ODP_ERR("Failed to enqueue packet");
			return -1;
		}

		rc = rte_cryptodev_dequeue_burst(rte_session->dev_id,
						 queue_pair, &op, 1);

		if (rc == 0) {
			rte_crypto_op_free(op);
			if (pkt_allocated)
				odp_packet_free(params->out_pkt);
			ODP_ERR("Failed to dequeue packet");
			return -1;
		}

		params->out_pkt = (odp_packet_t)op->sym->m_src;
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

	rte_crypto_op_free(op);

	/* If specified during creation post event to completion queue */
	if (ODP_QUEUE_INVALID != entry->compl_queue) {
		odp_event_t completion_event;
		odp_crypto_generic_op_result_t *op_result;

		completion_event = odp_packet_to_event(params->out_pkt);
		_odp_buffer_event_type_set(
			odp_buffer_from_event(completion_event),
			ODP_EVENT_CRYPTO_COMPL);
		/* Asynchronous, build result (no HW so no errors) and send it*/
		op_result = get_op_result_from_event(completion_event);
		op_result->magic = OP_RESULT_MAGIC;
		op_result->result = local_result;
		if (odp_queue_enq(entry->compl_queue, completion_event)) {
			odp_event_free(completion_event);
			return -1;
		}

		/* Indicate to caller operation was async */
		*posted = 1;
	} else {
		/* Synchronous, simply return results */
		if (!result)
			return -1;
		*result = local_result;

		/* Indicate to caller operation was sync */
		*posted = 0;
	}

	return 0;
}

int odp_crypto_term_global(void)
{
	int rc = 0;
	int ret;
	int count = 0;
	crypto_session_entry_t *session;

	odp_spinlock_init(&global->lock);
	odp_spinlock_lock(&global->lock);
	for (session = global->free; session != NULL; session = session->next)
		count++;
	if (count != MAX_SESSIONS) {
		ODP_ERR("crypto sessions still active\n");
		rc = -1;
	}

	if (global->crypto_op_pool != NULL)
		rte_mempool_free(global->crypto_op_pool);

	odp_spinlock_unlock(&global->lock);

	ret = odp_shm_free(crypto_global_shm);
	if (ret < 0) {
		ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

odp_random_kind_t odp_random_max_kind(void)
{
	return ODP_RANDOM_CRYPTO;
}

int32_t odp_random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	int rc;

	switch (kind) {
	case ODP_RANDOM_BASIC:
		RAND_pseudo_bytes(buf, len);
		return len;

	case ODP_RANDOM_CRYPTO:
		rc = RAND_bytes(buf, len);
		return (1 == rc) ? (int)len /*success*/: -1 /*failure*/;

	case ODP_RANDOM_TRUE:
	default:
		return -1;
	}
}

int32_t odp_random_test_data(uint8_t *buf, uint32_t len, uint64_t *seed)
{
	union {
		uint32_t rand_word;
		uint8_t rand_byte[4];
	} u;
	uint32_t i = 0, j;
	uint32_t seed32 = (*seed) & 0xffffffff;

	while (i < len) {
		u.rand_word = rand_r(&seed32);

		for (j = 0; j < 4 && i < len; j++, i++)
			*buf++ = u.rand_byte[j];
	}

	*seed = seed32;
	return len;
}

odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	if (odp_event_type(ev) != ODP_EVENT_CRYPTO_COMPL)
		ODP_ABORT("Event not a crypto completion");
	return (odp_crypto_compl_t)ev;
}

odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event)
{
	return (odp_event_t)completion_event;
}

void odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			     odp_crypto_op_result_t *result)
{
	odp_event_t ev = odp_crypto_compl_to_event(completion_event);
	odp_crypto_generic_op_result_t *op_result;

	op_result = get_op_result_from_event(ev);

	if (OP_RESULT_MAGIC != op_result->magic)
		ODP_ABORT();

	memcpy(result, &op_result->result, sizeof(*result));
}

void odp_crypto_compl_free(odp_crypto_compl_t completion_event)
{
	_odp_buffer_event_type_set(
		odp_buffer_from_event((odp_event_t)completion_event),
		ODP_EVENT_PACKET);
}

void odp_crypto_session_param_init(odp_crypto_session_param_t *param)
{
	memset(param, 0, sizeof(odp_crypto_session_param_t));
}

uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

uint64_t odp_crypto_compl_to_u64(odp_crypto_compl_t hdl)
{
	return _odp_pri(hdl);
}
