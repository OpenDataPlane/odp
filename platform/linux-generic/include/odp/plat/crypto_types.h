/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_CRYPTO_TYPES_H_
#define ODP_CRYPTO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_crypto
 *  @{
 */

#define ODP_CRYPTO_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t odp_crypto_session_t;
typedef odp_handle_t odp_crypto_compl_t;

enum odp_crypto_op_mode {
	ODP_CRYPTO_SYNC,
	ODP_CRYPTO_ASYNC,
};

enum odp_crypto_op {
	ODP_CRYPTO_OP_ENCODE,
	ODP_CRYPTO_OP_DECODE,
};

enum  odp_cipher_alg {
	ODP_CIPHER_ALG_NULL,
	ODP_CIPHER_ALG_DES,
	ODP_CIPHER_ALG_3DES_CBC,
};

enum odp_auth_alg {
	ODP_AUTH_ALG_NULL,
	ODP_AUTH_ALG_MD5_96,
};

enum odp_crypto_ses_create_err {
	ODP_CRYPTO_SES_CREATE_ERR_NONE,
	ODP_CRYPTO_SES_CREATE_ERR_ENOMEM,
	ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER,
	ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH,
};

enum crypto_alg_err {
	ODP_CRYPTO_ALG_ERR_NONE,
	ODP_CRYPTO_ALG_ERR_DATA_SIZE,
	ODP_CRYPTO_ALG_ERR_KEY_SIZE,
	ODP_CRYPTO_ALG_ERR_ICV_CHECK,
	ODP_CRYPTO_ALG_ERR_IV_INVALID,
};

enum crypto_hw_err {
	ODP_CRYPTO_HW_ERR_NONE,
	ODP_CRYPTO_HW_ERR_DMA,
	ODP_CRYPTO_HW_ERR_BP_DEPLETED,
};

/** Get printable format of odp_crypto_session_t */
static inline uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

/** Get printable format of odp_crypto_compl_t_t */
static inline uint64_t odp_crypto_compl_to_u64(odp_crypto_compl_t hdl)
{
	return _odp_pri(hdl);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
