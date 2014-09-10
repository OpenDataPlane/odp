/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ti/drv/nwal/nwal.h>
#include <ti/drv/nwal/nwal_util.h>

#define OP_RESULT_MAGIC 0x91919191

/** Forward declaration of session structure */
struct odp_crypto_session_s;

/**
 * Algorithm handler function prototype
 */
typedef
enum crypto_alg_err (*crypto_func_t)(struct odp_crypto_op_params *params,
				     struct odp_crypto_session_s *session);

#define ODP_CRYPTO_MAX_IV_LENGTH 32

struct iv_full {
	uint8_t data[ODP_CRYPTO_MAX_IV_LENGTH];
	size_t  length;
};


/**
 * Per crypto session data structure
 */
struct odp_crypto_session_s {
	nwal_Handle         dm_handle;
	nwalTxDmPSCmdInfo_t dm_ps_cmdinfo;
	odp_buffer_pool_t   out_pool;
	uint32_t	    out_flow_id;
	odp_queue_t         compl_queue;
	struct {
		enum odp_cipher_alg alg;
		struct iv_full      iv;
	} cipher;

	struct {
		enum odp_auth_alg   alg;
		struct iv_full      iv;
		uint32_t            tag_len;
	} auth;

	uint32_t            index;
	enum odp_crypto_op  op;
};

/**
 * Per packet operation result
 */
struct odp_operation_result_s {
	uint32_t magic;
	struct odp_crypto_compl_status cipher;
	struct odp_crypto_compl_status auth;
};

/**
 * Per session creation operation result
 */
struct odp_session_result_s {
	enum odp_crypto_ses_create_err rc;
	odp_crypto_session_t           session;
};

#ifdef __cplusplus
}
#endif

#endif
