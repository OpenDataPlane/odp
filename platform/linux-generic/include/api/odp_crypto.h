/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_CRYPTO_H_
#define ODP_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_event.h>
#include <odp_pool.h>
#include <odp_queue.h>
#include <odp_packet.h>

/** @defgroup odp_crypto ODP CRYPTO
 *  Macros, enums, types and operations to utilise crypto.
 *  @{
 */

/** Invalid session handle */
#define ODP_CRYPTO_SESSION_INVALID (0xffffffffffffffffULL)

/**
 * Crypto API opaque session handle
 */
typedef uint64_t odp_crypto_session_t;

/**
 * Crypto API operation mode
 */
enum odp_crypto_op_mode {
	ODP_CRYPTO_SYNC,    /**< Synchronous, return results immediately */
	ODP_CRYPTO_ASYNC,   /**< Aynchronous, return results via posted event */
};

/**
 * Crypto API operation type
 */
enum odp_crypto_op {
	ODP_CRYPTO_OP_ENCODE, /**< Encrypt and/or compute authentication ICV */
	ODP_CRYPTO_OP_DECODE  /**< Decrypt and/or verify authentication ICV */
};

/**
 * Crypto API cipher algorithm
 */
enum  odp_cipher_alg {
	ODP_CIPHER_ALG_NULL,     /**< No cipher algorithm specified */
	ODP_CIPHER_ALG_DES,      /**< DES */
	ODP_CIPHER_ALG_3DES_CBC, /**< Triple DES with cipher block chaining */
};

/**
 * Crypto API authentication algorithm
 */
enum odp_auth_alg {
	ODP_AUTH_ALG_NULL,   /**< No authentication algorithm specified */
	ODP_AUTH_ALG_MD5_96, /**< HMAC-MD5 with 96 bit key */
};

/**
 * Crypto API key structure
 */
typedef struct odp_crypto_key {
	uint8_t *data;       /**< Key data */
	uint32_t length;     /**< Key length in bytes */
} odp_crypto_key_t;

/**
 * Crypto API IV structure
 */
typedef struct odp_crypto_iv {
	uint8_t *data;      /**< IV data */
	uint32_t length;    /**< IV length in bytes */
} odp_crypto_iv_t;

/**
 * Crypto API data range specifier
 */
typedef struct odp_crypto_data_range {
	uint32_t offset;  /**< Offset from beginning of buffer (chain) */
	uint32_t length;  /**< Length of data to operate on */
} odp_crypto_data_range_t;

/**
 * Crypto API session creation paramters
 *
 * @todo Add "odp_session_proc_info_t"
 */
typedef struct odp_crypto_session_params {
	enum odp_crypto_op op;             /**< Encode versus decode */
	bool auth_cipher_text;             /**< Authenticate/cipher ordering */
	enum odp_crypto_op_mode pref_mode; /**< Preferred sync vs async */
	enum odp_cipher_alg cipher_alg;    /**< Cipher algorithm */
	odp_crypto_key_t cipher_key;       /**< Cipher key */
	odp_crypto_iv_t  iv;               /**< Cipher Initialization Vector (IV) */
	enum odp_auth_alg auth_alg;        /**< Authentication algorithm */
	odp_crypto_key_t auth_key;         /**< Authentication key */
	odp_queue_t compl_queue;           /**< Async mode completion event queue */
	odp_buffer_pool_t output_pool;     /**< Output buffer pool */
} odp_crypto_session_params_t;

/**
 * @var odp_crypto_session_params_t::auth_cipher_text
 *
 *   Controls ordering of authentication and cipher operations,
 *   and is relative to the operation (encode vs decode).
 *   When encoding, @c TRUE indicates the authentication operation
 *   should be peformed @b after the cipher operation else before.
 *   When decoding, @c TRUE indicates the reverse order of operation.
 *
 * @var odp_crypto_session_params_t::compl_queue
 *
 *   When the API operates asynchronously, the completion queue is
 *   used to return the completion status of the operation to the
 *   application.
 *
 * @var odp_crypto_session_params_t::output_pool
 *
 *   When the output packet is not specified during the call to
 *   odp_crypto_operation, the output packet buffer will be allocated
 *   from this pool.
 */

/**
 * Crypto API per packet operation parameters
 *
 * @todo Clarify who zero's ICV and how this relates to "hash_result_offset"
 */
typedef struct odp_crypto_op_params {
	odp_crypto_session_t session;   /**< Session handle from creation */
	odp_packet_t pkt;               /**< Input packet buffer */
	odp_packet_t out_pkt;           /**< Output packet buffer */
	uint8_t *override_iv_ptr;       /**< Override session IV pointer */
	uint32_t hash_result_offset;    /**< Offset from start of packet buffer for hash result */
	odp_crypto_data_range_t cipher_range;   /**< Data range to apply cipher */
	odp_crypto_data_range_t auth_range;     /**< Data range to authenticate */
} odp_crypto_op_params_t;

/**
 * @var odp_crypto_op_params_t::pkt
 *   Specifies the input packet buffer for the crypto operation.  When the
 *   @c out_pkt variable is set to @c ODP_PACKET_INVALID (indicating a new
 *   buffer should be allocated for the resulting packet), the \#define TBD
 *   indicates whether the implementation will free the input packet buffer
 *   or if it becomes the responsibility of the caller.
 *
 * @var odp_crypto_op_params_t::out_pkt
 *
 *   The API supports both "in place" (the original packet "pkt" is
 *   modified) and "copy" (the packet is replicated to a new buffer
 *   which contains the modified data).
 *
 *   The "in place" mode of operation is indicated by setting @c out_pkt
 *   equal to @c pkt.  For the copy mode of operation, setting @c out_pkt
 *   to a valid packet buffer value indicates the caller wishes to specify
 *   the destination buffer.  Setting @c out_pkt to @c ODP_PACKET_INVALID
 *   indicates the caller wishes the destination packet buffer be allocated
 *   from the output pool specified during session creation.
 *
 *   @sa odp_crypto_session_params_t::output_pool.
 */

/**
 * Crypto API session creation return code
 */
enum odp_crypto_ses_create_err {
	ODP_CRYPTO_SES_CREATE_ERR_NONE,       /**< Session created */
	ODP_CRYPTO_SES_CREATE_ERR_ENOMEM,     /**< Creation failed, no resources */
	ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER, /**< Creation failed, bad cipher params */
	ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH,   /**< Creation failed, bad auth params */
};

/**
 * Crypto API algorithm return code
 */
enum crypto_alg_err {
	ODP_CRYPTO_ALG_ERR_NONE,      /**< Algorithm successful */
	ODP_CRYPTO_ALG_ERR_DATA_SIZE, /**< Invalid data block size */
	ODP_CRYPTO_ALG_ERR_KEY_SIZE,  /**< Key size invalid for algorithm */
	ODP_CRYPTO_ALG_ERR_ICV_CHECK, /**< Computed ICV value mismatch */
};

/**
 * Crypto API hardware centric return code
 */
enum crypto_hw_err {
	ODP_CRYPTO_HW_ERR_NONE,         /**< Operation completed successfully */
	ODP_CRYPTO_HW_ERR_DMA,          /**< Error detected during DMA of data */
	ODP_CRYPTO_HW_ERR_BP_DEPLETED,  /**< Operation failed due to buffer pool depletion */
};

/**
 * Cryto API per packet operation completion status
 */
typedef struct odp_crypto_compl_status {
	enum crypto_alg_err alg_err;  /**< Algorithm specific return code */
	enum crypto_hw_err  hw_err;   /**< Hardware specific return code */
} odp_crypto_compl_status_t;


/**
 * Crypto session creation (synchronous)
 *
 * @param params            Session parameters
 * @param session           Created session else ODP_CRYPTO_SESSION_INVALID
 * @param status            Failure code if unsuccessful
 *
 * @return 0 if successful else -1
 */
int
odp_crypto_session_create(odp_crypto_session_params_t *params,
			  odp_crypto_session_t *session,
			  enum odp_crypto_ses_create_err *status);


/**
 * Crypto per packet operation
 *
 * Performs the cryptographic operations specified during session creation
 * on the packet.  If the operation is performed synchronously, "posted"
 * will return FALSE and the result of the operation is immediately available
 * in the completion event.  If "posted" returns TRUE the result will be
 * delivered via the completion queue specified when the session was created.
 *
 * @todo Resolve if completion_event is necessary, can/should the output
 *       packet buffer always be used instead.
 *
 * @param params            Operation parameters
 * @param posted            Pointer to return posted, TRUE for async operation
 * @param completion_event  Event by which the operation results are delivered.
 *
 * @return 0 if successful else -1
 */
int
odp_crypto_operation(odp_crypto_op_params_t *params,
		     bool *posted,
		     odp_event_t completion_event);

/**
 * Crypto per packet operation set user context in completion event
 *
 * @param completion_event  Event containing operation results
 * @param ctx               User data
 */
void
odp_crypto_set_operation_compl_ctx(odp_event_t completion_event,
				   void *ctx);

/**
 * Crypto per packet operation completion status
 *
 * Accessor function for obtaining operation status from the completion event.
 *
 * @param completion_event  Event containing operation results
 * @param auth              Pointer to store authentication results
 * @param cipher            Pointer to store cipher results
 */
void
odp_crypto_get_operation_compl_status(odp_event_t completion_event,
				      odp_crypto_compl_status_t *auth,
				      odp_crypto_compl_status_t *cipher);

/**
 * Crypto per packet operation query completed operation packet
 *
 * Accessor function for obtaining current packet buffer, can be
 * different from input packet buffer on some systems
 *
 * @param completion_event  Event containing operation results
 *
 * @return Packet structure where data now resides
 */
odp_packet_t
odp_crypto_get_operation_compl_packet(odp_event_t completion_event);

/**
 * Crypto per packet operation query user context in completion event
 *
 * @param completion_event  Event containing operation results
 *
 * @return User data
 */
void *
odp_crypto_get_operation_compl_ctx(odp_event_t completion_event);

/**
 * Generate random byte string
 *
 * @param buf          Pointer to store result
 * @param len          Pointer to input length value as well as return value
 * @param use_entropy  Use entropy
 *
 * @todo Define the implication of the use_entropy parameter
 *
 * @return 0 if succesful
 */
int
odp_hw_random_get(uint8_t *buf, size_t *len, bool use_entropy);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
