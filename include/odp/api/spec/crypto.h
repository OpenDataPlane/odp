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

#ifndef ODP_API_CRYPTO_H_
#define ODP_API_CRYPTO_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_crypto ODP CRYPTO
 *  Macros, enums, types and operations to utilise crypto.
 *  @{
 */

/**
 * @def ODP_CRYPTO_SESSION_INVALID
 * Invalid session handle
 */

/**
 * @typedef odp_crypto_session_t
 * Crypto API opaque session handle
 */

/**
 * @typedef odp_crypto_compl_t
* Crypto API completion event (platform dependent).
*/

/**
 * Crypto API operation mode
 */
typedef enum {
	/** Synchronous, return results immediately */
	ODP_CRYPTO_SYNC,
	/** Asynchronous, return results via posted event */
	ODP_CRYPTO_ASYNC,
} odp_crypto_op_mode_t;

/**
 * Crypto API operation type
 */
typedef enum {
	/** Encrypt and/or compute authentication ICV */
	ODP_CRYPTO_OP_ENCODE,
	/** Decrypt and/or verify authentication ICV */
	ODP_CRYPTO_OP_DECODE,
} odp_crypto_op_t;

/**
 * Crypto API cipher algorithm
 */
typedef enum {
	/** No cipher algorithm specified */
	ODP_CIPHER_ALG_NULL,

	/** DES */
	ODP_CIPHER_ALG_DES,

	/** Triple DES with cipher block chaining */
	ODP_CIPHER_ALG_3DES_CBC,

	/** AES with cipher block chaining */
	ODP_CIPHER_ALG_AES_CBC,

	/** AES in Galois/Counter Mode
	 *
	 *  @note Must be paired with cipher ODP_AUTH_ALG_AES_GCM
	 */
	ODP_CIPHER_ALG_AES_GCM,

	/** @deprecated  Use ODP_CIPHER_ALG_AES_CBC instead */
	ODP_CIPHER_ALG_AES128_CBC,

	/** @deprecated  Use ODP_CIPHER_ALG_AES_GCM instead */
	ODP_CIPHER_ALG_AES128_GCM

} odp_cipher_alg_t;

/**
 * Crypto API authentication algorithm
 */
typedef enum {
	 /** No authentication algorithm specified */
	ODP_AUTH_ALG_NULL,

	/** HMAC-MD5
	 *
	 * MD5 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_MD5_HMAC,

	/** HMAC-SHA-256
	 *
	 *  SHA-256 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_SHA256_HMAC,

	/** AES in Galois/Counter Mode
	 *
	 *  @note Must be paired with cipher ODP_CIPHER_ALG_AES_GCM
	 */
	ODP_AUTH_ALG_AES_GCM,

	/** @deprecated  Use ODP_AUTH_ALG_MD5_HMAC instead */
	ODP_AUTH_ALG_MD5_96,

	/** @deprecated  Use ODP_AUTH_ALG_SHA256_HMAC instead */
	ODP_AUTH_ALG_SHA256_128,

	/** @deprecated  Use ODP_AUTH_ALG_AES_GCM instead */
	ODP_AUTH_ALG_AES128_GCM
} odp_auth_alg_t;

/**
 * Cipher algorithms in a bit field structure
 */
typedef union odp_crypto_cipher_algos_t {
	/** Cipher algorithms */
	struct {
		/** ODP_CIPHER_ALG_NULL */
		uint32_t null        : 1;

		/** ODP_CIPHER_ALG_DES */
		uint32_t des         : 1;

		/** ODP_CIPHER_ALG_3DES_CBC */
		uint32_t trides_cbc  : 1;

		/** ODP_CIPHER_ALG_AES_CBC */
		uint32_t aes_cbc     : 1;

		/** ODP_CIPHER_ALG_AES_GCM */
		uint32_t aes_gcm     : 1;

		/** @deprecated  Use aes_cbc instead */
		uint32_t aes128_cbc  : 1;

		/** @deprecated  Use aes_gcm instead */
		uint32_t aes128_gcm  : 1;
	} bit;

	/** All bits of the bit field structure
	  *
	  * This field can be used to set/clear all flags, or bitwise
	  * operations over the entire structure. */
	uint32_t all_bits;
} odp_crypto_cipher_algos_t;

/**
 * Authentication algorithms in a bit field structure
 */
typedef union odp_crypto_auth_algos_t {
	/** Authentication algorithms */
	struct {
		/** ODP_AUTH_ALG_NULL */
		uint32_t null        : 1;

		/** ODP_AUTH_ALG_MD5_HMAC */
		uint32_t md5_hmac    : 1;

		/** ODP_AUTH_ALG_SHA256_HMAC */
		uint32_t sha256_hmac : 1;

		/** ODP_AUTH_ALG_AES_GCM */
		uint32_t aes_gcm     : 1;

		/** @deprecated  Use md5_hmac instead */
		uint32_t md5_96      : 1;

		/** @deprecated  Use sha256_hmac instead */
		uint32_t sha256_128  : 1;

		/** @deprecated  Use aes_gcm instead */
		uint32_t aes128_gcm  : 1;
	} bit;

	/** All bits of the bit field structure
	  *
	  * This field can be used to set/clear all flags, or bitwise
	  * operations over the entire structure. */
	uint32_t all_bits;
} odp_crypto_auth_algos_t;

/**
 * Crypto API key structure
 */
typedef struct odp_crypto_key {
	/** Key data */
	uint8_t *data;

	/** Key length in bytes */
	uint32_t length;

} odp_crypto_key_t;

/**
 * Crypto API IV structure
 */
typedef struct odp_crypto_iv {
	/** IV data */
	uint8_t *data;

	/** IV length in bytes */
	uint32_t length;

} odp_crypto_iv_t;

/**
 * Crypto API data range specifier
 */
typedef struct odp_crypto_data_range {
	/** Offset from beginning of packet */
	uint32_t offset;

	/** Length of data to operate on */
	uint32_t length;

} odp_crypto_data_range_t;

/**
 * Crypto API session creation parameters
 */
typedef struct odp_crypto_session_param_t {
	/** Encode vs. decode operation */
	odp_crypto_op_t op;

	/** Authenticate cipher vs. plain text
	 *
	 *  Controls ordering of authentication and cipher operations,
	 *  and is relative to the operation (encode vs decode). When encoding,
	 *  TRUE indicates the authentication operation should be performed
	 *  after the cipher operation else before. When decoding, TRUE
	 *  indicates the reverse order of operation.
	 *
	 *  true:  Authenticate cipher text
	 *  false: Authenticate plain text
	 */
	odp_bool_t auth_cipher_text;

	/** Preferred sync vs. async */
	odp_crypto_op_mode_t pref_mode;

	/** Cipher algorithm
	 *
	 *  Use odp_crypto_capability() for supported algorithms.
	 */
	odp_cipher_alg_t cipher_alg;

	/** Cipher key
	 *
	 * Use odp_crypto_cipher_capa() for supported key and IV lengths.
	 */
	odp_crypto_key_t cipher_key;

	/** Cipher Initialization Vector (IV) */
	odp_crypto_iv_t iv;

	/** Authentication algorithm
	 *
	 *  Use odp_crypto_capability() for supported algorithms.
	 */
	odp_auth_alg_t auth_alg;

	/** Authentication key
	 *
	 *  Use odp_crypto_auth_capa() for supported digest and key lengths.
	 */
	odp_crypto_key_t auth_key;

	/** Async mode completion event queue
	 *
	 *  When odp_crypto_operation() is asynchronous, the completion queue is
	 *  used to return the completion status of the operation to the
	 *  application.
	 */
	odp_queue_t compl_queue;

	/** Output pool
	 *
	 *  When the output packet is not specified during the call to
	 *  odp_crypto_operation(), the output packet will be allocated
	 *  from this pool.
	 */
	odp_pool_t output_pool;

} odp_crypto_session_param_t;

/** @deprecated  Use odp_crypto_session_param_t instead */
typedef odp_crypto_session_param_t odp_crypto_session_params_t;

/**
 * Crypto API per packet operation parameters
 */
typedef struct odp_crypto_op_param_t {
	/** Session handle from creation */
	odp_crypto_session_t session;

	/** User context */
	void *ctx;

	/** Input packet
	 *
	 *  Specifies the input packet for the crypto operation. When the
	 *  'out_pkt' variable is set to ODP_PACKET_INVALID (indicating a new
	 *  packet should be allocated for the resulting packet).
	 */
	odp_packet_t pkt;

	/** Output packet
	 *
	 *  Both "in place" (the original packet 'pkt' is modified) and
	 *  "copy" (the packet is replicated to a new packet which contains
	 *  the modified data) modes are supported. The "in place" mode of
	 *  operation is indicated by setting 'out_pkt' equal to 'pkt'.
	 *  For the copy mode of operation, setting 'out_pkt' to a valid packet
	 *  value indicates the caller wishes to specify the destination packet.
	 *  Setting 'out_pkt' to ODP_PACKET_INVALID indicates the caller wishes
	 *  the destination packet be allocated from the output pool specified
	 *  during session creation.
	 */
	odp_packet_t out_pkt;

	/** Override session IV pointer */
	uint8_t *override_iv_ptr;

	/** Offset from start of packet for hash result
	 *
	 *  Specifies the offset where the hash result is to be stored. In case
	 *  of decode sessions, input hash values will be read from this offset,
	 *  and overwritten with hash results. If this offset lies within
	 *  specified 'auth_range', implementation will mute this field before
	 *  calculating the hash result.
	 */
	uint32_t hash_result_offset;

	/** Data range to apply cipher */
	odp_crypto_data_range_t cipher_range;

	/** Data range to authenticate */
	odp_crypto_data_range_t auth_range;

} odp_crypto_op_param_t;

/** @deprecated  Use odp_crypto_op_param_t instead */
typedef odp_crypto_op_param_t odp_crypto_op_params_t;

/**
 * Crypto API session creation return code
 */
typedef enum {
	/** Session created */
	ODP_CRYPTO_SES_CREATE_ERR_NONE,
	/** Creation failed, no resources */
	ODP_CRYPTO_SES_CREATE_ERR_ENOMEM,
	/** Creation failed, bad cipher params */
	ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER,
	/** Creation failed, bad auth params */
	ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH,
} odp_crypto_ses_create_err_t;

/**
 * Crypto API algorithm return code
 */
typedef enum {
	/** Algorithm successful */
	ODP_CRYPTO_ALG_ERR_NONE,
	/** Invalid data block size */
	ODP_CRYPTO_ALG_ERR_DATA_SIZE,
	/** Key size invalid for algorithm */
	ODP_CRYPTO_ALG_ERR_KEY_SIZE,
	/** Computed ICV value mismatch */
	ODP_CRYPTO_ALG_ERR_ICV_CHECK,
	/** IV value not specified */
	ODP_CRYPTO_ALG_ERR_IV_INVALID,
} odp_crypto_alg_err_t;

/**
 * Crypto API hardware centric return code
 */
typedef enum {
	/** Operation completed successfully */
	ODP_CRYPTO_HW_ERR_NONE,
	/** Error detected during DMA of data */
	ODP_CRYPTO_HW_ERR_DMA,
	/** Operation failed due to pool depletion */
	ODP_CRYPTO_HW_ERR_BP_DEPLETED,
} odp_crypto_hw_err_t;

/**
 * Cryto API per packet operation completion status
 */
typedef struct odp_crypto_compl_status {
	/** Algorithm specific return code */
	odp_crypto_alg_err_t alg_err;

	/** Hardware specific return code */
	odp_crypto_hw_err_t  hw_err;

} odp_crypto_compl_status_t;

/**
 * Crypto API operation result
 */
typedef struct odp_crypto_op_result {
	/** Request completed successfully */
	odp_bool_t  ok;

	/** User context from request */
	void *ctx;

	/** Output packet */
	odp_packet_t pkt;

	/** Cipher status */
	odp_crypto_compl_status_t cipher_status;

	/** Authentication status */
	odp_crypto_compl_status_t auth_status;

} odp_crypto_op_result_t;

/**
 * Crypto capabilities
 */
typedef struct odp_crypto_capability_t {
	/** Maximum number of crypto sessions */
	uint32_t max_sessions;

	/** Supported cipher algorithms */
	odp_crypto_cipher_algos_t ciphers;

	/** Cipher algorithms implemented with HW offload */
	odp_crypto_cipher_algos_t hw_ciphers;

	/** Supported authentication algorithms */
	odp_crypto_auth_algos_t   auths;

	/** Authentication algorithms implemented with HW offload */
	odp_crypto_auth_algos_t   hw_auths;

} odp_crypto_capability_t;

/**
 * Cipher algorithm capabilities
 */
typedef struct odp_crypto_cipher_capability_t {
	/** Key length in bytes */
	uint32_t key_len;

	/** IV length in bytes */
	uint32_t iv_len;

} odp_crypto_cipher_capability_t;

/**
 * Authentication algorithm capabilities
 */
typedef struct odp_crypto_auth_capability_t {
	/** Digest length in bytes */
	uint32_t digest_len;

	/** Key length in bytes */
	uint32_t key_len;

	/** Additional Authenticated Data (AAD) lengths */
	struct {
		/** Minimum AAD length in bytes */
		uint32_t min;

		/** Maximum AAD length in bytes */
		uint32_t max;

		/** Increment of supported lengths between min and max
		 *  (in bytes) */
		uint32_t inc;
	} aad_len;

} odp_crypto_auth_capability_t;

/**
 * Query crypto capabilities
 *
 * Outputs crypto capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_capability(odp_crypto_capability_t *capa);

/**
 * Query supported cipher algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by key length, then by IV
 * length.
 *
 * @param      cipher       Cipher algorithm
 * @param[out] capa         Array of capability structures for output
 * @param      num          Maximum number of capability structures to output
 *
 * @return Number of capability structures for the algorithm. If this is larger
 *         than 'num', only 'num' first structures were output and application
 *         may call the function again with a larger value of 'num'.
 * @retval <0 on failure
 */
int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t capa[],
				 int num);

/**
 * Query supported authentication algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by digest length, then by key
 * length.
 *
 * @param      auth         Authentication algorithm
 * @param[out] capa         Array of capability structures for output
 * @param      num          Maximum number of capability structures to output
 *
 * @return Number of capability structures for the algorithm. If this is larger
 *         than 'num', only 'num' first structures were output and application
 *         may call the function again with a larger value of 'num'.
 * @retval <0 on failure
 */
int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t capa[], int num);

/**
 * Crypto session creation
 *
 * Create a crypto session according to the session parameters. Use
 * odp_crypto_session_param_init() to initialize parameters into their
 * default values.
 *
 * @param param             Session parameters
 * @param session           Created session else ODP_CRYPTO_SESSION_INVALID
 * @param status            Failure code if unsuccessful
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_create(odp_crypto_session_param_t *param,
			      odp_crypto_session_t *session,
			      odp_crypto_ses_create_err_t *status);

/**
 * Crypto session destroy
 *
 * Destroy an unused session. Result is undefined if session is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param session           Session handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_destroy(odp_crypto_session_t session);

/**
 * Return crypto completion handle that is associated with event
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param ev An event of type ODP_EVENT_CRYPTO_COMPL
 *
 * @return crypto completion handle
 */
odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev);

/**
 * Convert crypto completion handle to event handle
 *
 * @param completion_event  Completion event to convert to generic event
 *
 * @return Event handle
 */
odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event);

/**
 * Release crypto completion event
 *
 * @param completion_event  Completion event we are done accessing
 */
void odp_crypto_compl_free(odp_crypto_compl_t completion_event);

/**
 * Crypto per packet operation
 *
 * Performs the cryptographic operations specified during session creation
 * on the packet.  If the operation is performed synchronously, "posted"
 * will return FALSE and the result of the operation is immediately available.
 * If "posted" returns TRUE the result will be delivered via the completion
 * queue specified when the session was created.
 *
 * @param param             Operation parameters
 * @param posted            Pointer to return posted, TRUE for async operation
 * @param result            Results of operation (when posted returns FALSE)
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_operation(odp_crypto_op_param_t *param,
			 odp_bool_t *posted,
			 odp_crypto_op_result_t *result);

/**
 * Crypto per packet operation query result from completion event
 *
 * @param completion_event  Event containing operation results
 * @param result            Pointer to result structure
 */
void odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			     odp_crypto_op_result_t *result);

/**
 * Get printable value for an odp_crypto_session_t
 *
 * @param hdl  odp_crypto_session_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_crypto_session_t handle.
 */
uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl);

/**
 * Get printable value for an odp_crypto_compl_t
 *
 * @param hdl  odp_crypto_compl_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_crypto_compl_t handle.
 */
uint64_t odp_crypto_compl_to_u64(odp_crypto_compl_t hdl);

/**
 * Initialize crypto session parameters
 *
 * Initialize an odp_crypto_session_param_t to its default values for
 * all fields.
 *
 * @param param   Pointer to odp_crypto_session_param_t to be initialized
 */
void odp_crypto_session_param_init(odp_crypto_session_param_t *param);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
