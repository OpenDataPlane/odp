/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_API_SPEC_CRYPTO_H_
#define ODP_API_SPEC_CRYPTO_H_
#include <odp/visibility_begin.h>

#include <odp/api/deprecated.h>
#include <odp/api/packet_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_crypto ODP CRYPTO
 *  Data ciphering and authentication.
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
*  @deprecated Crypto API completion event (platform dependent).
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

	/** Triple DES with Electronic Codebook */
	ODP_CIPHER_ALG_3DES_ECB,

	/** AES with cipher block chaining */
	ODP_CIPHER_ALG_AES_CBC,

	/** AES with counter mode */
	ODP_CIPHER_ALG_AES_CTR,

	/** AES with electronic codebook */
	ODP_CIPHER_ALG_AES_ECB,

	/** AES with 128-bit cipher feedback */
	ODP_CIPHER_ALG_AES_CFB128,

	/** AES with XEX-based tweaked-codebook mode with ciphertext stealing
	 * (XTS) */
	ODP_CIPHER_ALG_AES_XTS,

	/** AES-GCM
	 *
	 *  AES in Galois/Counter Mode (GCM) algorithm. GCM provides both
	 *  authentication and ciphering of data (authenticated encryption)
	 *  in the same operation. Hence this algorithm must be paired always
	 *  with ODP_AUTH_ALG_AES_GCM authentication.
	 */
	ODP_CIPHER_ALG_AES_GCM,

	/** AES-CCM
	 *
	 *  AES in Counter with CBC-MAC (CCM) mode algorithm. CCM provides both
	 *  authentication and ciphering of data (authenticated encryption)
	 *  in the same operation. Hence this algorithm must be paired always
	 *  with ODP_AUTH_ALG_AES_CCM authentication.
	 */
	ODP_CIPHER_ALG_AES_CCM,

	/** ChaCha20-Poly1305
	 *
	 *  ChaCha20 with Poly1305 provide both authentication and ciphering of
	 *  data (authenticated encryption) in the same operation. Hence this
	 *  algorithm must be paired always with ODP_AUTH_ALG_CHACHA20_POLY1305
	 *  authentication.
	 */
	ODP_CIPHER_ALG_CHACHA20_POLY1305,

	/** Confidentiality F8 algorithm (UEA1)
	 *
	 *  KASUMI-based F8 algorithm (also known as UEA1).
	 *
	 *  IV should be formatted according to the 3GPP TS 35.201:
	 *  COUNT || BEARER || DIRECTION || 0...0
	 */
	ODP_CIPHER_ALG_KASUMI_F8,

	/** Confidentiality UEA2 algorithm (128-EEA1)
	 *
	 *  SNOW 3G-based UEA2 algorithm (also known as 128-EEA1).
	 *
	 *  IV (128 bit) should be formatted according to the ETSI/SAGE
	 *  UEA2 & UIA2 specification:
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 */
	ODP_CIPHER_ALG_SNOW3G_UEA2,

	/** Confidentiality 128-EEA2 algorithm
	 *
	 *  AES-CTR-based 128-EEA2 algorithm.
	 *
	 *  IV (128 bit) should be formatted according to the ETSI/SAGE
	 *  128-EA2 & 128-EIA2 specification:
	 *  COUNT || BEARER ||
	 *  DIRECTION || 0....0
	 */
	ODP_CIPHER_ALG_AES_EEA2,

	/** Confidentiality 128-EEA3 algorithm
	 *
	 *  ZUC-based 128-EEA3 algorithm.
	 *
	 *  IV (128 bit) should be formatted according to the ETSI/SAGE
	 *  128-EEA3 & 128-EIA3 specification:
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 */
	ODP_CIPHER_ALG_ZUC_EEA3,

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

	/** HMAC-SHA-1
	 *
	 *  SHA-1 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_SHA1_HMAC,

	/** HMAC-SHA-224
	 *
	 *  SHA-224 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_SHA224_HMAC,

	/** HMAC-SHA-256
	 *
	 *  SHA-256 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_SHA256_HMAC,

	 /** HMAC-SHA-384
	 *
	 *  SHA-384 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_SHA384_HMAC,

	/** HMAC-SHA-512
	 *
	 *  SHA-512 algorithm in HMAC mode
	 */
	ODP_AUTH_ALG_SHA512_HMAC,

	/** AES-GCM
	 *
	 *  AES in Galois/Counter Mode (GCM) algorithm. GCM provides both
	 *  authentication and ciphering of data (authenticated encryption)
	 *  in the same operation. Hence this algorithm must be paired always
	 *  with ODP_CIPHER_ALG_AES_GCM cipher.
	 */
	ODP_AUTH_ALG_AES_GCM,

	/** AES-GMAC
	 *
	 *  AES Galois Message Authentication Code (GMAC) algorithm. AES-GMAC
	 *  is based on AES-GCM operation, but provides authentication only.
	 *  Hence this algorithm can be paired only with ODP_CIPHER_ALG_NULL
	 *  cipher.
	 *
	 *  NIST and RFC specifications of GMAC refer to all data to be
	 *  authenticated as AAD. In ODP the data to be authenticated, i.e.
	 *  AAD, is ODP packet data and specified using the auth_range
	 *  parameter. The aad_length and aad_ptr parameters, which would
	 *  require the data to be contiguous in memory, are ignored with
	 *  AES-GMAC.
	 *
	 *  GMAC needs an initialization vector, which can be passed via
	 *  session (auth_iv) or packet (auth_iv_ptr) level parameters.
	 */
	ODP_AUTH_ALG_AES_GMAC,

	/** AES-CCM
	 *
	 *  AES in Counter with CBC-MAC (CCM) mode algorithm. CCM provides both
	 *  authentication and ciphering of data (authenticated encryption)
	 *  in the same operation. Hence this algorithm must be paired always
	 *  with ODP_CIPHER_ALG_AES_CCM cipher.
	 */
	ODP_AUTH_ALG_AES_CCM,

	/** AES-CMAC
	 *
	 *  AES Cipher-based Message Authentication Code (CMAC) algorithm. CMAC
	 *  is a keyed hash function that is based on a symmetric key block
	 *  cipher, such as the AES.
	 */
	ODP_AUTH_ALG_AES_CMAC,

	/** AES-XCBC-MAC
	 *
	 *  AES CBC MAC for arbitrary-length messages (XCBC-MAC).
	 *
	 */
	ODP_AUTH_ALG_AES_XCBC_MAC,

	/** ChaCha20-Poly1305 AEAD
	 *
	 *  ChaCha20 with Poly1305 provide both authentication and ciphering of
	 *  data (authenticated encryption) in the same operation. Hence this
	 *  algorithm must be paired always with
	 *  ODP_CIPHER_ALG_CHACHA20_POLY1305 cipher.
	 */
	ODP_AUTH_ALG_CHACHA20_POLY1305,

	/** Integrity F9 algorithm (UIA1)
	 *
	 *  KASUMI-based F9 algorithm (also known as UIA1).
	 *
	 *  IV (9 bytes) is a concatenation of COUNT (32b), FRESH (32b) and
	 *  DIRECTION (LSB-aligned, 1b).
	 *  IV (8 bytes) is a concatenation of COUNT (32b) and FRESH (32b)
	 *  DIRECTION (1b) and padding should come at the end of message.
	 */
	ODP_AUTH_ALG_KASUMI_F9,

	/** Integrity UIA2 algorithm (128-EIA1)
	 *
	 *  SNOW 3G-based UIA2 algorithm (also known as 128-EIA1).
	 *  IV (128 bit) should be formatted according to the ETSI/SAGE
	 *  UEA2 & UIA2 specification:
	 *  COUNT || FRESH ||
	 *  DIRECTION XOR COUNT0 || COUNT1 .. COUNT31 ||
	 *  FRESH0 .. FRESH15 || FRESH16 XOR DIRECTION || FRESH17 .. FRESH31
	 */
	ODP_AUTH_ALG_SNOW3G_UIA2,

	/** Integrity 128-EIA2 algorithm
	 *
	 *  AES_CMAC-based 128-EIA2 algorithm.
	 *
	 *  IV (128 bit) should be formatted according to the ETSI/SAGE
	 *  128-EA2 & 128-EIA2 specification:
	 *  COUNT || BEARER ||
	 *  DIRECTION || 0....0
	 */
	ODP_AUTH_ALG_AES_EIA2,

	/** Integrity 128-EIA3 algorithm
	 *
	 *  ZUC-based 128-EIA3 algorithm.
	 *
	 *  IV (128 bit) should be formatted according to the ETSI/SAGE
	 *  128-EA3 & 128-EIA2 specification:
	 *  COUNT || BEARER ||
	 *  DIRECTION XOR COUNT0 || COUNT1 .. COUNT31 ||
	 *  BEARER || 0...0 || DIRECTION || 0...0
	 */
	ODP_AUTH_ALG_ZUC_EIA3,

	/** MD5 algorithm */
	ODP_AUTH_ALG_MD5,

	/** SHA1 algorithm */
	ODP_AUTH_ALG_SHA1,

	/** 224 bit SHA2 algorithm */
	ODP_AUTH_ALG_SHA224,

	/** 256 bit SHA2 algorithm */
	ODP_AUTH_ALG_SHA256,

	/** 384 bit SHA2 algorithm */
	ODP_AUTH_ALG_SHA384,

	/** 512 bit SHA2 algorithm */
	ODP_AUTH_ALG_SHA512,

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

		/** ODP_CIPHER_ALG_3DES_ECB */
		uint32_t trides_ecb : 1;

		/** ODP_CIPHER_ALG_AES_CBC */
		uint32_t aes_cbc     : 1;

		/** ODP_CIPHER_ALG_AES_CTR */
		uint32_t aes_ctr     : 1;

		/** ODP_CIPHER_ALG_AES_ECB */
		uint32_t aes_ecb     : 1;

		/** ODP_CIPHER_ALG_AES_CFB128 */
		uint32_t aes_cfb128  : 1;

		/** ODP_CIPHER_ALG_AES_XTS */
		uint32_t aes_xts     : 1;

		/** ODP_CIPHER_ALG_AES_GCM */
		uint32_t aes_gcm     : 1;

		/** ODP_CIPHER_ALG_AES_CCM */
		uint32_t aes_ccm     : 1;

		/** ODP_CIPHER_ALG_CHACHA20_POLY1305 */
		uint32_t chacha20_poly1305 : 1;

		/** ODP_CIPHER_ALG_KASUMI_F8 */
		uint32_t kasumi_f8   : 1;

		/** ODP_CIPHER_ALG_SNOW3G_UEA2 */
		uint32_t snow3g_uea2 : 1;

		/** ODP_CIPHER_ALG_AES_EEA2 */
		uint32_t aes_eea2 : 1;

		/** ODP_CIPHER_ALG_ZUC_EEA3 */
		uint32_t zuc_eea3    : 1;

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

		/** ODP_AUTH_ALG_SHA1_HMAC */
		uint32_t sha1_hmac : 1;

		/** ODP_AUTH_ALG_SHA224_HMAC */
		uint32_t sha224_hmac : 1;

		/** ODP_AUTH_ALG_SHA256_HMAC */
		uint32_t sha256_hmac : 1;

		/** ODP_AUTH_ALG_SHA384_HMAC */
		uint32_t sha384_hmac : 1;

		/** ODP_AUTH_ALG_SHA512_HMAC */
		uint32_t sha512_hmac : 1;

		/** ODP_AUTH_ALG_AES_GCM */
		uint32_t aes_gcm     : 1;

		/** ODP_AUTH_ALG_AES_GMAC*/
		uint32_t aes_gmac    : 1;

		/** ODP_AUTH_ALG_AES_CCM */
		uint32_t aes_ccm     : 1;

		/** ODP_AUTH_ALG_AES_CMAC*/
		uint32_t aes_cmac    : 1;

		/** ODP_AUTH_ALG_AES_XCBC_MAC*/
		uint32_t aes_xcbc_mac    : 1;

		/** ODP_AUTH_ALG_CHACHA20_POLY1305 */
		uint32_t chacha20_poly1305 : 1;

		/** ODP_AUTH_ALG_KASUMI_F9 */
		uint32_t kasumi_f9   : 1;

		/** ODP_AUTH_ALG_SNOW3G_UIA2 */
		uint32_t snow3g_uia2 : 1;

		/** ODP_AUTH_ALG_AES_EIA2 */
		uint32_t aes_eia2 : 1;

		/** ODP_AUTH_ALG_ZUC_EIA3 */
		uint32_t zuc_eia3    : 1;

		/** ODP_AUTH_ALG_MD5 */
		uint32_t md5 : 1;

		/** ODP_AUTH_ALG_SHA1 */
		uint32_t sha1 : 1;

		/** ODP_AUTH_ALG_SHA224 */
		uint32_t sha224 : 1;

		/** ODP_AUTH_ALG_SHA256 */
		uint32_t sha256 : 1;

		/** ODP_AUTH_ALG_SHA384 */
		uint32_t sha384 : 1;

		/** ODP_AUTH_ALG_SHA512 */
		uint32_t sha512 : 1;

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
 *
 * @deprecated
 */
typedef struct odp_crypto_iv {
	/** IV data
	 *
	 *  Ignored when length is zero. Null value indicates that an
	 *  IV will be provided for each packet through the crypto
	 *  operation parameters. In that case the per-operation
	 *  IV parameter must always point to a valid IV.
	 *
	 *  Default value is NULL.
	 */
	uint8_t *data;

	/** IV length in bytes. Default value is zero. */
	uint32_t length;

} ODP_DEPRECATE(odp_crypto_iv_t);

/**
 * Crypto API session creation parameters
 */
typedef struct odp_crypto_session_param_t {
	/** Encode vs. decode operation
	 *
	 *  The default value is ODP_CRYPTO_OP_ENCODE.
	 */
	odp_crypto_op_t op;

	/** Authenticate cipher vs. plain text
	 *
	 *  Controls ordering of authentication and cipher operations,
	 *  and is relative to the operation (encode vs decode). When encoding,
	 *  TRUE indicates the authentication operation should be performed
	 *  after the cipher operation else before. When decoding, TRUE
	 *  indicates the reverse order of operation.
	 *
	 *  The value is ignored with authenticated encryption algorithms
	 *  such as AES-GCM.
	 *
	 *  true:  Authenticate cipher text
	 *  false: Authenticate plain text
	 *
	 *  The default value is false.
	 */
	odp_bool_t auth_cipher_text;

	/** Hash result location may overlap authentication range
	 *
	 *  This flag indicates that the hash result location may (but is
	 *  not required to) overlap authentication range. Setting this
	 *  flag may reduce performance.
	 *
	 *  Default value is false.
	 */
	odp_bool_t hash_result_in_auth_range;

	/** Preferred sync vs. async for odp_crypto_operation()
	 *
	 *  The default value is ODP_CRYPTO_SYNC.
	 *
	 *  @deprecated Used only with deprecated odp_crypto_operation()
	 */
	odp_crypto_op_mode_t ODP_DEPRECATE(pref_mode);

	/** Operation mode when using packet interface: sync or async
	 *
	 *  The default value is ODP_CRYPTO_SYNC.
	 */
	odp_crypto_op_mode_t op_mode;

	/** Cipher algorithm
	 *
	 *  Select cipher algorithm to be used. ODP_CIPHER_ALG_NULL indicates
	 *  that ciphering is disabled. Use odp_crypto_capability() for
	 *  supported algorithms. Note that some algorithms restrict choice of
	 *  the pairing authentication algorithm. When ciphering is enabled
	 *  cipher key and IV need to be set. The default value is
	 *  ODP_CIPHER_ALG_NULL.
	 */
	odp_cipher_alg_t cipher_alg;

	/** Cipher key
	 *
	 * Use odp_crypto_cipher_capa() for supported key and IV lengths.
	 */
	odp_crypto_key_t cipher_key;

	/** Cipher Initialization Vector (IV)
	 *
	 *  Unless using the deprecated API, this specifies the length of
	 *  the IV only. The actual IV must then be provided in per-packet
	 *  parameters of crypto operations.
	 */
	union {
#if ODP_DEPRECATED_API
		/** Cipher Initialization Vector (IV) */
		odp_crypto_iv_t ODP_DEPRECATE(cipher_iv);
#endif
		/** Cipher IV length */
		struct {
#if ODP_DEPRECATED_API
			/** Unused padding field */
			uint8_t *dummy_padding_0;
#endif
			/** Length of cipher initialization vector.
			 *  Default value is zero.
			 */
			uint32_t cipher_iv_len;
		};
	};

	/** Authentication algorithm
	 *
	 *  Select authentication algorithm to be used. ODP_AUTH_ALG_NULL
	 *  indicates that authentication is disabled. Use
	 *  odp_crypto_capability() for supported algorithms. Note that some
	 *  algorithms restrict choice of the pairing cipher algorithm. When
	 *  single algorithm provides both ciphering and authentication
	 *  (i.e. Authenticated Encryption), authentication side key
	 *  (auth_key) and IV (auth_iv) are ignored, and cipher side values are
	 *  used instead. These algorithms ignore authentication side key
	 *  and IV: ODP_AUTH_ALG_AES_GCM, ODP_AUTH_ALG_AES_CCM and
	 *  ODP_AUTH_ALG_CHACHA20_POLY1305. Otherwise, all authentication side
	 *  parameters must be set when authentication is enabled. The default
	 *  value is ODP_AUTH_ALG_NULL.
	 */
	odp_auth_alg_t auth_alg;

	/** Authentication key
	 *
	 *  Use odp_crypto_auth_capability() for supported key lengths.
	 */
	odp_crypto_key_t auth_key;

	/** Authentication Initialization Vector (IV)
	 *
	 *  Unless using the deprecated API, this specifies the length of
	 *  the IV only. The actual IV must then be provided in per-packet
	 *  parameters of crypto operations.
	 */
	union {
#if ODP_DEPRECATED_API
		odp_crypto_iv_t ODP_DEPRECATE(auth_iv);
#endif
		/** Authentication IV length */
		struct {
#if ODP_DEPRECATED_API
			/** Unused padding field */
			uint8_t *dummy_padding_1;
#endif
			/** Length of authentication initialization vector.
			 *  Default value is zero.
			 */
			uint32_t auth_iv_len;
		};
	};

	/** Authentication digest length in bytes
	 *
	 *  Use odp_crypto_auth_capability() for supported digest lengths.
	 */
	uint32_t auth_digest_len;

	/** Additional Authenticated Data (AAD) length in bytes
	 *
	 *  AAD length is constant for all operations (packets) of the session.
	 *  Set to zero when AAD is not used. Use odp_crypto_auth_capability()
	 *  for supported AAD lengths. The default value is zero.
	 */
	uint32_t auth_aad_len;

	/** Async mode completion event queue
	 *
	 *  The completion queue is used to return completions from
	 *  odp_crypto_op_enq() (and the deprecated odp_crypto_operation())
	 *  to the application.
	 */
	odp_queue_t compl_queue;

	/** Output pool
	 *
	 *  When the output packet is not specified during the call to
	 *  crypto operation, the output packet will be allocated
	 *  from this pool.
	 */
	odp_pool_t output_pool;

} odp_crypto_session_param_t;

/**
 * Crypto API per packet operation parameters
 *
 * @deprecated Use odp_crypto_packet_op_param_t instead.
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

	/** IV pointer for cipher */
	uint8_t *cipher_iv_ptr;

	/** Authentication IV pointer */
	uint8_t *auth_iv_ptr;

	/** Offset from start of packet for hash result
	 *
	 *  In case of decode sessions, the expected hash will be read from
	 *  this offset and compared with the calculated hash. After the
	 *  operation the hash bytes will have undefined values.
	 *
	 *  In case of encode sessions the calculated hash will be stored in
	 *  this offset.
	 *
	 *  If the hash_result_in_auth_range session parameter is true,
	 *  the hash result location may overlap auth_range. In that case
	 *  the result location will be zeroed in decode sessions before
	 *  hash calculation. Zeroing is not done in encode sessions.
	 */
	uint32_t hash_result_offset;

	/** Pointer to AAD. AAD length is defined by 'auth_aad_len'
	 *  session parameter.
	 */
	uint8_t *aad_ptr;

	/** Data range to be ciphered */
	odp_packet_data_range_t cipher_range;

	/** Data range to be authenticated
	 *
	 *  The value is ignored with authenticated encryption algorithms,
	 *  such as AES-GCM, which authenticate data in the cipher range
	 *  and the AAD.
	 *
	 *  As a special case AES-GMAC uses this field instead of aad_ptr
	 *  for the data bytes to be authenticated.
	 */
	odp_packet_data_range_t auth_range;

} ODP_DEPRECATE(odp_crypto_op_param_t);

/**
 * Crypto packet API per packet operation parameters
 */
typedef struct odp_crypto_packet_op_param_t {
	/** Session handle from creation */
	odp_crypto_session_t session;

	/** IV pointer for cipher */
	uint8_t *cipher_iv_ptr;

	/** IV pointer for authentication */
	uint8_t *auth_iv_ptr;

	/** Offset from start of packet for hash result
	 *
	 *  In case of decode sessions, the expected hash will be read from
	 *  this offset and compared with the calculated hash. After the
	 *  operation the hash bytes will have undefined values.
	 *
	 *  In case of encode sessions the calculated hash will be stored in
	 *  this offset.
	 *
	 *  If the hash_result_not_in_auth_range session parameter is false,
	 *  the hash result location may overlap auth_range. In that case the
	 *  result location will be zeroed in decode sessions before hash
	 *  calculation. Zeroing is not done in encode sessions.
	 */
	uint32_t hash_result_offset;

	/** Pointer to AAD. AAD length is defined by 'auth_aad_len'
	 *  session parameter.
	 */
	uint8_t *aad_ptr;

	/** Data range to apply cipher */
	odp_packet_data_range_t cipher_range;

	/** Data range to authenticate */
	odp_packet_data_range_t auth_range;

} odp_crypto_packet_op_param_t;

/**
 * Crypto API session creation return code
 */
typedef enum {
	/** Session created */
	ODP_CRYPTO_SES_ERR_NONE,
	/** Creation failed, no resources */
	ODP_CRYPTO_SES_ERR_ENOMEM,
	/** Creation failed, bad cipher params */
	ODP_CRYPTO_SES_ERR_CIPHER,
	/** Creation failed, bad auth params */
	ODP_CRYPTO_SES_ERR_AUTH,

	/** Unsupported combination of algorithms
	 *
	 *  The combination of cipher and auth algorithms with their
	 *  specific parameters is not supported even if the algorithms
	 *  appear in capabilities and are supported in combination with
	 *  other algorithms or other algorithm specific parameters.
	 */
	ODP_CRYPTO_SES_ERR_ALG_COMBO,

	/** Unsupported order of cipher and auth
	 *
	 *  The requested mutual order of ciphering and authentication
	 *  is not supported with the chosen individual cipher and
	 *  authentication algorithms.
	 */
	ODP_CRYPTO_SES_ERR_ALG_ORDER,

	/** Unsupported combination of session creation parameters
	 *
	 *  The combination of provided session creation parameters is not
	 *  supported. This error can occur when there are limitations that
	 *  are not expressible through crypto capabilities or other error
	 *  status values.
	 */
	ODP_CRYPTO_SES_ERR_PARAMS,
} odp_crypto_ses_create_err_t;

/** This synonym for backward compatibility will be deprecated later */
#define ODP_CRYPTO_SES_CREATE_ERR_NONE       ODP_CRYPTO_SES_ERR_NONE
/** This synonym for backward compatibility will be deprecated later */
#define ODP_CRYPTO_SES_CREATE_ERR_ENOMEM     ODP_CRYPTO_SES_ERR_ENOMEM
/** This synonym for backward compatibility will be deprecated later */
#define ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER ODP_CRYPTO_SES_ERR_CIPHER
/** This synonym for backward compatibility will be deprecated later */
#define ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH   ODP_CRYPTO_SES_ERR_AUTH

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
typedef struct odp_crypto_op_status {
	/** Algorithm specific return code */
	odp_crypto_alg_err_t alg_err;

	/** Hardware specific return code */
	odp_crypto_hw_err_t  hw_err;

} odp_crypto_op_status_t;

/**
 * Crypto API operation result
 *
 * @deprecated Use odp_crypto_packet_result_t instead.
 */
typedef struct odp_crypto_op_result {
	/** Request completed successfully */
	odp_bool_t  ok;

	/** User context from request */
	void *ctx;

	/** Output packet */
	odp_packet_t pkt;

	/** Cipher status */
	odp_crypto_op_status_t cipher_status;

	/** Authentication status */
	odp_crypto_op_status_t auth_status;

} ODP_DEPRECATE(odp_crypto_op_result_t);

/**
 * Crypto packet API operation result
 */
typedef struct odp_crypto_packet_result_t {
	/** Request completed successfully */
	odp_bool_t  ok;

	/** Cipher status */
	odp_crypto_op_status_t cipher_status;

	/** Authentication status */
	odp_crypto_op_status_t auth_status;

} odp_crypto_packet_result_t;

/**
 * Crypto capabilities
 */
typedef struct odp_crypto_capability_t {
	/** Maximum number of crypto sessions */
	uint32_t max_sessions;

	/** Supported packet operation in SYNC mode */
	odp_support_t sync_mode;

	/** Supported packet operation in ASYNC mode */
	odp_support_t async_mode;

	/** Supported cipher algorithms */
	odp_crypto_cipher_algos_t ciphers;

	/** Cipher algorithms implemented with HW offload */
	odp_crypto_cipher_algos_t hw_ciphers;

	/** Supported authentication algorithms */
	odp_crypto_auth_algos_t   auths;

	/** Authentication algorithms implemented with HW offload */
	odp_crypto_auth_algos_t   hw_auths;

	/**
	 * Scheduled crypto completion queue support
	 *
	 * This defines whether scheduled queues are supported as crypto
	 * compl_queue.
	 * 0: Scheduled queues are not supported as crypto completion queues
	 * 1: Scheduled queues are supported as crypto completion queues
	 * @see odp_crypto_session_param_t
	 */
	odp_bool_t queue_type_sched;

	/**
	 * Plain crypto completion queue support
	 *
	 * This defines whether plain queues are supported as crypto
	 * compl_queue.
	 * 0: Plain queues are not supported as crypto completion queues
	 * 1: Plain queues are supported as crypto completion queues
	 * @see odp_crypto_session_param_t
	 */
	odp_bool_t queue_type_plain;
} odp_crypto_capability_t;

/**
 * Cipher algorithm capabilities
 */
typedef struct odp_crypto_cipher_capability_t {
	/** Key length in bytes */
	uint32_t key_len;

	/** IV length in bytes */
	uint32_t iv_len;

	/** Cipher is operating in bitwise mode
	 *
	 * This cipher works on series of bits, rather than sequences of bytes:
	 * cipher_range in odp_crypto_op_param_t and
	 * odp_crypto_packet_op_param_t will use bits, rather than bytes.
	 *
	 * Note: data buffer MUST start on the byte boundary, using offset
	 * which is not divisible by 8 is unsupported and will result in
	 * unspecified behaviour.
	 *
	 * Note2: If the data length is not a multiple of 8, the remaining
	 * bits of the data in the last byte of the input/output will be the
	 * most significant bits, i.e. the most significant bit is considered
	 * to be the first bit of a byte for the purpose of input and output
	 * data range. The output bits that fall out of the output range are
	 * undefined.
	 */
	odp_bool_t bit_mode;

} odp_crypto_cipher_capability_t;

/**
 * Authentication algorithm capabilities
 */
typedef struct odp_crypto_auth_capability_t {
	/** Digest length in bytes */
	uint32_t digest_len;

	/** Key length in bytes */
	uint32_t key_len;

	/** IV length in bytes */
	uint32_t iv_len;

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

	/** Auth is operating in bitstring mode
	 *
	 * This auth works on series of bits, rather than sequences of bytes:
	 * auth_range in odp_crypto_op_param_t and
	 * odp_crypto_packet_op_param_t will use bits, rather than bytes.
	 *
	 * Note: data buffer MUST start on the byte boundary, using offset
	 * which is not divisible by 8 is unsupported and will result in
	 * unpredictable behaviour.
	 *
	 * Note2: If the data length is not a multiple of 8, the remaining
	 * bits of the data in the last byte of the input/output will be the
	 * most significant bits, i.e. the most significant bit is considered
	 * to be the first bit of a byte for the purpose of input and output
	 * data range. The output bits that fall out of the output range are
	 * undefined.
	 */
	odp_bool_t bit_mode;

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
 * default values. If call ends up with an error no new session will be
 * created.
 *
 * The parameter structure as well as the key and IV data pointed to by it
 * can be freed after the call.
 *
 * @param      param        Session parameters
 * @param[out] session      Created session else ODP_CRYPTO_SESSION_INVALID
 * @param[out] status       Failure code if unsuccessful
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_create(const odp_crypto_session_param_t *param,
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

#if ODP_DEPRECATED_API

/**
 * Return crypto completion handle that is associated with event
 *
 * @deprecated Used only with the deprecated odp_crypto_operation()
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
 * @deprecated Used only with the deprecated odp_crypto_operation()
 *
 * @param completion_event  Completion event to convert to generic event
 *
 * @return Event handle
 */
odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event);

/**
 * Release crypto completion event
 *
 * @deprecated Used only with the deprecated odp_crypto_operation()
 *
 * @param completion_event  Completion event we are done accessing
 */
void odp_crypto_compl_free(odp_crypto_compl_t completion_event);

/**
 * Crypto per packet operation
 *
 * @deprecated Use odp_crypto_op() or odp_crypto_op_enq() instead.
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
 * @deprecated Used only with the deprecated odp_crypto_operation()
 *
 * @param completion_event  Event containing operation results
 * @param result            Pointer to result structure
 */
void odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			     odp_crypto_op_result_t *result);

#endif /* ODP_DEPRECATED_API */

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

#if ODP_DEPRECATED_API
/**
 * Get printable value for an odp_crypto_compl_t
 *
 * @deprecated Used only with the deprecated odp_crypto_operation()
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
#endif

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
 * Return crypto processed packet that is associated with event
 *
 * Get packet handle to an crypto processed packet event. Event subtype must be
 * ODP_EVENT_PACKET_CRYPTO. Crypto operation results can be examined with
 * odp_crypto_result().
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param ev       Event handle
 *
 * @return Packet handle
 */
odp_packet_t odp_crypto_packet_from_event(odp_event_t ev);

/**
 * Convert crypto packet handle to event
 *
 * The packet handle must be an output of an crypto operation.
 *
 * @param pkt      Packet handle from crypto operation
 *
 * @return Event handle
 */
odp_event_t odp_crypto_packet_to_event(odp_packet_t pkt);

/**
 * Get crypto operation results from an crypto processed packet
 *
 * Successful crypto operations of all types (SYNC and ASYNC) produce packets
 * which contain crypto result metadata. This function copies the operation
 * results from an crypto processed packet. Event subtype of this kind of
 * packet is ODP_EVENT_PACKET_CRYPTO. Results are undefined if a non-crypto
 * processed packet is passed as input.
 *
 * @param         packet  An crypto processed packet (ODP_EVENT_PACKET_CRYPTO)
 * @param[out]    result  Pointer to operation result for output
 *
 * @retval  0     On success
 * @retval <0     On failure
 */
int odp_crypto_result(odp_crypto_packet_result_t *result,
		      odp_packet_t packet);

/**
 * Crypto packet operation
 *
 * Performs the SYNC cryptographic operations specified during session creation
 * on the packets. Caller should initialize pkt_out either with desired output
 * packet handles or with ODP_PACKET_INVALID to make ODP allocate new packets
 * from provided pool. All arrays should be of num_pkt size.
 *
 * @param         pkt_in   Packets to be processed
 * @param[in,out] pkt_out  Packet handle array specifyint resulting packets
 * @param         param    Operation parameters array
 * @param         num_pkt  Number of packets to be processed
 *
 * @return Number of input packets consumed (0 ... num_pkt)
 * @retval <0 on failure
 */
int odp_crypto_op(const odp_packet_t pkt_in[],
		  odp_packet_t pkt_out[],
		  const odp_crypto_packet_op_param_t param[],
		  int num_pkt);

/**
 * Crypto packet operation
 *
 * Performs the ASYNC cryptographic operations specified during session creation
 * on the packets. Caller should initialize pkt_out either with desired output
 * packet handles or with ODP_PACKET_INVALID to make ODP allocate new packets
 * from provided pool. All arrays should be of num_pkt size. Resulting packets
 * are returned through events.
 *
 * @param pkt_in   Packets to be processed
 * @param pkt_out  Packet handle array specifying resulting packets
 * @param param    Operation parameters array
 * @param num_pkt  Number of packets to be processed
 *
 * @return Number of input packets consumed (0 ... num_pkt)
 * @retval <0 on failure
 */
int odp_crypto_op_enq(const odp_packet_t pkt_in[],
		      const odp_packet_t pkt_out[],
		      const odp_crypto_packet_op_param_t param[],
		      int num_pkt);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
