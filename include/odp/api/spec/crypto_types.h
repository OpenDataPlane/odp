/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

/**
 * @file
 *
 * ODP crypto types */

#ifndef ODP_API_SPEC_CRYPTO_TYPES_H_
#define ODP_API_SPEC_CRYPTO_TYPES_H_
#include <odp/visibility_begin.h>

#include <odp/api/deprecated.h>
#include <odp/api/packet_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_crypto
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
 * Crypto API operation mode
 */
typedef enum {
	/** Synchronous, return results immediately */
	ODP_CRYPTO_SYNC,
	/** Asynchronous, return results via posted event */
	ODP_CRYPTO_ASYNC,
} odp_crypto_op_mode_t;

/**
 * Crypto API operation
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
	 *  IV (128 bits) should be formatted according to the ETSI/SAGE
	 *  UEA2 & UIA2 specification:
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 */
	ODP_CIPHER_ALG_SNOW3G_UEA2,

	/** Confidentiality 128-EEA2 algorithm
	 *
	 *  AES-CTR-based 128-EEA2 algorithm.
	 *
	 *  IV (128 bits) should be formatted according to the ETSI/SAGE
	 *  128-EAA2 & 128-EIA2 specification:
	 *  COUNT || BEARER || DIRECTION || 0....0
	 */
	ODP_CIPHER_ALG_AES_EEA2,

	/** ZUC based confidentiality algorithm
	 *
	 *  128-EEA3/128-NEA3 algorithm when key length is 128 bits.
	 *
	 *  IV (128 bits) should be formatted according to the ETSI/SAGE
	 *  128-EEA3 & 128-EIA3 specification:
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 *  COUNT || BEARER || DIRECTION || 0...0 ||
	 *
	 *  256-bit key length support is experimental and subject to
	 *  change. The following variants may be supported:
	 *
	 *  - ZUC-256 with 25 byte IV (of which 184 bits are variable)
	 *    as specified in "The ZUC-256 Stream Cipher".
	 *  - ZUC-256 with 16 byte IV as specified in
	 *        "An Addendum to the ZUC-256 Stream Cipher",
	 *        https://eprint.iacr.org/2021/1439
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
	 *  GMAC needs an initialization vector, which must be passed via
	 *  operation parameters (auth_iv_ptr).
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
	 *  IV (128 bits) should be formatted according to the ETSI/SAGE
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
	 *  IV (64 bits) should be formatted according to the ETSI/SAGE
	 *  128-EEA2 & 128-EIA2 specification:
	 *  COUNT || BEARER || DIRECTION || 0....0
	 */
	ODP_AUTH_ALG_AES_EIA2,

	/** ZUC-based integrity algorithm.
	 *
	 *  128-EIA3/128-NIA3 algorithm when key length is 128 bits.
	 *
	 *  IV (128 bits) should be formatted according to the ETSI/SAGE
	 *  128-EEA3 & 128-EIA2 specification:
	 *  COUNT || BEARER ||
	 *  DIRECTION XOR COUNT0 || COUNT1 .. COUNT31 ||
	 *  BEARER || 0...0 || DIRECTION || 0...0
	 *
	 *  256-bit key length support is experimental and subject to
	 *  change. The following variants may be supported:
	 *
	 *  - ZUC-256 with 25 byte IV (of which 184 bits are variable) and
	 *    32/64/128 bit MAC as specified in "The ZUC-256 Stream Cipher".
	 *  - ZUC-256 with 16 byte IV and 32/64/128 bit MAC as specified in
	 *        "An Addendum to the ZUC-256 Stream Cipher",
	 *        https://eprint.iacr.org/2021/1439
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
 * Type of odp_crypto_op()/odp_crypto_op_enq() calls.
 */
typedef enum odp_crypto_op_type_t {
	/**
	 * Input packet data and metadata are copied to the output packet
	 * and then processed. Output packet is allocated by the caller
	 * or by ODP.
	 *
	 * This is the default value but will be deprecated in the future.
	 */
	ODP_CRYPTO_OP_TYPE_LEGACY,

	/**
	 * Input packet data and metadata are copied to the output packet
	 * and then processed. Output packet is allocated by ODP.
	 */
	ODP_CRYPTO_OP_TYPE_BASIC,

	/**
	 * Out-of-place crypto operation. Output packet is provided by
	 * the caller and the input packet is not consumed nor modified.
	 *
	 * Output of the crypto operation is written in the caller provided
	 * output packet without affecting other data and metadata of the
	 * output packet. Memory layout of the output packet may change
	 * during the operation.
	 *
	 * Crypto output is the processed crypto_range, auth_range and
	 * MAC/digest (in encode sessions) of the input packet.
	 */
	ODP_CRYPTO_OP_TYPE_OOP,
} odp_crypto_op_type_t;

/**
 * Crypto API session creation parameters
 */
typedef struct odp_crypto_session_param_t {
	/** Encode vs. decode operation
	 *
	 *  The default value is ODP_CRYPTO_OP_ENCODE.
	 */
	odp_crypto_op_t op;

	/** Crypto operation type
	 *
	 *  This field defines how the crypto operation functions are
	 *  to be called and what they return. In particular, this field
	 *  specifies the interpretation of the output packet parameter,
	 *  how output packets are allocated and what data and metadata
	 *  they contain.
	 *
	 *  The default value is ODP_CRYPTO_OP_TYPE_LEGACY.
	 */
	odp_crypto_op_type_t op_type;

	/** Cipher range unit
	 *
	 *  When this flag is true, cipher range offset and length are in bits.
	 *  Otherwise the offset and length are in bytes.
	 *
	 *  If cipher capabilities do not include bit_mode, setting this to
	 *  true causes a session creation failure.
	 *
	 *  The default value is false.
	 */
	odp_bool_t cipher_range_in_bits;

	/** Auth range unit
	 *
	 *  When this flag is true, auth range offset and length are in bits.
	 *  Otherwise the offset and length are in bytes.
	 *
	 *  If auth capabilities do not include bit_mode, setting this to
	 *  true causes a session creation failure.
	 *
	 *  The default value is false.
	 */
	odp_bool_t auth_range_in_bits;

	/** Authenticate cipher vs. plain text
	 *
	 *  Controls ordering of authentication and cipher operations,
	 *  and is relative to the operation (encode vs decode). When encoding,
	 *  TRUE indicates the authentication operation should be performed
	 *  after the cipher operation else before. When decoding, TRUE
	 *  indicates the reverse order of operation.
	 *
	 *  The value is ignored with authenticated encryption algorithms
	 *  such as AES-GCM. The value is also ignored when one of the
	 *  algorithms is null.
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

	/** Enable skipping crypto on per-packet basis
	 *
	 *  When this flag is true, the null_crypto flag of crypto operation
	 *  parameters can be set to request skipping of ciphering and
	 *  authentication of a packet regardless of session configuration.
	 *  This may be useful for preserving packet order between packets
	 *  that require crypto processing and packets that do not.
	 *
	 *  This flag must be set false when op_mode is ODP_CRYPTO_SYNC.
	 *
	 *  The default value is false.
	 */
	odp_bool_t null_crypto_enable;

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
	 *
	 *  When ciphering is disabled, i.e. cipher_alg is ODP_CIPHER_ALG_NULL,
	 *  cipher_key and cipher_iv_len parameters are ignored.
	 */
	odp_cipher_alg_t cipher_alg;

	/** Cipher key
	 *
	 * Use odp_crypto_cipher_capa() for supported key and IV lengths.
	 */
	odp_crypto_key_t cipher_key;

	/** Cipher IV length. The default value is zero. */
	uint32_t cipher_iv_len;

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
	 *
	 *  When authentication is disabled, i.e. auth_alg is
	 *  ODP_AUTH_ALG_NULL, auth_key, auth_iv_len, auth_digest_len,
	 *  auth_aad_len and hash_result_in_auth_range parameters are ignored.
	 */
	odp_auth_alg_t auth_alg;

	/** Authentication key
	 *
	 *  Use odp_crypto_auth_capability() for supported key lengths.
	 */
	odp_crypto_key_t auth_key;

	/** Authentication IV length. The default value is zero. */
	uint32_t auth_iv_len;

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
	 *  odp_crypto_op_enq() to the application.
	 */
	odp_queue_t compl_queue;

	/** Output pool
	 *
	 *  When the output packet is not specified during the call to
	 *  crypto operation in the legacy operation type, the output
	 *  packet will be allocated from this pool.
	 *
	 *  In ODP_CRYPTO_OP_TYPE_BASIC and ODP_CRYPTO_OP_TYPE_OOP
	 *  operation types this must be set to ODP_POOL_INVALID.
	 */
	odp_pool_t output_pool;

} odp_crypto_session_param_t;

/**
 * Crypto packet API per packet operation parameters
 */
typedef struct odp_crypto_packet_op_param_t {
	/** Session handle from creation */
	odp_crypto_session_t session;

	/** IV pointer for cipher */
	const uint8_t *cipher_iv_ptr;

	/** IV pointer for authentication */
	const uint8_t *auth_iv_ptr;

	/** Offset from start of packet for hash result
	 *
	 *  In case of decode sessions, the expected hash will be read from
	 *  this offset from the input packet and compared with the calculated
	 *  hash. After the operation the hash bytes will have undefined
	 *  values except with out-of-place sessions (ODP_CRYPTO_OP_TYPE_OOP
	 *  operation type).
	 *
	 *  With out-of-place decode sessions the input packet is not modified
	 *  but if the hash location overlaps the cipher range or the auth
	 *  range, then the corresponding location in the output packet will
	 *  have undefined content.
	 *
	 *  In case of encode sessions the calculated hash will be stored in
	 *  this offset in the output packet.
	 *
	 *  If the hash_result_in_auth_range session parameter is true,
	 *  the hash result location may overlap auth_range. In that case the
	 *  result location will be treated as containing zero bytes for the
	 *  purpose of hash calculation in decode sessions.
	 */
	uint32_t hash_result_offset;

	/** Pointer to AAD. AAD length is defined by 'auth_aad_len'
	 *  session parameter.
	 */
	const uint8_t *aad_ptr;

	/** Data range to be ciphered.
	 *
	 *  The range is given in bits or bytes as configured at session
	 *  creation.
	 *
	 *  Ignored by the null cipher with operation types other than
	 *  ODP_CRYPTO_OP_TYPE_OOP.
	 *
	 *  With the OOP operation type the cipher range is copied to the
	 *  output packet even with the null cipher. Non-zero-length ranges
	 *  are not necessarily supported with the null cipher and the OOP
	 *  operation type. If the requested range is not supported, the
	 *  crypto operation will fail. The failure is indicated through
	 *  odp_crypto_result() or through a negative return value of
	 *  odp_crypto_op()/odp_crypto_op_enq().
	 **/
	odp_packet_data_range_t cipher_range;

	/** Data range to be authenticated
	 *
	 *  The range is given in bits or bytes as configured at session
	 *  creation.
	 *
	 *  The value is ignored with authenticated encryption algorithms,
	 *  such as AES-GCM, which authenticate data in the cipher range
	 *  and the AAD.
	 *
	 *  Ignored by the null auth algorithm with operation types other than
	 *  ODP_CRYPTO_OP_TYPE_OOP.
	 *
	 *  With the OOP operation type the auth range is copied to the
	 *  output packet even with the null auth algorithm. Non-zero-length
	 *  ranges are not necessarily supported with the null algorithm and
	 *  the OOP operation type. If the requested range is not supported,
	 *  the crypto operation will fail. The failure is indicated through
	 *  odp_crypto_result() or through a negative return value of
	 *  odp_crypto_op()/odp_crypto_op_enq().
	 *
	 *  As a special case AES-GMAC uses this field instead of aad_ptr
	 *  for the data bytes to be authenticated.
	 */
	odp_packet_data_range_t auth_range;

	/** Shift of the output offsets with ODP_CRYPTO_OP_TYPE_OOP
	 *
	 *  The processed crypto range and auth range of the input packet
	 *  will be written in the output packet at the offset specified
	 *  in the ranges (i.e. the same as in the input packet), shifted
	 *  by this many bytes. This allows directing the output to
	 *  a different packet offset than the offset of the input data.
	 *
	 *  This is ignored if the crypto operation type is not
	 *  ODP_CRYPTO_OP_TYPE_OOP.
	 */
	int32_t dst_offset_shift;

	/** Use null crypto algorithms
	 *
	 * Process packet using the null cipher and null auth algorithm
	 * instead of the algoithms configured in the session. This flag is
	 * ignored if the null_crypto_enable session parameter is not set.
	 */
	uint8_t null_crypto :1;

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

#if ODP_DEPRECATED_API
/** This synonym for backward compatibility has been deprecated */
#define ODP_CRYPTO_SES_CREATE_ERR_NONE       ODP_CRYPTO_SES_ERR_NONE
/** This synonym for backward compatibility has been deprecated */
#define ODP_CRYPTO_SES_CREATE_ERR_ENOMEM     ODP_CRYPTO_SES_ERR_ENOMEM
/** This synonym for backward compatibility has been deprecated */
#define ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER ODP_CRYPTO_SES_ERR_CIPHER
/** This synonym for backward compatibility has been deprecated */
#define ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH   ODP_CRYPTO_SES_ERR_AUTH
#endif

/**
 * Crypto API algorithm return code
 */
typedef enum {
	/** Algorithm successful */
	ODP_CRYPTO_ALG_ERR_NONE,
	/** Invalid range or packet size */
	ODP_CRYPTO_ALG_ERR_DATA_SIZE,
	/** Key size invalid for algorithm */
	ODP_DEPRECATE(ODP_CRYPTO_ALG_ERR_KEY_SIZE),
	/** Computed ICV value mismatch */
	ODP_CRYPTO_ALG_ERR_ICV_CHECK,
	/** IV value not specified */
	ODP_DEPRECATE(ODP_CRYPTO_ALG_ERR_IV_INVALID),
	/** Other error */
	ODP_CRYPTO_ALG_ERR_OTHER,
} odp_crypto_alg_err_t;

/**
 * Crypto API hardware centric return code
 */
typedef enum {
	/** Operation completed successfully */
	ODP_DEPRECATE(ODP_CRYPTO_HW_ERR_NONE),
	/** Error detected during DMA of data */
	ODP_DEPRECATE(ODP_CRYPTO_HW_ERR_DMA),
	/** Operation failed due to pool depletion */
	ODP_DEPRECATE(ODP_CRYPTO_HW_ERR_BP_DEPLETED),
} ODP_DEPRECATE(odp_crypto_hw_err_t);

/**
 * Crypto API per packet operation completion status
 */
typedef struct odp_crypto_op_status {
	/** Algorithm specific return code */
	odp_crypto_alg_err_t alg_err;

	/** Hardware specific return code */
	ODP_DEPRECATE(odp_crypto_hw_err_t) ODP_DEPRECATE(hw_err);
} odp_crypto_op_status_t;

/**
 * Crypto packet API operation result
 */
typedef struct odp_crypto_packet_result_t {
	/** Request completed successfully.
	 *
	 *  @deprecated Check the return value of odp_crypto_result() instead.
	 */
	odp_bool_t  ODP_DEPRECATE(ok);

	/** Input packet passed to odp_crypo_op_enq() when the operation
	 *  type of the session is ODP_CRYPTO_OP_TYPE_OOP. In other cases
	 *  this field does not have a valid value.
	 */
	odp_packet_t pkt_in;

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

	/** Cipher supports bit mode
	 *
	 * This cipher can work on a range of bits in addition to a range of
	 * bytes. When this capability is not present, only byte ranges are
	 * supported. The unit of cipher range is selected at session creation
	 * through the cipher_range_in_bits session parameter.
	 *
	 * Note: In bit mode the cipher range must start on a byte boundary.
	 * Using an offset which is not divisible by 8 will result in
	 * undefined behaviour.
	 *
	 * Note2: If the range length in bit mode is not a multiple of 8,
	 * the remaining bits of the data in the last byte of the input/output
	 * will be the most significant bits, i.e. the most significant bit is
	 * considered to be the first bit of a byte for the purpose of input
	 * and output data range. The output bits that fall out of the output
	 * range are undefined.
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

	/** Auth algorithm supports bit mode
	 *
	 * This auth algorithm can work on a range of bits in addition to
	 * a range of bytes. When this capability is not present, only byte
	 * ranges are supported. The unit of auth range is selected at session
	 * creation through the auth_range_in_bits session parameter.
	 *
	 * Note: In bit mode the auth range must start on a byte boundary.
	 * Using an offset which is not divisible by 8 will result in
	 * undefined behaviour.
	 *
	 * Note2: If the range length in bit mode is not a multiple of 8,
	 * the remaining bits of the data in the last byte of the input/output
	 * will be the most significant bits, i.e. the most significant bit is
	 * considered to be the first bit of a byte for the purpose of input
	 * and output data range. The output bits that fall out of the output
	 * range are undefined.
	 */
	odp_bool_t bit_mode;

} odp_crypto_auth_capability_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
