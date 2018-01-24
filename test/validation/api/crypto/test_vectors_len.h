/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef TEST_VECTORS_LEN_
#define TEST_VECTORS_LEN_

/* Maximum */
#define MAX_KEY_LEN         64
#define MAX_IV_LEN          16
#define MAX_DATA_LEN        270
#define MAX_AAD_LEN         12
#define MAX_DIGEST_LEN      64

/* TDES-CBC */
#define TDES_CBC_KEY_LEN        24
#define TDES_CBC_IV_LEN         8

/* AES-CBC common */
#define AES_CBC_IV_LEN         16

/* AES128-CBC */
#define AES128_CBC_KEY_LEN        16

/* AES192-CBC */
#define AES192_CBC_KEY_LEN        24

/* AES256-CBC */
#define AES256_CBC_KEY_LEN        32

/* AES-CBC common */
#define AES_CTR_IV_LEN         16

/* AES128-CTR */
#define AES128_CTR_KEY_LEN        16

/* AES192-CTR */
#define AES192_CTR_KEY_LEN        24

/* AES256-CTR */
#define AES256_CTR_KEY_LEN        32

/* AES-GCM common */
#define AES_GCM_IV_LEN         12
#define AES_GCM_DIGEST_LEN     16

/* AES128-GCM */
#define AES128_GCM_KEY_LEN        16

/* AES192-GCM */
#define AES192_GCM_KEY_LEN        24

/* AES256-GCM */
#define AES256_GCM_KEY_LEN        32

/* HMAC-MD5 */
#define HMAC_MD5_KEY_LEN        16
#define HMAC_MD5_96_CHECK_LEN   12
#define HMAC_MD5_CHECK_LEN      16

/* HMAC-SHA256 */
#define HMAC_SHA256_KEY_LEN        32
#define HMAC_SHA256_128_CHECK_LEN  16
#define HMAC_SHA256_CHECK_LEN      32

/* HMAC-SHA1 */
#define HMAC_SHA1_KEY_LEN        20
#define HMAC_SHA1_96_CHECK_LEN   12
#define HMAC_SHA1_CHECK_LEN      20

/* HMAC-SHA512 */
#define HMAC_SHA512_KEY_LEN        64
#define HMAC_SHA512_256_CHECK_LEN  32
#define HMAC_SHA512_CHECK_LEN      64

/* ChaCha20-Poly1305 */
#define CHACHA20_POLY1305_KEY_LEN  32
#define CHACHA20_POLY1305_IV_LEN   12
#define CHACHA20_POLY1305_CHECK_LEN 16

#endif
