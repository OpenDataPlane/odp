/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef TEST_VECTORS_LEN_
#define TEST_VECTORS_LEN_

/* TDES-CBC */
#define TDES_CBC_KEY_LEN        24
#define TDES_CBC_IV_LEN         8
#define TDES_CBC_MAX_DATA_LEN   16


/* HMAC-MD5 */
#define HMAC_MD5_KEY_LEN        16
#define HMAC_MD5_MAX_DATA_LEN   128
#define HMAC_MD5_DIGEST_LEN     16
#define HMAC_MD5_96_CHECK_LEN   12

/* HMAC-SHA256 */
#define HMAC_SHA256_KEY_LEN        32
#define HMAC_SHA256_MAX_DATA_LEN   128
#define HMAC_SHA256_DIGEST_LEN     32
#define HMAC_SHA256_128_CHECK_LEN  16

#endif
