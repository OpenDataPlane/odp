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

#ifndef ODP_API_ABI_CRYPTO_H_
#define ODP_API_ABI_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_crypto
 *  @{
 */

#define ODP_CRYPTO_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t odp_crypto_session_t;
typedef ODP_HANDLE_T(odp_crypto_compl_t);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
