/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_CRYPTO_TYPES_H_
#define ODP_ABI_CRYPTO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_crypto_compl_t;

/** @ingroup odp_crypto
 *  @{
 */

#define ODP_CRYPTO_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t  odp_crypto_session_t;
typedef _odp_abi_crypto_compl_t *odp_crypto_compl_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
