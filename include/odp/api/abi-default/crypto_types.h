/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_ABI_CRYPTO_TYPES_H_
#define ODP_ABI_CRYPTO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @ingroup odp_crypto
 *  @{
 */

#define ODP_CRYPTO_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t  odp_crypto_session_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
