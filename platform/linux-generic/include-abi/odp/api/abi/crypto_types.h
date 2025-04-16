/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_API_ABI_CRYPTO_TYPES_H_
#define ODP_API_ABI_CRYPTO_TYPES_H_

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_crypto
 *  @{
 */

#define ODP_CRYPTO_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t odp_crypto_session_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
