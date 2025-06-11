/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#include <odp/api/crypto.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void _odp_crypto_session_print(const char *type, uint32_t index,
			       const odp_crypto_session_param_t *param);

#ifdef __cplusplus
}
#endif

#endif
