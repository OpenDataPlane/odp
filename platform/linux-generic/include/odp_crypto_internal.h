/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025-2026 Nokia
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#include <odp/api/crypto.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct odp_crypto_generic_session_t odp_crypto_generic_session_t;

static inline odp_crypto_generic_session_t *
odp_crypto_session_from_handle(odp_crypto_session_t hdl)
{
	return (odp_crypto_generic_session_t *)(uintptr_t)hdl;
}

static inline odp_crypto_session_t
odp_crypto_session_to_handle(odp_crypto_generic_session_t *session)
{
	return (odp_crypto_session_t)(uintptr_t)session;
}

void _odp_crypto_session_print(const char *type, uint32_t index,
			       const odp_crypto_session_param_t *param);

#ifdef __cplusplus
}
#endif

#endif
