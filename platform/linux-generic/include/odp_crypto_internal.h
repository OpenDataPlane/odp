/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025-2026 Nokia
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#include <odp/api/crypto.h>
#include <odp/api/event.h>
#include <odp/api/queue.h>

#include <odp_pending_queue_internal.h>

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

static inline odp_bool_t _odp_crypto_aad_len_ignored(odp_auth_alg_t auth_alg)
{
	return auth_alg == ODP_AUTH_ALG_NULL ||
	       auth_alg == ODP_AUTH_ALG_AES_GMAC ||
	       auth_alg == ODP_AUTH_ALG_SNOW_V_GMAC ||
	       auth_alg == ODP_AUTH_ALG_SM4_GMAC;
}

void _odp_crypto_session_print(const char *type, uint32_t index,
			       const odp_crypto_session_param_t *param);

void _odp_crypto_enqueue_completions(_odp_pending_queue_t *pending,
				     const odp_event_t events[],
				     const odp_queue_t queues[],
				     int num);

#ifdef __cplusplus
}
#endif

#endif
