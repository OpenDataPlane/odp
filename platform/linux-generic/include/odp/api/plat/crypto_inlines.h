/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_CRYPTO_INLINES_H_
#define ODP_PLAT_CRYPTO_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/crypto_types.h>
#include <odp/api/event.h>
#include <odp/api/packet.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/packet_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_crypto_packet_from_event __odp_crypto_packet_from_event
	#define odp_crypto_packet_to_event __odp_crypto_packet_to_event
	#define odp_crypto_result __odp_crypto_result
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_packet_t odp_crypto_packet_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);
	_ODP_ASSERT(odp_event_subtype(ev) == ODP_EVENT_PACKET_CRYPTO);

	return odp_packet_from_event(ev);
}

_ODP_INLINE odp_event_t odp_crypto_packet_to_event(odp_packet_t pkt)
{
	return odp_packet_to_event(pkt);
}

_ODP_INLINE int odp_crypto_result(odp_crypto_packet_result_t *result, odp_packet_t pkt)
{
	odp_crypto_packet_result_t *op_result;
	odp_bool_t ok;

	_ODP_ASSERT(odp_packet_subtype(pkt) == ODP_EVENT_PACKET_CRYPTO);

	op_result = _odp_pkt_get_ptr(pkt, odp_crypto_packet_result_t, crypto_op);

	ok = op_result->cipher_status.alg_err == ODP_CRYPTO_ALG_ERR_NONE &&
	     op_result->auth_status.alg_err   == ODP_CRYPTO_ALG_ERR_NONE;

	if (result)
		*result = *op_result;

	return ok ? 0 : -1;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
