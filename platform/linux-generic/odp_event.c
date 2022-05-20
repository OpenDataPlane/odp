/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/event.h>
#include <odp/api/buffer.h>
#include <odp/api/crypto.h>
#include <odp/api/dma.h>
#include <odp/api/packet.h>
#include <odp/api/timer.h>
#include <odp/api/pool.h>

#include <odp_buffer_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp_event_internal.h>
#include <odp_event_vector_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_vector_inlines.h>
#include <odp/api/plat/timer_inlines.h>

#include <odp/api/plat/event_inline_types.h>

#include <odp/visibility_begin.h>

/* Fill in event header field offsets for inline functions */
const _odp_event_inline_offset_t
_odp_event_inline_offset ODP_ALIGNED_CACHE = {
	.event_type = offsetof(_odp_event_hdr_t, event_type),
	.base_data  = offsetof(_odp_event_hdr_t, base_data)
};

#include <odp/visibility_end.h>

odp_event_subtype_t odp_event_subtype(odp_event_t event)
{
	if (_odp_event_type(event) != ODP_EVENT_PACKET)
		return ODP_EVENT_NO_SUBTYPE;

	return odp_packet_subtype(odp_packet_from_event(event));
}

odp_event_type_t odp_event_types(odp_event_t event,
				 odp_event_subtype_t *subtype)
{
	odp_event_type_t event_type = _odp_event_type(event);

	*subtype = event_type == ODP_EVENT_PACKET ?
			odp_packet_subtype(odp_packet_from_event(event)) :
			ODP_EVENT_NO_SUBTYPE;

	return event_type;
}

uint32_t odp_event_flow_id(odp_event_t event)
{
	return event_flow_id(event);
}

void odp_event_flow_id_set(odp_event_t event, uint32_t flow_id)
{
	event_flow_id_set(event, flow_id);
}

void odp_event_free(odp_event_t event)
{
	switch (odp_event_type(event)) {
	case ODP_EVENT_BUFFER:
		odp_buffer_free(odp_buffer_from_event(event));
		break;
	case ODP_EVENT_PACKET:
		odp_packet_free(odp_packet_from_event(event));
		break;
	case ODP_EVENT_PACKET_VECTOR:
		_odp_packet_vector_free_full(odp_packet_vector_from_event(event));
		break;
	case ODP_EVENT_TIMEOUT:
		odp_timeout_free(odp_timeout_from_event(event));
		break;
#if ODP_DEPRECATED_API
	case ODP_EVENT_CRYPTO_COMPL:
		odp_crypto_compl_free(odp_crypto_compl_from_event(event));
		break;
#endif
	case ODP_EVENT_IPSEC_STATUS:
		_odp_ipsec_status_free(_odp_ipsec_status_from_event(event));
		break;
	case ODP_EVENT_PACKET_TX_COMPL:
		odp_packet_tx_compl_free(odp_packet_tx_compl_from_event(event));
		break;
	case ODP_EVENT_DMA_COMPL:
		odp_dma_compl_free(odp_dma_compl_from_event(event));
		break;
	default:
		ODP_ABORT("Invalid event type: %d\n", odp_event_type(event));
	}
}

void odp_event_free_multi(const odp_event_t event[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		odp_event_free(event[i]);
}

void odp_event_free_sp(const odp_event_t event[], int num)
{
	odp_event_free_multi(event, num);
}

uint64_t odp_event_to_u64(odp_event_t hdl)
{
	return _odp_pri(hdl);
}

int odp_event_is_valid(odp_event_t event)
{
	if (event == ODP_EVENT_INVALID)
		return 0;

	if (_odp_event_is_valid(event) == 0)
		return 0;

	switch (odp_event_type(event)) {
	case ODP_EVENT_BUFFER:
		/* Fall through */
	case ODP_EVENT_PACKET:
		/* Fall through */
	case ODP_EVENT_TIMEOUT:
		/* Fall through */
#if ODP_DEPRECATED_API
	case ODP_EVENT_CRYPTO_COMPL:
		/* Fall through */
#endif
	case ODP_EVENT_IPSEC_STATUS:
		/* Fall through */
	case ODP_EVENT_PACKET_VECTOR:
		/* Fall through */
	case ODP_EVENT_DMA_COMPL:
		/* Fall through */
	case ODP_EVENT_PACKET_TX_COMPL:
		break;
	default:
		return 0;
	}

	return 1;
}
