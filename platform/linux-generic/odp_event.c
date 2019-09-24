/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/event.h>
#include <odp/api/buffer.h>
#include <odp/api/crypto.h>
#include <odp/api/packet.h>
#include <odp/api/timer.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/packet_inlines.h>

odp_event_subtype_t odp_event_subtype(odp_event_t event)
{
	if (_odp_buffer_event_type(odp_buffer_from_event(event)) !=
			ODP_EVENT_PACKET)
		return ODP_EVENT_NO_SUBTYPE;

	return odp_packet_subtype(odp_packet_from_event(event));
}

odp_event_type_t odp_event_types(odp_event_t event,
				 odp_event_subtype_t *subtype)
{
	odp_buffer_t buf = odp_buffer_from_event(event);
	odp_event_type_t event_type = _odp_buffer_event_type(buf);

	*subtype = event_type == ODP_EVENT_PACKET ?
			odp_packet_subtype(odp_packet_from_event(event)) :
			ODP_EVENT_NO_SUBTYPE;

	return event_type;
}

int odp_event_type_multi(const odp_event_t event[], int num,
			 odp_event_type_t *type_out)
{
	int i;
	odp_event_type_t type = odp_event_type(event[0]);

	for (i = 1; i < num; i++) {
		if (odp_event_type(event[i]) != type)
			break;
	}

	*type_out = type;

	return i;
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
	case ODP_EVENT_TIMEOUT:
		odp_timeout_free(odp_timeout_from_event(event));
		break;
	case ODP_EVENT_CRYPTO_COMPL:
		odp_crypto_compl_free(odp_crypto_compl_from_event(event));
		break;
	case ODP_EVENT_IPSEC_STATUS:
		_odp_ipsec_status_free(_odp_ipsec_status_from_event(event));
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
