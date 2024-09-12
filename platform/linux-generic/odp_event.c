/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2020-2024 Nokia
 */

#include <odp/autoheader_external.h>

#include <odp/api/event.h>
#include <odp/api/buffer.h>
#include <odp/api/crypto.h>
#include <odp/api/dma.h>
#include <odp/api/packet.h>
#include <odp/api/timer.h>
#include <odp/api/pool.h>
#include <odp/api/ml.h>

#include <odp_buffer_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp_event_internal.h>
#include <odp_event_validation_internal.h>
#include <odp_event_vector_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_vector_inlines.h>
#include <odp/api/plat/timer_inlines.h>

void odp_event_free(odp_event_t event)
{
	switch (odp_event_type(event)) {
	case ODP_EVENT_BUFFER:
		_odp_buffer_validate(odp_buffer_from_event(event), _ODP_EV_EVENT_FREE);
		odp_buffer_free(odp_buffer_from_event(event));
		break;
	case ODP_EVENT_PACKET:
		_odp_packet_validate(odp_packet_from_event(event), _ODP_EV_EVENT_FREE);
		odp_packet_free(odp_packet_from_event(event));
		break;
	case ODP_EVENT_PACKET_VECTOR:
		_odp_packet_vector_free_full(odp_packet_vector_from_event(event));
		break;
	case ODP_EVENT_TIMEOUT:
		odp_timeout_free(odp_timeout_from_event(event));
		break;
	case ODP_EVENT_IPSEC_STATUS:
		_odp_ipsec_status_free(_odp_ipsec_status_from_event(event));
		break;
	case ODP_EVENT_PACKET_TX_COMPL:
		odp_packet_tx_compl_free(odp_packet_tx_compl_from_event(event));
		break;
	case ODP_EVENT_DMA_COMPL:
		odp_dma_compl_free(odp_dma_compl_from_event(event));
		break;
	case ODP_EVENT_ML_COMPL:
		odp_ml_compl_free(odp_ml_compl_from_event(event));
		break;
	default:
		_ODP_ABORT("Invalid event type: %d\n", odp_event_type(event));
	}
}

static inline void packet_vector_free_full_multi(const odp_packet_vector_t pktv[], int num)
{
	for (int i = 0; i < num; i++)
		_odp_packet_vector_free_full(pktv[i]);
}

static inline void ipsec_status_free_multi(const ipsec_status_t status[], int num)
{
	for (int i = 0; i < num; i++)
		_odp_ipsec_status_free(status[i]);
}

static inline void packet_tx_compl_free_multi(const odp_packet_tx_compl_t tx_compl[], int num)
{
	for (int i = 0; i < num; i++)
		odp_packet_tx_compl_free(tx_compl[i]);
}

static inline void dma_compl_free_multi(const odp_dma_compl_t dma_compl[], int num)
{
	for (int i = 0; i < num; i++)
		odp_dma_compl_free(dma_compl[i]);
}

static inline void ml_compl_free_multi(const odp_ml_compl_t ml_compl[], int num)
{
	for (int i = 0; i < num; i++)
		odp_ml_compl_free(ml_compl[i]);
}

static inline void event_free_multi(const odp_event_t event[], int num, odp_event_type_t type,
				    _odp_ev_id_t id)
{
	switch (type) {
	case ODP_EVENT_BUFFER:
		_odp_buffer_validate_multi((odp_buffer_t *)(uintptr_t)event, num, id);
		odp_buffer_free_multi((odp_buffer_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_PACKET:
		_odp_packet_validate_multi((odp_packet_t *)(uintptr_t)event, num, id);
		odp_packet_free_multi((odp_packet_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_PACKET_VECTOR:
		packet_vector_free_full_multi((odp_packet_vector_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_TIMEOUT:
		odp_timeout_free_multi((odp_timeout_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_IPSEC_STATUS:
		ipsec_status_free_multi((ipsec_status_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_PACKET_TX_COMPL:
		packet_tx_compl_free_multi((odp_packet_tx_compl_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_DMA_COMPL:
		dma_compl_free_multi((odp_dma_compl_t *)(uintptr_t)event, num);
		break;
	case ODP_EVENT_ML_COMPL:
		ml_compl_free_multi((odp_ml_compl_t *)(uintptr_t)event, num);
		break;
	default:
		_ODP_ABORT("Invalid event type: %d\n", type);
	}
}

void odp_event_free_multi(const odp_event_t event[], int num)
{
	const odp_event_t *burst_start;
	odp_event_type_t burst_type;
	int burst_size;

	if (odp_unlikely(num <= 0))
		return;

	burst_type = odp_event_type(event[0]);
	burst_start = &event[0];
	burst_size = 1;

	for (int i = 1; i < num; i++) {
		const odp_event_type_t cur_type = odp_event_type(event[i]);

		if (cur_type == burst_type) {
			burst_size++;
			continue;
		}

		event_free_multi(burst_start, burst_size, burst_type, _ODP_EV_EVENT_FREE_MULTI);

		burst_type = cur_type;
		burst_start = &event[i];
		burst_size = 1;
	}

	event_free_multi(burst_start, burst_size, burst_type, _ODP_EV_EVENT_FREE_MULTI);
}

void odp_event_free_sp(const odp_event_t event[], int num)
{
	if (odp_unlikely(num <= 0))
		return;

	if (ODP_DEBUG) {
		const odp_pool_t pool = _odp_event_pool(event[0]);

		for (int i = 1; i < num; i++)
			_ODP_ASSERT(_odp_event_pool(event[i]) == pool);
	}

	event_free_multi(event, num, odp_event_type(event[0]), _ODP_EV_EVENT_FREE_SP);
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
		return !_odp_buffer_validate(odp_buffer_from_event(event), _ODP_EV_EVENT_IS_VALID);
	case ODP_EVENT_PACKET:
		return !_odp_packet_validate(odp_packet_from_event(event), _ODP_EV_EVENT_IS_VALID);
	case ODP_EVENT_TIMEOUT:
		/* Fall through */
	case ODP_EVENT_IPSEC_STATUS:
		/* Fall through */
	case ODP_EVENT_PACKET_VECTOR:
		/* Fall through */
	case ODP_EVENT_DMA_COMPL:
		/* Fall through */
	case ODP_EVENT_ML_COMPL:
		/* Fall through */
	case ODP_EVENT_PACKET_TX_COMPL:
		break;
	default:
		return 0;
	}

	return 1;
}
