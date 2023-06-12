/* Copyright (c) 2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_DMA_INLINES_H_
#define ODP_PLAT_DMA_INLINES_H_

#include <odp/api/buffer.h>
#include <odp/api/dma_types.h>
#include <odp/api/event_types.h>
#include <odp/api/hints.h>
#include <odp/api/pool_types.h>
#include <odp/api/queue_types.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/event_inline_types.h>

#include <stdint.h>
#include <string.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_dma_compl_from_event __odp_dma_compl_from_event
	#define odp_dma_compl_to_event __odp_dma_compl_to_event
	#define odp_dma_compl_user_area __odp_dma_compl_user_area
	#define odp_dma_compl_result __odp_dma_compl_result
	#define odp_dma_transfer_param_init __odp_dma_transfer_param_init
	#define odp_dma_compl_param_init __odp_dma_compl_param_init
	#define odp_dma_compl_alloc __odp_dma_compl_alloc
	#define odp_dma_compl_free __odp_dma_compl_free
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_dma_compl_t odp_dma_compl_from_event(odp_event_t ev)
{
	_ODP_ASSERT(_odp_event_hdr_field(ev, int8_t, event_type) == ODP_EVENT_DMA_COMPL);

	return (odp_dma_compl_t)(uintptr_t)ev;
}

_ODP_INLINE odp_event_t odp_dma_compl_to_event(odp_dma_compl_t dma_compl)
{
	return (odp_event_t)(uintptr_t)dma_compl;
}

_ODP_INLINE void *odp_dma_compl_user_area(odp_dma_compl_t dma_compl)
{
	return odp_buffer_user_area((odp_buffer_t)(uintptr_t)dma_compl);
}

_ODP_INLINE int odp_dma_compl_result(odp_dma_compl_t dma_compl, odp_dma_result_t *result_out)
{
	odp_dma_result_t *result;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)dma_compl;

	if (odp_unlikely(dma_compl == ODP_DMA_COMPL_INVALID)) {
		_ODP_ERR("Bad DMA compl handle\n");
		return -1;
	}

	result = (odp_dma_result_t *)odp_buffer_addr(buf);

	if (result_out)
		*result_out = *result;

	return result->success ? 0 : -1;
}

_ODP_INLINE void odp_dma_transfer_param_init(odp_dma_transfer_param_t *trs_param)
{
	memset(trs_param, 0, sizeof(odp_dma_transfer_param_t));

	trs_param->src_format = ODP_DMA_FORMAT_ADDR;
	trs_param->dst_format = ODP_DMA_FORMAT_ADDR;
	trs_param->num_src    = 1;
	trs_param->num_dst    = 1;
}

_ODP_INLINE void odp_dma_compl_param_init(odp_dma_compl_param_t *compl_param)
{
	memset(compl_param, 0, sizeof(odp_dma_compl_param_t));

	compl_param->queue = ODP_QUEUE_INVALID;
	compl_param->event = ODP_EVENT_INVALID;
	compl_param->transfer_id = ODP_DMA_TRANSFER_ID_INVALID;
}

_ODP_INLINE odp_dma_compl_t odp_dma_compl_alloc(odp_pool_t pool)
{
	odp_buffer_t buf;
	odp_event_t ev;
	odp_dma_result_t *result;
	int8_t *ev_type;

	buf = odp_buffer_alloc(pool);
	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_DMA_COMPL_INVALID;

	result = (odp_dma_result_t *)odp_buffer_addr(buf);
	memset(result, 0, sizeof(odp_dma_result_t));

	ev = odp_buffer_to_event(buf);
	ev_type = _odp_event_hdr_ptr(ev, int8_t, event_type);
	*ev_type = ODP_EVENT_DMA_COMPL;

	return (odp_dma_compl_t)(uintptr_t)buf;
}

_ODP_INLINE void odp_dma_compl_free(odp_dma_compl_t dma_compl)
{
	int8_t *ev_type;
	odp_event_t ev;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)dma_compl;

	if (odp_unlikely(dma_compl == ODP_DMA_COMPL_INVALID)) {
		_ODP_ERR("Bad DMA compl handle\n");
		return;
	}

	ev = odp_buffer_to_event(buf);
	ev_type = _odp_event_hdr_ptr(ev, int8_t, event_type);
	*ev_type = ODP_EVENT_BUFFER;

	odp_buffer_free(buf);
}

/** @endcond */

#endif
