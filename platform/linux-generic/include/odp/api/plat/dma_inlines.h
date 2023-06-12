/* Copyright (c) 2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_DMA_INLINES_H_
#define ODP_PLAT_DMA_INLINES_H_

#include <odp/api/dma_types.h>
#include <odp/api/event_types.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/event_inline_types.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_dma_compl_from_event __odp_dma_compl_from_event
	#define odp_dma_compl_to_event __odp_dma_compl_to_event
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

/** @endcond */

#endif
