/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_INLINES_H_
#define _ODP_PLAT_PACKET_INLINES_H_

#include <odp/api/plat/packet_types.h>
#include <odp/api/pool.h>
#include <odp/api/packet_io.h>
#include <odp/api/hints.h>

/** @internal Inline function offsets */
extern const _odp_packet_inline_offset_t _odp_packet_inline;

#if ODP_ABI_COMPAT == 1
/** @internal Inline function @param seg @return */
static inline uint32_t _odp_packet_seg_to_ndx(odp_packet_seg_t seg)
{
	return _odp_typeval(seg);
}

/** @internal Inline function @param ndx @return */
static inline odp_packet_seg_t _odp_packet_seg_from_ndx(uint32_t ndx)
{
	return _odp_cast_scalar(odp_packet_seg_t, ndx);
}
#endif

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_data(odp_packet_t pkt)
{
	return *(void **)(uintptr_t)((uint8_t *)pkt + _odp_packet_inline.data);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_seg_len(odp_packet_t pkt)
{
	return *(uint32_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.seg_len);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_len(odp_packet_t pkt)
{
	return *(uint32_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.frame_len);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_headroom(odp_packet_t pkt)
{
	return *(uint32_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.headroom);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_tailroom(odp_packet_t pkt)
{
	return *(uint32_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.tailroom);
}

/** @internal Inline function @param pkt @return */
static inline odp_pool_t _odp_packet_pool(odp_packet_t pkt)
{
	return *(odp_pool_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.pool);
}

/** @internal Inline function @param pkt @return */
static inline odp_pktio_t _odp_packet_input(odp_packet_t pkt)
{
	return *(odp_pktio_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.input);
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_num_segs(odp_packet_t pkt)
{
	return *(uint8_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.segcount);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_user_ptr(odp_packet_t pkt)
{
	return *(void **)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.user_ptr);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_user_area(odp_packet_t pkt)
{
	return *(void **)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.user_area);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_user_area_size(odp_packet_t pkt)
{
	return *(uint32_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.user_area_size);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_flow_hash(odp_packet_t pkt)
{
	return *(uint32_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.flow_hash);
}

/** @internal Inline function @param pkt @return */
static inline odp_time_t _odp_packet_ts(odp_packet_t pkt)
{
	return *(odp_time_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.timestamp);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)_odp_packet_data(pkt) - _odp_packet_headroom(pkt);
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_is_segmented(odp_packet_t pkt)
{
	return _odp_packet_num_segs(pkt) > 1;
}

/** @internal Inline function @param pkt @return */
static inline odp_packet_seg_t _odp_packet_first_seg(odp_packet_t pkt)
{
	(void)pkt;

	return _odp_packet_seg_from_ndx(0);
}

/** @internal Inline function @param pkt @return */
static inline odp_packet_seg_t _odp_packet_last_seg(odp_packet_t pkt)
{
	return _odp_packet_seg_from_ndx(_odp_packet_num_segs(pkt) - 1);
}

/** @internal Inline function @param pkt @param seg @return */
static inline odp_packet_seg_t _odp_packet_next_seg(odp_packet_t pkt,
						    odp_packet_seg_t seg)
{
	if (odp_unlikely(_odp_packet_seg_to_ndx(seg) >=
			 _odp_packet_seg_to_ndx(_odp_packet_last_seg(pkt))))
		return ODP_PACKET_SEG_INVALID;

	return seg + 1;
}

/** @internal Inline function @param pkt @param offset @param len */
static inline void _odp_packet_prefetch(odp_packet_t pkt, uint32_t offset,
					uint32_t len)
{
	(void)pkt; (void)offset; (void)len;
}

/* Include inlined versions of API functions */
#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0

/** @ingroup odp_packet
 *  @{
 */

#include <odp/api/plat/packet_inlines_api.h>

/**
 * @}
 */

#endif

#endif
