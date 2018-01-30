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
	return _odp_pkt_get(pkt, void *, data);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, seg_len);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_len(odp_packet_t pkt)
{
	uint32_t pkt_len = _odp_pkt_get(pkt, uint32_t, frame_len);
	void *ref_nxt    = _odp_pkt_get(pkt, void *, ref_hdr);
	void *ref_pkt    = (void *)pkt;

	while (ref_nxt) {
		pkt_len += _odp_pkt_get(ref_pkt, uint32_t, ref_len) -
			_odp_pkt_get(ref_pkt, uint32_t, ref_offset);

		ref_pkt = ref_nxt;
		ref_nxt = _odp_pkt_get(ref_nxt, void *, ref_hdr);
	}

	return pkt_len;
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_headroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, headroom);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_tailroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, tailroom);
}

/** @internal Inline function @param pkt @return */
static inline odp_pool_t _odp_packet_pool(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pool_t, pool);
}

/** @internal Inline function @param pkt @return */
static inline odp_pktio_t _odp_packet_input(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pktio_t, input);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_user_ptr(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_ptr);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_user_area(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_area);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_user_area_size(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, user_area_size);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, flow_hash);
}

/** @internal Inline function @param pkt @return */
static inline odp_time_t _odp_packet_ts(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_time_t, timestamp);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)_odp_packet_data(pkt) - _odp_packet_headroom(pkt);
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_is_segmented(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, segcount) > 1 ||
		_odp_pkt_get(pkt, void *, ref_hdr) != NULL;
}

/** @internal Inline function @param pkt @return */
static inline odp_packet_seg_t _odp_packet_first_seg(odp_packet_t pkt)
{
	(void)pkt;

	return _odp_packet_seg_from_ndx(0);
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
