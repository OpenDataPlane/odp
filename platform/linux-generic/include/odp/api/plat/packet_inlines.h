/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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

#include <odp/api/abi/packet.h>
#include <odp/api/pool.h>
#include <odp/api/abi/packet_io.h>
#include <odp/api/hints.h>
#include <odp/api/time.h>
#include <odp/api/abi/buffer.h>
#include <odp/api/abi/event.h>

#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/plat/pool_inline_types.h>
#include <odp/api/plat/pktio_inlines.h>

#include <string.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_packet_data __odp_packet_data
	#define odp_packet_seg_len __odp_packet_seg_len
	#define odp_packet_data_seg_len __odp_packet_data_seg_len
	#define odp_packet_len __odp_packet_len
	#define odp_packet_headroom __odp_packet_headroom
	#define odp_packet_tailroom __odp_packet_tailroom
	#define odp_packet_pool __odp_packet_pool
	#define odp_packet_input __odp_packet_input
	#define odp_packet_input_index __odp_packet_input_index
	#define odp_packet_num_segs __odp_packet_num_segs
	#define odp_packet_user_ptr __odp_packet_user_ptr
	#define odp_packet_user_area __odp_packet_user_area
	#define odp_packet_user_area_size __odp_packet_user_area_size
	#define odp_packet_l2_offset __odp_packet_l2_offset
	#define odp_packet_l3_offset __odp_packet_l3_offset
	#define odp_packet_l4_offset __odp_packet_l4_offset
	#define odp_packet_l2_ptr __odp_packet_l2_ptr
	#define odp_packet_l3_ptr __odp_packet_l3_ptr
	#define odp_packet_l4_ptr __odp_packet_l4_ptr
	#define odp_packet_flow_hash __odp_packet_flow_hash
	#define odp_packet_ts __odp_packet_ts
	#define odp_packet_head __odp_packet_head
	#define odp_packet_is_segmented __odp_packet_is_segmented
	#define odp_packet_first_seg __odp_packet_first_seg
	#define odp_packet_seg_data __odp_packet_seg_data
	#define odp_packet_seg_data_len __odp_packet_seg_data_len
	#define odp_packet_next_seg __odp_packet_next_seg
	#define odp_packet_prefetch __odp_packet_prefetch
	#define odp_packet_copy_from_mem __odp_packet_copy_from_mem
	#define odp_packet_copy_to_mem __odp_packet_copy_to_mem
	#define odp_packet_from_event __odp_packet_from_event
	#define odp_packet_to_event __odp_packet_to_event
	#define odp_packet_from_event_multi __odp_packet_from_event_multi
	#define odp_packet_to_event_multi __odp_packet_to_event_multi
	#define odp_packet_subtype __odp_packet_subtype
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

void *_odp_packet_map(void *pkt_ptr, uint32_t offset, uint32_t *seg_len,
		      odp_packet_seg_t *seg);

int _odp_packet_copy_from_mem_seg(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, const void *src);

int _odp_packet_copy_to_mem_seg(odp_packet_t pkt, uint32_t offset,
				uint32_t len, void *dst);

extern const _odp_packet_inline_offset_t _odp_packet_inline;
extern const _odp_pool_inline_offset_t   _odp_pool_inline;

_ODP_INLINE void *odp_packet_data(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, seg_data);
}

_ODP_INLINE uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, seg_len);
}

_ODP_INLINE void *odp_packet_data_seg_len(odp_packet_t pkt,
					     uint32_t *seg_len)
{
	*seg_len = odp_packet_seg_len(pkt);
	return odp_packet_data(pkt);
}

_ODP_INLINE uint32_t odp_packet_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, frame_len);
}

_ODP_INLINE uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, headroom);
}

_ODP_INLINE uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, tailroom);
}

_ODP_INLINE odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, odp_pool_t, pool_hdl);
}

_ODP_INLINE odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pktio_t, input);
}

_ODP_INLINE int odp_packet_input_index(odp_packet_t pkt)
{
	odp_pktio_t pktio = odp_packet_input(pkt);

	return odp_pktio_index(pktio);
}

_ODP_INLINE int odp_packet_num_segs(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, seg_count);
}

_ODP_INLINE void *odp_packet_user_ptr(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	if (flags.user_ptr_set == 0)
		return NULL;

	return _odp_pkt_get(pkt, void *, user_ptr);
}

_ODP_INLINE void *odp_packet_user_area(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_area);
}

_ODP_INLINE uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, uint32_t, uarea_size);
}

_ODP_INLINE uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l2_offset);
}

_ODP_INLINE uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l3_offset);
}

_ODP_INLINE uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l4_offset);
}

_ODP_INLINE void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = odp_packet_l2_offset(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

_ODP_INLINE void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = odp_packet_l3_offset(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

_ODP_INLINE void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = odp_packet_l4_offset(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

_ODP_INLINE uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, flow_hash);
}

_ODP_INLINE odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_time_t, timestamp);
}

_ODP_INLINE void *odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)odp_packet_data(pkt) - odp_packet_headroom(pkt);
}

_ODP_INLINE int odp_packet_is_segmented(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, seg_count) > 1;
}

_ODP_INLINE odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

_ODP_INLINE void *odp_packet_seg_data(odp_packet_t pkt ODP_UNUSED,
				      odp_packet_seg_t seg)
{
	return _odp_pkt_get((odp_packet_t)seg, void *, seg_data);
}

_ODP_INLINE uint32_t odp_packet_seg_data_len(odp_packet_t pkt ODP_UNUSED,
					     odp_packet_seg_t seg)
{
	return _odp_pkt_get((odp_packet_t)seg, uint32_t, seg_len);
}

_ODP_INLINE odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt ODP_UNUSED,
						 odp_packet_seg_t seg)
{
	void *next_seg = _odp_pkt_get((odp_packet_t)seg, void *, seg_next);

	if (odp_unlikely(next_seg == NULL))
		return ODP_PACKET_SEG_INVALID;

	return (odp_packet_seg_t)next_seg;
}

_ODP_INLINE void odp_packet_prefetch(odp_packet_t pkt, uint32_t offset,
					uint32_t len)
{
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);
	(void)len;

	if (odp_unlikely(offset >= seg_len))
		return;

	odp_prefetch(data + offset);
}

_ODP_INLINE int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
					    uint32_t len, const void *src)
{
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset + len > seg_len))
		return _odp_packet_copy_from_mem_seg(pkt, offset, len, src);

	memcpy(data + offset, src, len);

	return 0;
}

_ODP_INLINE int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
					  uint32_t len, void *dst)
{
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset + len > seg_len))
		return _odp_packet_copy_to_mem_seg(pkt, offset, len, dst);

	memcpy(dst, data + offset, len);

	return 0;
}

_ODP_INLINE odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

_ODP_INLINE odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

_ODP_INLINE void odp_packet_from_event_multi(odp_packet_t pkt[],
						const odp_event_t ev[],
						int num)
{
	int i;

	for (i = 0; i < num; i++)
		pkt[i] = odp_packet_from_event(ev[i]);
}

_ODP_INLINE void odp_packet_to_event_multi(const odp_packet_t pkt[],
					      odp_event_t ev[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		ev[i] = odp_packet_to_event(pkt[i]);
}

_ODP_INLINE odp_event_subtype_t odp_packet_subtype(odp_packet_t pkt)
{
	return (odp_event_subtype_t)_odp_pkt_get(pkt, int8_t, subtype);
}

/** @endcond */

#endif
