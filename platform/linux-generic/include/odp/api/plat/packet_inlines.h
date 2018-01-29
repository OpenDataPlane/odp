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

#include <odp/api/abi/packet.h>
#include <odp/api/pool.h>
#include <odp/api/abi/packet_io.h>
#include <odp/api/hints.h>
#include <odp/api/time.h>
#include <odp/api/abi/buffer.h>

#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/plat/pool_inline_types.h>

#include <string.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

void *_odp_packet_map(void *pkt_ptr, uint32_t offset, uint32_t *seg_len,
		      int *seg_idx);

int _odp_packet_copy_from_mem_seg(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, const void *src);

int _odp_packet_copy_to_mem_seg(odp_packet_t pkt, uint32_t offset,
				uint32_t len, void *dst);

extern const _odp_packet_inline_offset_t _odp_packet_inline;
extern const _odp_pool_inline_offset_t   _odp_pool_inline;

#ifndef _ODP_HAVE_PACKET_SEG_NDX
#include <odp/api/plat/strong_types.h>
static inline uint32_t _odp_packet_seg_to_ndx(odp_packet_seg_t seg)
{
	return _odp_typeval(seg);
}

static inline odp_packet_seg_t _odp_packet_seg_from_ndx(uint32_t ndx)
{
	return _odp_cast_scalar(odp_packet_seg_t, ndx);
}
#endif

static inline void *_odp_packet_data(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, data);
}

static inline uint32_t _odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, seg_len);
}

static inline uint32_t _odp_packet_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, frame_len);
}

static inline uint32_t _odp_packet_headroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, headroom);
}

static inline uint32_t _odp_packet_tailroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, tailroom);
}

static inline odp_pool_t _odp_packet_pool(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, odp_pool_t, pool_hdl);
}

static inline odp_pktio_t _odp_packet_input(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pktio_t, input);
}

static inline int _odp_packet_num_segs(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, segcount);
}

static inline void *_odp_packet_user_ptr(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_ptr);
}

static inline void *_odp_packet_user_area(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_area);
}

static inline uint32_t _odp_packet_user_area_size(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, uint32_t, uarea_size);
}

static inline uint32_t _odp_packet_l2_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l2_offset);
}

static inline uint32_t _odp_packet_l3_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l3_offset);
}

static inline uint32_t _odp_packet_l4_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l4_offset);
}

static inline void *_odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = _odp_packet_l2_offset(pkt);
	uint32_t seg_len = _odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)_odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

static inline void *_odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = _odp_packet_l3_offset(pkt);
	uint32_t seg_len = _odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)_odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

static inline void *_odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = _odp_packet_l4_offset(pkt);
	uint32_t seg_len = _odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)_odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

static inline uint32_t _odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, flow_hash);
}

static inline odp_time_t _odp_packet_ts(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_time_t, timestamp);
}

static inline void *_odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)_odp_packet_data(pkt) - _odp_packet_headroom(pkt);
}

static inline int _odp_packet_is_segmented(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, segcount) > 1;
}

static inline odp_packet_seg_t _odp_packet_first_seg(odp_packet_t pkt)
{
	(void)pkt;

	return _odp_packet_seg_from_ndx(0);
}

static inline odp_packet_seg_t _odp_packet_last_seg(odp_packet_t pkt)
{
	return _odp_packet_seg_from_ndx(_odp_packet_num_segs(pkt) - 1);
}

static inline odp_packet_seg_t _odp_packet_next_seg(odp_packet_t pkt,
						    odp_packet_seg_t seg)
{
	if (odp_unlikely(_odp_packet_seg_to_ndx(seg) >=
			 _odp_packet_seg_to_ndx(_odp_packet_last_seg(pkt))))
		return ODP_PACKET_SEG_INVALID;

	return seg + 1;
}

static inline void _odp_packet_prefetch(odp_packet_t pkt, uint32_t offset,
					uint32_t len)
{
	uint32_t seg_len = _odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)_odp_packet_data(pkt);
	(void)len;

	if (odp_unlikely(offset >= seg_len))
		return;

	odp_prefetch(data + offset);
}

static inline int _odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
					    uint32_t len, const void *src)
{
	uint32_t seg_len = _odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)_odp_packet_data(pkt);

	if (odp_unlikely(offset + len > seg_len))
		return _odp_packet_copy_from_mem_seg(pkt, offset, len, src);

	memcpy(data + offset, src, len);

	return 0;
}

static inline int _odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
					  uint32_t len, void *dst)
{
	uint32_t seg_len = _odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)_odp_packet_data(pkt);

	if (odp_unlikely(offset + len > seg_len))
		return _odp_packet_copy_to_mem_seg(pkt, offset, len, dst);

	memcpy(dst, data + offset, len);

	return 0;
}

static inline odp_packet_t _odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

static inline odp_event_t _odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

static inline void _odp_packet_from_event_multi(odp_packet_t pkt[],
						const odp_event_t ev[],
						int num)
{
	int i;

	for (i = 0; i < num; i++)
		pkt[i] = _odp_packet_from_event(ev[i]);
}

static inline void _odp_packet_to_event_multi(const odp_packet_t pkt[],
					      odp_event_t ev[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		ev[i] = _odp_packet_to_event(pkt[i]);
}

/** @endcond */

#endif
