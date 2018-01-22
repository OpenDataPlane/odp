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

#ifndef _ODP_PLAT_PACKET_INLINES_API_H_
#define _ODP_PLAT_PACKET_INLINES_API_H_

_ODP_INLINE void *odp_packet_data(odp_packet_t pkt)
{
	return _odp_packet_data(pkt);
}

_ODP_INLINE uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_packet_seg_len(pkt);
}

_ODP_INLINE uint32_t odp_packet_len(odp_packet_t pkt)
{
	return _odp_packet_len(pkt);
}

_ODP_INLINE uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return _odp_packet_headroom(pkt);
}

_ODP_INLINE uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	return _odp_packet_tailroom(pkt);
}

_ODP_INLINE odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return _odp_packet_pool(pkt);
}

_ODP_INLINE odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return _odp_packet_input(pkt);
}

_ODP_INLINE int odp_packet_input_index(odp_packet_t pkt)
{
	return _odp_packet_input_index(pkt);
}

_ODP_INLINE int odp_packet_num_segs(odp_packet_t pkt)
{
	return _odp_packet_num_segs(pkt);
}

_ODP_INLINE void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return _odp_packet_user_ptr(pkt);
}

_ODP_INLINE void *odp_packet_user_area(odp_packet_t pkt)
{
	return _odp_packet_user_area(pkt);
}

_ODP_INLINE uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return _odp_packet_user_area_size(pkt);
}

_ODP_INLINE uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return _odp_packet_l2_offset(pkt);
}

_ODP_INLINE uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return _odp_packet_l3_offset(pkt);
}

_ODP_INLINE uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return _odp_packet_l4_offset(pkt);
}

_ODP_INLINE void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	return _odp_packet_l2_ptr(pkt, len);
}

_ODP_INLINE void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	return _odp_packet_l3_ptr(pkt, len);
}

_ODP_INLINE void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	return _odp_packet_l4_ptr(pkt, len);
}

_ODP_INLINE uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_packet_flow_hash(pkt);
}

_ODP_INLINE void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	return _odp_packet_flow_hash_set(pkt, flow_hash);
}

_ODP_INLINE odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	return _odp_packet_ts(pkt);
}

_ODP_INLINE void *odp_packet_head(odp_packet_t pkt)
{
	return _odp_packet_head(pkt);
}

_ODP_INLINE int odp_packet_is_segmented(odp_packet_t pkt)
{
	return _odp_packet_is_segmented(pkt);
}

_ODP_INLINE odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return _odp_packet_first_seg(pkt);
}

_ODP_INLINE odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	return _odp_packet_last_seg(pkt);
}

_ODP_INLINE odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt,
						 odp_packet_seg_t seg)
{
	return _odp_packet_next_seg(pkt, seg);
}

_ODP_INLINE void odp_packet_prefetch(odp_packet_t pkt, uint32_t offset,
				     uint32_t len)
{
	return _odp_packet_prefetch(pkt, offset, len);
}

_ODP_INLINE int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
					 uint32_t len, const void *src)
{
	return _odp_packet_copy_from_mem(pkt, offset, len, src);
}

_ODP_INLINE int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
				       uint32_t len, void *dst)
{
	return _odp_packet_copy_to_mem(pkt, offset, len, dst);
}

_ODP_INLINE odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return _odp_packet_from_event(ev);
}

_ODP_INLINE odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return _odp_packet_to_event(pkt);
}

_ODP_INLINE void odp_packet_from_event_multi(odp_packet_t pkt[],
					     const odp_event_t ev[], int num)
{
	return _odp_packet_from_event_multi(pkt, ev, num);
}

_ODP_INLINE void odp_packet_to_event_multi(const odp_packet_t pkt[],
					   odp_event_t ev[], int num)
{
	return _odp_packet_to_event_multi(pkt, ev, num);
}
#endif
